//! The TLS 1.2 PRF (RFC 5246 §5) and the secrets derived from it: master
//! secret (RFC 5246 §8.1), extended master secret (RFC 7627 §4), key block
//! (RFC 5246 §6.3) and `Finished.verify_data` (RFC 5246 §7.4.9).
//!
//! `P_hash` is HMAC iterated exactly as the RFC writes it; HMAC and the hash
//! functions are RustCrypto's. Every derived secret is returned in a
//! `Zeroizing` buffer.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha384};
use zeroize::{Zeroize, Zeroizing};

use crate::suite::{CipherSuite, PrfHash};

/// Length of the master secret (RFC 5246 §8.1).
pub(crate) const MASTER_SECRET_LEN: usize = 48;
/// Length of `Finished.verify_data` for every suite here (RFC 5246 §7.4.9).
pub(crate) const VERIFY_DATA_LEN: usize = 12;

/// `P_hash(secret, label || seed)` into `out` (RFC 5246 §5).
fn p_hash<M: Mac + KeyInit + Clone>(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    // HMAC is defined for keys of any length, so this cannot fail.
    let keyed = <M as KeyInit>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    // A(1) = HMAC(secret, A(0)) with A(0) = label || seed.
    let mut a = {
        let mut m = keyed.clone();
        m.update(label);
        m.update(seed);
        m.finalize().into_bytes()
    };
    let mut offset = 0;
    while offset < out.len() {
        let mut m = keyed.clone();
        m.update(&a);
        m.update(label);
        m.update(seed);
        let mut block = m.finalize().into_bytes();
        let n = block.len().min(out.len() - offset);
        out[offset..offset + n].copy_from_slice(&block[..n]);
        block.as_mut_slice().zeroize();
        offset += n;
        let mut m = keyed.clone();
        m.update(&a);
        a = m.finalize().into_bytes();
    }
}

/// `PRF(secret, label, seed)` with the suite's PRF hash, filling `out`.
pub(crate) fn prf(hash: PrfHash, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    match hash {
        PrfHash::Sha256 => p_hash::<Hmac<Sha256>>(secret, label, seed, out),
        PrfHash::Sha384 => p_hash::<Hmac<Sha384>>(secret, label, seed, out),
    }
}

/// Hash of the handshake messages so far, with the suite's PRF hash.
pub(crate) fn transcript_hash(hash: PrfHash, transcript: &[u8]) -> Vec<u8> {
    match hash {
        PrfHash::Sha256 => Sha256::digest(transcript).to_vec(),
        PrfHash::Sha384 => Sha384::digest(transcript).to_vec(),
    }
}

/// RFC 5246 §8.1: `PRF(pre_master_secret, "master secret", client_random ||
/// server_random)[0..48]`.
pub(crate) fn master_secret(
    hash: PrfHash,
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Zeroizing<[u8; MASTER_SECRET_LEN]> {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    let mut out = Zeroizing::new([0u8; MASTER_SECRET_LEN]);
    prf(hash, pre_master_secret, b"master secret", &seed, out.as_mut_slice());
    out
}

/// RFC 7627 §4: `PRF(pre_master_secret, "extended master secret",
/// session_hash)[0..48]`, `session_hash` = hash of the handshake messages up
/// to and including ClientKeyExchange.
pub(crate) fn extended_master_secret(
    hash: PrfHash,
    pre_master_secret: &[u8],
    session_hash: &[u8],
) -> Zeroizing<[u8; MASTER_SECRET_LEN]> {
    let mut out = Zeroizing::new([0u8; MASTER_SECRET_LEN]);
    prf(hash, pre_master_secret, b"extended master secret", session_hash, out.as_mut_slice());
    out
}

/// The record keys of one connection (RFC 5246 §6.3). CBC suites in TLS 1.2
/// use an explicit per-record IV, so no IVs are derived.
pub(crate) struct KeyMaterial {
    pub client_mac: Zeroizing<Vec<u8>>,
    pub server_mac: Zeroizing<Vec<u8>>,
    pub client_key: Zeroizing<Vec<u8>>,
    pub server_key: Zeroizing<Vec<u8>>,
}

/// `key_block = PRF(master_secret, "key expansion", server_random ||
/// client_random)`, split as client MAC, server MAC, client key, server key.
pub(crate) fn key_material(
    suite: CipherSuite,
    master: &[u8; MASTER_SECRET_LEN],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> KeyMaterial {
    let mac_len = suite.mac().len();
    let key_len = suite.enc_key_len();
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    let mut block = Zeroizing::new(vec![0u8; 2 * mac_len + 2 * key_len]);
    prf(suite.prf(), master, b"key expansion", &seed, &mut block);
    let take = |from: usize, len: usize| Zeroizing::new(block[from..from + len].to_vec());
    KeyMaterial {
        client_mac: take(0, mac_len),
        server_mac: take(mac_len, mac_len),
        client_key: take(2 * mac_len, key_len),
        server_key: take(2 * mac_len + key_len, key_len),
    }
}

/// `Finished.verify_data = PRF(master_secret, label, Hash(handshake_messages))[0..12]`.
pub(crate) fn verify_data(
    hash: PrfHash,
    master: &[u8; MASTER_SECRET_LEN],
    label: &[u8],
    handshake_hash: &[u8],
) -> [u8; VERIFY_DATA_LEN] {
    let mut out = [0u8; VERIFY_DATA_LEN];
    prf(hash, master, label, handshake_hash, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The TLS 1.2 PRF test vector for SHA-256 circulated on the IETF TLS
    /// working group list (secret, seed, label "test label", 100 bytes);
    /// cross-checked against Python's `hmac` before it was committed.
    #[test]
    fn tls12_prf_sha256_known_answer() {
        let secret = hex("9b be 43 6b a9 40 f0 17 b1 76 52 84 9a 71 db 35");
        let seed = hex("a0 ba 9f 93 6c da 31 18 27 a6 f7 96 ff d5 19 8c");
        let expected =
            hex("e3 f2 29 ba 72 7b e1 7b 8d 12 26 20 55 7c d4 53 c2 aa b2 1d 07 c3 d4 95 32 9b 52 d4 e6 1e db 5a
             6b 30 17 91 e9 0d 35 c9 c9 a4 6b 4e 14 ba f9 af 0f a0 22 f7 07 7d ef 17 ab fd 37 97 c0 56 4b ab
             4f bc 91 66 6e 9d ef 9b 97 fc e3 4f 79 67 89 ba a4 80 82 d1 22 ee 42 c5 a7 2e 5a 51 10 ff f7 01
             87 34 7b 66");
        let mut out = vec![0u8; expected.len()];
        prf(PrfHash::Sha256, &secret, b"test label", &seed, &mut out);
        assert_eq!(out, expected);
    }

    /// The companion SHA-384 vector (148 bytes), same source and check.
    #[test]
    fn tls12_prf_sha384_known_answer() {
        let secret = hex("b8 0b 73 3d 6c ee fc dc 71 56 6e a4 8e 55 67 df");
        let seed = hex("cd 66 5c f6 a8 44 7d d6 ff 8b 27 55 5e db 74 65");
        let expected =
            hex("7b 0c 18 e9 ce d4 10 ed 18 04 f2 cf a3 4a 33 6a 1c 14 df fb 49 00 bb 5f d7 94 21 07 e8 1c 83 cd
             e9 ca 0f aa 60 be 9f e3 4f 82 b1 23 3c 91 46 a0 e5 34 cb 40 0f ed 27 00 88 4f 9d c2 36 f8 0e dd
             8b fa 96 11 44 c9 e8 d7 92 ec a7 22 a7 b3 2f c3 d4 16 d4 73 eb c2 c5 fd 4a bf da d0 5d 91 84 25
             9b 5b f8 cd 4d 90 fa 0d 31 e2 de c4 79 e4 f1 a2 60 66 f2 ee a9 a6 92 36 a3 e5 26 55 c9 e9 ae e6
             91 c8 f3 a2 68 54 30 8d 5e aa 3b e8 5e 09 90 70 3d 73 e5 6f");
        let mut out = vec![0u8; expected.len()];
        prf(PrfHash::Sha384, &secret, b"test label", &seed, &mut out);
        assert_eq!(out, expected);
    }

    /// Output that is not a multiple of the hash length is a prefix of the
    /// longer output (the PRF is a stream).
    #[test]
    fn prf_output_is_a_prefix_stream() {
        let mut long = [0u8; 100];
        let mut short = [0u8; 33];
        prf(PrfHash::Sha256, b"k", b"l", b"s", &mut long);
        prf(PrfHash::Sha256, b"k", b"l", b"s", &mut short);
        assert_eq!(&long[..33], &short[..]);
    }

    // Fixed inputs for the derivation vectors below. The expected values were
    // computed with an independent implementation (Python `hmac` + `hashlib`,
    // the RFC formulas written out by hand), so a swapped seed order or label
    // here fails the test rather than agreeing with itself.
    fn pms() -> Vec<u8> {
        (0x00..0x20).collect()
    }
    fn client_random() -> [u8; 32] {
        core::array::from_fn(|i| 0x20 + i as u8)
    }
    fn server_random() -> [u8; 32] {
        core::array::from_fn(|i| 0x40 + i as u8)
    }

    #[test]
    fn master_secret_known_answer() {
        let ms = master_secret(PrfHash::Sha256, &pms(), &client_random(), &server_random());
        assert_eq!(
            ms.to_vec(),
            hex("518bc65fd30dabe86349152f98435c94d907b50c92a931c5a2f9e3a4d90f3439f2726c763fb1a40aec90b8bc60173f7c")
        );
        let ms = master_secret(PrfHash::Sha384, &pms(), &client_random(), &server_random());
        assert_eq!(
            ms.to_vec(),
            hex("909490f0f47aee91bd8a00a8f1371a0f419ed788896cfaed9fb726fe7b9bce56af69b2924aebce67f95f8068856cc870")
        );
    }

    #[test]
    fn extended_master_secret_known_answer() {
        let session = transcript_hash(PrfHash::Sha256, b"bv-tls-legacy transcript");
        assert_eq!(
            extended_master_secret(PrfHash::Sha256, &pms(), &session).to_vec(),
            hex("5cc4b9027541a6166d9c8eb4eeb1bc4badd1ba6276dbc73e5291ce46549fe12b4fdce9693ca6734be63670e702d0af99")
        );
        let session = transcript_hash(PrfHash::Sha384, b"bv-tls-legacy transcript");
        assert_eq!(
            extended_master_secret(PrfHash::Sha384, &pms(), &session).to_vec(),
            hex("dbc757bcc75c11302a667f80d8e8ede3981431fac593856b35248350caa39f01c611c8260faddb6360bbbdcec8244e9a")
        );
    }

    #[test]
    fn verify_data_known_answer() {
        let ms = master_secret(PrfHash::Sha256, &pms(), &client_random(), &server_random());
        let hash = transcript_hash(PrfHash::Sha256, b"bv-tls-legacy transcript");
        assert_eq!(
            verify_data(PrfHash::Sha256, &ms, b"client finished", &hash).to_vec(),
            hex("12f6a238c09868c36de621f6")
        );
        assert_eq!(
            verify_data(PrfHash::Sha256, &ms, b"server finished", &hash).to_vec(),
            hex("792c1e538b1192740d72cb56")
        );
        let ms = master_secret(PrfHash::Sha384, &pms(), &client_random(), &server_random());
        let hash = transcript_hash(PrfHash::Sha384, b"bv-tls-legacy transcript");
        assert_eq!(
            verify_data(PrfHash::Sha384, &ms, b"client finished", &hash).to_vec(),
            hex("026736dbe0243d97ae1a0448")
        );
        assert_eq!(
            verify_data(PrfHash::Sha384, &ms, b"server finished", &hash).to_vec(),
            hex("ac96c4c964a78c4b13dcf06c")
        );
    }

    /// Key block split for the SHA-1 / AES-128 suite (PRF SHA-256, 72 bytes)
    /// and the SHA-384 / AES-256 suite (PRF SHA-384, 160 bytes).
    #[test]
    fn key_block_known_answer_and_split() {
        let ms = master_secret(PrfHash::Sha256, &pms(), &client_random(), &server_random());
        let block =
            hex("9052d2e0e4485b2e323effcbc8a47e0839454ba1588ffbc35dccffd8fe8f67f36aee3d733b5a6abc5818a826fab3fea5\
             82291c5ae2097fcbbcb6038cd5d6a970f236e9b87b13063d");
        let km = key_material(CipherSuite::EcdheRsaAes128CbcSha, &ms, &client_random(), &server_random());
        assert_eq!(*km.client_mac, block[0..20]);
        assert_eq!(*km.server_mac, block[20..40]);
        assert_eq!(*km.client_key, block[40..56]);
        assert_eq!(*km.server_key, block[56..72]);

        let ms = master_secret(PrfHash::Sha384, &pms(), &client_random(), &server_random());
        let block =
            hex("b754545d0582b4de3cf2e11c10d40a24731c50482ac068f9efe6ae78a70c77edc487d0a62b6894e874d56e08fc0781f1\
             2a16267ef940fcb04d8f4ca59587024842b596b5c43ed72a6b628e0903b795b8334075f9d4a20b989bf07fdd66b6d7d1\
             aebe0ed9013d079a5bfa24f9cbdbdb3af92ea49ef3d0f53446b224d02fd7b62cf95d509df48cc7344d8b9142261f602c\
             5cdbb69ba7dfbcc0232d04781be5b451");
        let km = key_material(CipherSuite::EcdheRsaAes256CbcSha384, &ms, &client_random(), &server_random());
        assert_eq!(*km.client_mac, block[0..48]);
        assert_eq!(*km.server_mac, block[48..96]);
        assert_eq!(*km.client_key, block[96..128]);
        assert_eq!(*km.server_key, block[128..160]);
    }
}
