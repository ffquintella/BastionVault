//! Known-answer and old-data tests: AEAD ciphertext, ML-DSA keys and
//! signatures, the BVRG-v1 hybrid signature and the KEM/DEM envelope must
//! stay byte-identical across dependency upgrades.

use bv_crypto::bvrg::{sign_detached_hybrid, verify_detached_hybrid, HYBRID_SIG_LEN};
use bv_crypto::{
    AeadCipher, BvrgMasterPublicKey, BvrgMasterSigningKey, Chacha20Poly1305Cipher, KemDemEnvelopeV1, MlDsa44Provider,
    MlDsa65Provider, MlDsa87Provider, MlKem768Provider, Nonce, SymmetricKey,
};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, Signer as _};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// Provenance: ChaCha20-Poly1305 is RFC 8439 §2.8.2, Ed25519 is RFC 8032 TEST 1.
// Every other expected value and `tests/data/compat_v1/` was written by commit
// 1ae9d7e1 (chacha20poly1305 0.10.1, ed25519-dalek 2.2.0, fips204 0.4.6).

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd-length hex fixture");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex fixture")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A frozen fixture written by the old build. Never regenerate one with a newer build.
fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/compat_v1/{name}", env!("CARGO_MANIFEST_DIR"));
    unhex(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}")))
}

const ML_DSA_SEED: [u8; 32] = [0x5a; 32];
const KAT_MESSAGE: &[u8] = b"bastion-vault compat kat v1";

/// Ed25519 seed of RFC 8032 §7.1 TEST 1, reused as the BVRG classical half.
const RFC8032_T1_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn bvrg_master() -> BvrgMasterSigningKey {
    let ed_seed: [u8; 32] = unhex(RFC8032_T1_SEED).try_into().unwrap();
    BvrgMasterSigningKey {
        ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_seed),
        mldsa65_seed: Zeroizing::new([0x42; 32]),
    }
}

// ── ChaCha20-Poly1305 ──────────────────────────────────────────────

#[test]
fn chacha20_poly1305_matches_rfc8439_aead_vector() {
    let key: Vec<u8> = (0x80u8..=0x9f).collect();
    let key = SymmetricKey::try_from_slice(&key).unwrap();
    let nonce = Nonce::try_from_slice(&unhex("070000004041424344454647")).unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected = unhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b6116\
         1ae10b594f09e26a7e902ecbd0600691",
    );

    let cipher = Chacha20Poly1305Cipher;
    let ct = cipher.encrypt(&key, &nonce, &aad, plaintext).unwrap();
    assert_eq!(hex(&ct), hex(&expected));
    assert_eq!(cipher.decrypt(&key, &nonce, &aad, &expected).unwrap(), plaintext);

    // Malformed input: a truncated tag and a flipped tag bit are refused.
    assert!(cipher.decrypt(&key, &nonce, &aad, &expected[..expected.len() - 1]).is_err());
    let mut flipped = expected.clone();
    *flipped.last_mut().unwrap() ^= 0x01;
    assert!(cipher.decrypt(&key, &nonce, &aad, &flipped).is_err());
}

// ── ML-DSA ─────────────────────────────────────────────────────────

#[test]
fn ml_dsa_public_keys_from_a_fixed_seed_are_unchanged() {
    // SHA-256 of the encoded public key derived from `ML_DSA_SEED`.
    assert_eq!(
        sha256_hex(MlDsa44Provider.keypair_from_seed(&ML_DSA_SEED).unwrap().public_key()),
        "7c748368306992eba3649a53705735cb7ffef8f4210b9852b2efa264d80a8b27"
    );
    assert_eq!(
        sha256_hex(MlDsa65Provider.keypair_from_seed(&ML_DSA_SEED).unwrap().public_key()),
        "3c0c693a14b7ad8fcc0272eacce507b514d865a06e8058087130f50ff43cc09b"
    );
    assert_eq!(
        sha256_hex(MlDsa87Provider.keypair_from_seed(&ML_DSA_SEED).unwrap().public_key()),
        "0d716eae5161d6c643028de9f983c092a659ce1beb6cf79d709f51ab9575a232"
    );
}

#[test]
fn ml_dsa_65_deterministic_signature_is_unchanged_and_verifies() {
    let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(&ML_DSA_SEED);
    let sig = sk.try_sign_with_seed(&[0u8; 32], KAT_MESSAGE, b"").unwrap();
    assert_eq!(sha256_hex(&sig), "437d2682e9ddc663205cd474d24981b0ad3d357d9f864af887ce880ad4e54f29");
    assert!(MlDsa65Provider.verify(&ML_DSA_SEED, KAT_MESSAGE, &sig, &[]).unwrap());
    assert!(!MlDsa65Provider.verify(&ML_DSA_SEED, b"other message", &sig, &[]).unwrap());
}

#[test]
fn ml_dsa_65_signature_written_by_the_old_build_verifies() {
    let sig = fixture("ml_dsa_65_hedged_sig.hex");
    assert_eq!(sig.len(), bv_crypto::ML_DSA_65_SIGNATURE_LEN);
    assert!(MlDsa65Provider.verify(&ML_DSA_SEED, KAT_MESSAGE, &sig, &[]).unwrap());
}

// ── BVRG-v1 detached hybrid signature ──────────────────────────────

#[test]
fn bvrg_hybrid_signature_written_by_the_old_build_verifies() {
    let master = bvrg_master();
    let public: BvrgMasterPublicKey = master.public_key();
    assert_eq!(hex(public.ed25519.as_bytes()), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert_eq!(sha256_hex(&public.mldsa65), "2f40048b7202cf1d33e0af88f0695e076d00fea5be3d201d667021afe09c23c1");

    let old = fixture("bvrg_detached_hybrid_sig.hex");
    assert_eq!(old.len(), HYBRID_SIG_LEN);
    verify_detached_hybrid(KAT_MESSAGE, &old, &public).expect("old hybrid signature must verify");

    // The Ed25519 half is deterministic (RFC 8032), so a fresh signature must
    // reproduce the old one's classical half byte for byte.
    let fresh = sign_detached_hybrid(&master, KAT_MESSAGE).unwrap();
    assert_eq!(hex(&fresh[..66]), hex(&old[..66]));

    // Malformed input: one flipped bit in either half is refused.
    for i in [10usize, 70, HYBRID_SIG_LEN - 1] {
        let mut bad = old.clone();
        bad[i] ^= 0x01;
        assert!(verify_detached_hybrid(KAT_MESSAGE, &bad, &public).is_err(), "flipped byte {i} verified");
    }
}

#[test]
fn ed25519_half_matches_rfc8032_test_1() {
    let master = bvrg_master();
    let sig = sign_detached_hybrid(&master, b"").unwrap();
    assert_eq!(
        hex(&sig[2..66]),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

// ── KEM/DEM envelope ───────────────────────────────────────────────

#[test]
fn kem_dem_envelope_written_by_the_old_build_opens() {
    let keypair = MlKem768Provider.keypair_from_seed(&[0x11; 64]).unwrap();
    assert_eq!(sha256_hex(keypair.public_key()), "27ee97675ef5c87eab6f25d7348c278ff46ed744eb5ffd7076edc87a00bffa3b");
    let cbor = fixture("kem_dem_envelope_v1.cbor.hex");
    let envelope: KemDemEnvelopeV1 = ciborium::de::from_reader(cbor.as_slice()).unwrap();
    let plaintext = envelope.open(&MlKem768Provider, keypair.secret_key(), b"compat:v1").unwrap();
    assert_eq!(plaintext, KAT_MESSAGE);
    assert!(envelope.open(&MlKem768Provider, keypair.secret_key(), b"compat:v2").is_err());
}
