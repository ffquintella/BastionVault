//! Algorithm-specific crypto wrappers used by the path handlers.
//!
//! Each submodule owns one algorithm family and exposes the same
//! shape: `generate_keypair` (or `generate_*_key`) + the operation
//! primitives. The path handlers branch on `KeyType` and dispatch
//! into the right wrapper rather than threading provider objects
//! through the call stack.

pub mod ciphertext;
pub mod derive;
pub mod ed25519;
#[cfg(feature = "transit_pqc_hybrid")]
pub mod hybrid;
pub mod ml_dsa;
pub mod ml_kem;
pub mod sym;

/// Constant-time comparison helper used by HMAC-verify.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// HMAC over the supplied message using the configured hash algo.
/// Symmetric `Hmac` keys can MAC; AEAD keys can also MAC under their
/// own key material (Vault parity).
pub fn hmac(hash: HashAlgo, key: &[u8], msg: &[u8]) -> Vec<u8> {
    use hmac::{digest::KeyInit, Mac};
    match hash {
        HashAlgo::Sha256 => {
            let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
                .expect("hmac accepts any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        HashAlgo::Sha384 => {
            let mut m = <hmac::Hmac<sha2::Sha384> as KeyInit>::new_from_slice(key)
                .expect("hmac accepts any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        HashAlgo::Sha512 => {
            let mut m = <hmac::Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key)
                .expect("hmac accepts any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// Hash a single message under one of the supported algos.
pub fn hash(algo: HashAlgo, msg: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match algo {
        HashAlgo::Sha256 => sha2::Sha256::digest(msg).to_vec(),
        HashAlgo::Sha384 => sha2::Sha384::digest(msg).to_vec(),
        HashAlgo::Sha512 => sha2::Sha512::digest(msg).to_vec(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgo {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "" | "sha2-256" | "sha-256" | "sha256" => Ok(Self::Sha256),
            "sha2-384" | "sha-384" | "sha384" => Ok(Self::Sha384),
            "sha2-512" | "sha-512" | "sha512" => Ok(Self::Sha512),
            other => Err(format!(
                "unsupported hash algo `{other}`; expected sha2-256, sha2-384, or sha2-512"
            )),
        }
    }
}
