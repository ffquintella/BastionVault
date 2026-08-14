//! ML-DSA-44 / 65 / 87 sign and verify.
//!
//! Built on `bv_crypto::MlDsaXXProvider` (which wraps `fips204`).
//! `material` in `KeyVersion` is the 32-byte seed; the public key
//! is rederived from the seed at keygen time and stashed in `pk` so
//! `GET /keys/:name` can return it without a second derivation.
//!
//! `verify` here uses the seed too because that's what `bv_crypto`
//! exposes — the FIPS 204 verifier consumes the public key, but
//! `bv_crypto` rederives it from the seed inside `verify`. For the
//! Transit `verify` path, the engine has the public key from `pk`
//! already and could in principle bypass the seed; we go through
//! `bv_crypto`'s wrapper anyway to keep this file algorithm-agnostic
//! and to centralise the FIPS 204 dependency in one place.

use bv_crypto::{
    MlDsa44Provider, MlDsa65Provider, MlDsa87Provider,
    ML_DSA_44_SEED_LEN, ML_DSA_65_SEED_LEN, ML_DSA_87_SEED_LEN,
};

use super::super::keytype::KeyType;
use crate::errors::RvError;

pub fn seed_len(kt: KeyType) -> usize {
    match kt {
        KeyType::MlDsa44 => ML_DSA_44_SEED_LEN,
        KeyType::MlDsa65 => ML_DSA_65_SEED_LEN,
        KeyType::MlDsa87 => ML_DSA_87_SEED_LEN,
        _ => 0,
    }
}

/// Generate a fresh ML-DSA keypair at the requested level. Returns
/// `(seed, public_key)`.
pub fn generate_keypair(kt: KeyType) -> Result<(Vec<u8>, Vec<u8>), RvError> {
    match kt {
        KeyType::MlDsa44 => {
            let kp = MlDsa44Provider
                .generate_keypair()
                .map_err(|e| RvError::ErrString(format!("ml-dsa-44 keygen: {e:?}")))?;
            Ok((kp.secret_seed().to_vec(), kp.public_key().to_vec()))
        }
        KeyType::MlDsa65 => {
            let kp = MlDsa65Provider
                .generate_keypair()
                .map_err(|e| RvError::ErrString(format!("ml-dsa-65 keygen: {e:?}")))?;
            Ok((kp.secret_seed().to_vec(), kp.public_key().to_vec()))
        }
        KeyType::MlDsa87 => {
            let kp = MlDsa87Provider
                .generate_keypair()
                .map_err(|e| RvError::ErrString(format!("ml-dsa-87 keygen: {e:?}")))?;
            Ok((kp.secret_seed().to_vec(), kp.public_key().to_vec()))
        }
        other => Err(RvError::ErrString(format!(
            "{} is not an ml-dsa key type",
            other.as_str()
        ))),
    }
}

pub fn sign(kt: KeyType, seed: &[u8], message: &[u8]) -> Result<Vec<u8>, RvError> {
    match kt {
        KeyType::MlDsa44 => MlDsa44Provider
            .sign(seed, message, &[])
            .map_err(|e| RvError::ErrString(format!("ml-dsa-44 sign: {e:?}"))),
        KeyType::MlDsa65 => MlDsa65Provider
            .sign(seed, message, &[])
            .map_err(|e| RvError::ErrString(format!("ml-dsa-65 sign: {e:?}"))),
        KeyType::MlDsa87 => MlDsa87Provider
            .sign(seed, message, &[])
            .map_err(|e| RvError::ErrString(format!("ml-dsa-87 sign: {e:?}"))),
        other => Err(RvError::ErrString(format!(
            "{} is not an ml-dsa key type",
            other.as_str()
        ))),
    }
}

pub fn verify(
    kt: KeyType,
    seed: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, RvError> {
    match kt {
        KeyType::MlDsa44 => MlDsa44Provider
            .verify(seed, message, signature, &[])
            .map_err(|e| RvError::ErrString(format!("ml-dsa-44 verify: {e:?}"))),
        KeyType::MlDsa65 => MlDsa65Provider
            .verify(seed, message, signature, &[])
            .map_err(|e| RvError::ErrString(format!("ml-dsa-65 verify: {e:?}"))),
        KeyType::MlDsa87 => MlDsa87Provider
            .verify(seed, message, signature, &[])
            .map_err(|e| RvError::ErrString(format!("ml-dsa-87 verify: {e:?}"))),
        other => Err(RvError::ErrString(format!(
            "{} is not an ml-dsa key type",
            other.as_str()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(kt: KeyType) {
        let (seed, _pk) = generate_keypair(kt).unwrap();
        let msg = b"transit ml-dsa";
        let sig = sign(kt, &seed, msg).unwrap();
        assert!(verify(kt, &seed, msg, &sig).unwrap());
        assert!(!verify(kt, &seed, b"tampered", &sig).unwrap());
    }

    #[test]
    fn round_trip_44() {
        round_trip(KeyType::MlDsa44);
    }

    #[test]
    fn round_trip_65() {
        round_trip(KeyType::MlDsa65);
    }

    #[test]
    fn round_trip_87() {
        round_trip(KeyType::MlDsa87);
    }
}
