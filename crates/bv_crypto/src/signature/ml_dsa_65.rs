use std::fmt;

use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::seed_array;
use crate::error::CryptoError;

pub const ML_DSA_65_SEED_LEN: usize = 32;
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;
pub const ML_DSA_65_SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;

/// An ML-DSA-65 public key and the 32-byte seed it was derived from.
///
/// The seed is the whole private key, so it is wiped when the keypair is
/// dropped and left out of `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa65Keypair {
    public_key: Vec<u8>,
    secret_seed: [u8; ML_DSA_65_SEED_LEN],
}

impl MlDsa65Keypair {
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }

    pub fn secret_seed(&self) -> &[u8; ML_DSA_65_SEED_LEN] {
        &self.secret_seed
    }
}

impl fmt::Debug for MlDsa65Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa65Keypair")
            .field("public_key", &self.public_key)
            .field("secret_seed", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MlDsa65Provider;

impl MlDsa65Provider {
    pub fn generate_keypair(&self) -> Result<MlDsa65Keypair, CryptoError> {
        let mut secret_seed = Zeroizing::new([0u8; ML_DSA_65_SEED_LEN]);
        rand::rng().fill_bytes(secret_seed.as_mut());
        let (public_key, _private_key) = ml_dsa_65::KG::keygen_from_seed(&secret_seed);

        Ok(MlDsa65Keypair { public_key: public_key.into_bytes().to_vec(), secret_seed: *secret_seed })
    }

    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<MlDsa65Keypair, CryptoError> {
        let seed = seed_array::<ML_DSA_65_SEED_LEN>(seed)?;
        let (public_key, _private_key) = ml_dsa_65::KG::keygen_from_seed(&seed);

        Ok(MlDsa65Keypair { public_key: public_key.into_bytes().to_vec(), secret_seed: *seed })
    }

    pub fn sign(&self, seed: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let seed = seed_array::<ML_DSA_65_SEED_LEN>(seed)?;
        let (_public_key, private_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
        let signature = private_key.try_sign(message, context).map_err(|_| CryptoError::SignFailed)?;
        Ok(signature.to_vec())
    }

    pub fn verify(&self, seed: &[u8], message: &[u8], signature: &[u8], context: &[u8]) -> Result<bool, CryptoError> {
        let seed = seed_array::<ML_DSA_65_SEED_LEN>(seed)?;
        let signature: [u8; ML_DSA_65_SIGNATURE_LEN] =
            signature.try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let (public_key, _private_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
        Ok(public_key.verify(message, &signature, context))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn test_ml_dsa_65_round_trip() {
        let provider = MlDsa65Provider;
        let keypair = provider.generate_keypair().unwrap();
        let message = b"bastion_vault";
        let signature = provider.sign(keypair.secret_seed(), message, &[]).unwrap();
        assert!(provider.verify(keypair.secret_seed(), message, &signature, &[]).unwrap());
        assert!(!provider.verify(keypair.secret_seed(), b"bad", &signature, &[]).unwrap());
    }

    #[test]
    fn test_ml_dsa_65_keypair_from_seed_is_deterministic() {
        let seed = [0x5a; ML_DSA_65_SEED_LEN];
        let first = MlDsa65Provider.keypair_from_seed(&seed).unwrap();
        let second = MlDsa65Provider.keypair_from_seed(&seed).unwrap();
        assert_eq!(first.public_key(), second.public_key());
        assert_eq!(first.public_key().len(), ML_DSA_65_PUBLIC_KEY_LEN);
        assert_eq!(first.secret_seed(), &seed);
    }

    #[test]
    fn test_ml_dsa_65_rejects_wrong_seed_length() {
        let short = [0x5a; ML_DSA_65_SEED_LEN - 1];
        assert!(matches!(MlDsa65Provider.keypair_from_seed(&short), Err(CryptoError::InvalidSignatureSeedLength)));
        assert!(matches!(MlDsa65Provider.sign(&short, b"m", &[]), Err(CryptoError::InvalidSignatureSeedLength)));
    }

    #[test]
    fn test_ml_dsa_65_keypair_zeroizes_seed() {
        assert_zeroize_on_drop::<MlDsa65Keypair>();
        let mut keypair = MlDsa65Provider.keypair_from_seed(&[0x5a; ML_DSA_65_SEED_LEN]).unwrap();
        keypair.zeroize();
        assert_eq!(keypair.secret_seed(), &[0u8; ML_DSA_65_SEED_LEN]);
    }

    #[test]
    fn test_ml_dsa_65_keypair_debug_redacts_seed() {
        let keypair = MlDsa65Provider.keypair_from_seed(&[0x5a; ML_DSA_65_SEED_LEN]).unwrap();
        let rendered = format!("{keypair:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("secret_seed: ["), "seed bytes leaked into Debug: {rendered}");
    }
}
