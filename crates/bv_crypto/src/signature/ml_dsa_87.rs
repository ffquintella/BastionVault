use fips204::{
    ml_dsa_87,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use rand::Rng;

use crate::error::CryptoError;

pub const ML_DSA_87_SEED_LEN: usize = 32;
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = ml_dsa_87::PK_LEN;
pub const ML_DSA_87_SIGNATURE_LEN: usize = ml_dsa_87::SIG_LEN;

#[derive(Debug, Clone)]
pub struct MlDsa87Keypair {
    public_key: Vec<u8>,
    secret_seed: [u8; ML_DSA_87_SEED_LEN],
}

impl MlDsa87Keypair {
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_slice()
    }
    pub fn secret_seed(&self) -> &[u8; ML_DSA_87_SEED_LEN] {
        &self.secret_seed
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MlDsa87Provider;

impl MlDsa87Provider {
    pub fn generate_keypair(&self) -> Result<MlDsa87Keypair, CryptoError> {
        let mut secret_seed = [0u8; ML_DSA_87_SEED_LEN];
        rand::rng().fill_bytes(&mut secret_seed);
        let (public_key, _private_key) = ml_dsa_87::KG::keygen_from_seed(&secret_seed);
        Ok(MlDsa87Keypair { public_key: public_key.into_bytes().to_vec(), secret_seed })
    }

    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<MlDsa87Keypair, CryptoError> {
        let seed: [u8; ML_DSA_87_SEED_LEN] =
            seed.try_into().map_err(|_| CryptoError::InvalidSignatureSeedLength)?;
        let (public_key, _private_key) = ml_dsa_87::KG::keygen_from_seed(&seed);
        Ok(MlDsa87Keypair { public_key: public_key.into_bytes().to_vec(), secret_seed: seed })
    }

    pub fn sign(&self, seed: &[u8], message: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let seed: [u8; ML_DSA_87_SEED_LEN] =
            seed.try_into().map_err(|_| CryptoError::InvalidSignatureSeedLength)?;
        let (_pk, sk) = ml_dsa_87::KG::keygen_from_seed(&seed);
        let signature = sk.try_sign(message, context).map_err(|_| CryptoError::SignFailed)?;
        Ok(signature.to_vec())
    }

    pub fn verify(&self, seed: &[u8], message: &[u8], signature: &[u8], context: &[u8]) -> Result<bool, CryptoError> {
        let seed: [u8; ML_DSA_87_SEED_LEN] =
            seed.try_into().map_err(|_| CryptoError::InvalidSignatureSeedLength)?;
        let signature: [u8; ML_DSA_87_SIGNATURE_LEN] =
            signature.try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let (pk, _sk) = ml_dsa_87::KG::keygen_from_seed(&seed);
        Ok(pk.verify(message, &signature, context))
    }
}
