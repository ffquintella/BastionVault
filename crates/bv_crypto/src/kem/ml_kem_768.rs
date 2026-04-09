use ml_kem::{
    kem::{Decapsulate, Encapsulate, FromSeed, Kem, KeyExport, KeyInit, TryKeyInit},
    EncapsulationKey, MlKem768, Seed,
};

use crate::{
    kem::{KemAlgorithm, KemCiphertext, KemKeypair, KemProvider, SharedSecret, ML_KEM_768_SEED_LEN},
    CryptoError,
};

#[derive(Default)]
pub struct MlKem768Provider;

impl MlKem768Provider {
    pub fn keypair_from_seed(&self, seed: &[u8]) -> Result<KemKeypair, CryptoError> {
        if seed.len() != ML_KEM_768_SEED_LEN {
            return Err(CryptoError::InvalidSeedLength);
        }

        let seed = Seed::try_from(seed).map_err(|_| CryptoError::InvalidSeedLength)?;
        let (decapsulation_key, encapsulation_key) = MlKem768::from_seed(&seed);
        let public_key = <EncapsulationKey<MlKem768> as KeyExport>::to_bytes(&encapsulation_key);
        let secret_key = <ml_kem::DecapsulationKey<MlKem768> as KeyExport>::to_bytes(&decapsulation_key);

        Ok(KemKeypair::new(public_key.as_slice().to_vec(), secret_key.as_slice().to_vec()))
    }
}

impl KemProvider for MlKem768Provider {
    fn algorithm(&self) -> KemAlgorithm {
        KemAlgorithm::MlKem768
    }

    fn generate_keypair(&self) -> Result<KemKeypair, CryptoError> {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();
        let public_key = <EncapsulationKey<MlKem768> as KeyExport>::to_bytes(&encapsulation_key);
        let secret_key = <ml_kem::DecapsulationKey<MlKem768> as KeyExport>::to_bytes(&decapsulation_key);

        Ok(KemKeypair::new(public_key.as_slice().to_vec(), secret_key.as_slice().to_vec()))
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(KemCiphertext, SharedSecret), CryptoError> {
        let encapsulation_key =
            EncapsulationKey::<MlKem768>::new_from_slice(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
        let (ciphertext, shared_secret) = encapsulation_key.encapsulate();
        Ok((KemCiphertext::new(ciphertext.as_slice().to_vec()), SharedSecret::new(shared_secret.as_slice().to_vec())))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, CryptoError> {
        let decapsulation_key = ml_kem::DecapsulationKey::<MlKem768>::new_from_slice(secret_key)
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        let shared_secret =
            decapsulation_key.decapsulate_slice(ciphertext).map_err(|_| CryptoError::InvalidKemCiphertext)?;
        Ok(SharedSecret::new(shared_secret.as_slice().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_round_trip() {
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();
        let (ciphertext, send_secret) = provider.encapsulate(keypair.public_key()).unwrap();
        let recv_secret = provider.decapsulate(keypair.secret_key(), ciphertext.as_bytes()).unwrap();

        assert_eq!(send_secret, recv_secret);
    }

    #[test]
    fn ml_kem_768_rejects_invalid_public_key() {
        let provider = MlKem768Provider;
        let err = provider.encapsulate(&[0u8; 32]).unwrap_err();

        assert!(matches!(err, CryptoError::InvalidPublicKey));
    }

    #[test]
    fn ml_kem_768_keypair_from_seed_is_deterministic() {
        let provider = MlKem768Provider;
        let seed = [7u8; ML_KEM_768_SEED_LEN];

        let kp1 = provider.keypair_from_seed(&seed).unwrap();
        let kp2 = provider.keypair_from_seed(&seed).unwrap();

        assert_eq!(kp1, kp2);
    }
}
