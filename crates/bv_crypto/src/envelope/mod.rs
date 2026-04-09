use serde::{Deserialize, Serialize};

use crate::{AeadCipher, Chacha20Poly1305Cipher, CryptoError, KemAlgorithm, KemProvider, Nonce, SymmetricKey};

pub const KEM_DEM_ENVELOPE_V1: u8 = 1;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AeadAlgorithm {
    Chacha20Poly1305,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct KemDemEnvelopeV1 {
    pub version: u8,
    pub kem_algorithm: KemAlgorithm,
    pub aead_algorithm: AeadAlgorithm,
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_key_nonce: Vec<u8>,
    pub wrapped_key_ciphertext: Vec<u8>,
    pub payload_nonce: Vec<u8>,
    pub payload_ciphertext: Vec<u8>,
}

impl KemDemEnvelopeV1 {
    pub fn seal(
        kem_provider: &impl KemProvider,
        recipient_public_key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, CryptoError> {
        let aead = Chacha20Poly1305Cipher;
        let data_key = SymmetricKey::generate();
        let payload_nonce = Nonce::generate();
        let payload_ciphertext = aead.encrypt(&data_key, &payload_nonce, aad, plaintext)?;

        let (kem_ciphertext, shared_secret) = kem_provider.encapsulate(recipient_public_key)?;
        let wrapping_key = SymmetricKey::try_from_slice(shared_secret.as_bytes())?;
        let wrapped_key_nonce = Nonce::generate();
        let wrapped_key_ciphertext =
            aead.encrypt(&wrapping_key, &wrapped_key_nonce, aad, data_key.as_bytes().as_slice())?;

        Ok(Self {
            version: KEM_DEM_ENVELOPE_V1,
            kem_algorithm: kem_provider.algorithm(),
            aead_algorithm: AeadAlgorithm::Chacha20Poly1305,
            kem_ciphertext: kem_ciphertext.as_bytes().to_vec(),
            wrapped_key_nonce: wrapped_key_nonce.as_bytes().to_vec(),
            wrapped_key_ciphertext,
            payload_nonce: payload_nonce.as_bytes().to_vec(),
            payload_ciphertext,
        })
    }

    pub fn open(
        &self,
        kem_provider: &impl KemProvider,
        recipient_secret_key: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if self.version != KEM_DEM_ENVELOPE_V1 {
            return Err(CryptoError::InvalidEnvelopeVersion);
        }

        if self.kem_algorithm != kem_provider.algorithm() || self.aead_algorithm != AeadAlgorithm::Chacha20Poly1305 {
            return Err(CryptoError::UnsupportedAlgorithm);
        }

        let aead = Chacha20Poly1305Cipher;
        let shared_secret = kem_provider.decapsulate(recipient_secret_key, &self.kem_ciphertext)?;
        let wrapping_key = SymmetricKey::try_from_slice(shared_secret.as_bytes())?;
        let wrapped_key_nonce = Nonce::try_from_slice(&self.wrapped_key_nonce)?;
        let data_key_bytes = aead.decrypt(&wrapping_key, &wrapped_key_nonce, aad, &self.wrapped_key_ciphertext)?;
        let data_key = SymmetricKey::try_from_slice(&data_key_bytes)?;
        let payload_nonce = Nonce::try_from_slice(&self.payload_nonce)?;

        aead.decrypt(&data_key, &payload_nonce, aad, &self.payload_ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MlKem768Provider;

    #[test]
    fn kem_dem_envelope_round_trip() {
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();
        let aad = b"envelope:v1:path=test";
        let plaintext = b"bastionvault post quantum envelope";

        let envelope = KemDemEnvelopeV1::seal(&provider, keypair.public_key(), aad, plaintext).unwrap();
        let decrypted = envelope.open(&provider, keypair.secret_key(), aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn kem_dem_envelope_rejects_wrong_aad() {
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();
        let envelope = KemDemEnvelopeV1::seal(&provider, keypair.public_key(), b"aad:v1", b"payload").unwrap();

        let err = envelope.open(&provider, keypair.secret_key(), b"aad:v2").unwrap_err();
        assert!(matches!(err, CryptoError::DecryptFailed));
    }
}
