use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce as ChaChaNonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{aead::AeadCipher, CryptoError};

pub const CHACHA20_POLY1305_KEY_LEN: usize = 32;
pub const CHACHA20_POLY1305_NONCE_LEN: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; CHACHA20_POLY1305_KEY_LEN]);

impl SymmetricKey {
    pub fn generate() -> Self {
        let mut key = [0u8; CHACHA20_POLY1305_KEY_LEN];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn try_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != CHACHA20_POLY1305_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut out = [0u8; CHACHA20_POLY1305_KEY_LEN];
        out.copy_from_slice(key);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; CHACHA20_POLY1305_KEY_LEN] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Nonce([u8; CHACHA20_POLY1305_NONCE_LEN]);

impl Nonce {
    pub fn generate() -> Self {
        let mut nonce = [0u8; CHACHA20_POLY1305_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        Self(nonce)
    }

    pub fn try_from_slice(nonce: &[u8]) -> Result<Self, CryptoError> {
        if nonce.len() != CHACHA20_POLY1305_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength);
        }

        let mut out = [0u8; CHACHA20_POLY1305_NONCE_LEN];
        out.copy_from_slice(nonce);
        Ok(Self(out))
    }

    pub fn as_bytes(&self) -> &[u8; CHACHA20_POLY1305_NONCE_LEN] {
        &self.0
    }
}

#[derive(Default)]
pub struct Chacha20Poly1305Cipher;

impl AeadCipher for Chacha20Poly1305Cipher {
    fn encrypt(&self, key: &SymmetricKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        cipher
            .encrypt(ChaChaNonce::from_slice(nonce.as_bytes()), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::EncryptFailed)
    }

    fn decrypt(
        &self,
        key: &SymmetricKey,
        nonce: &Nonce,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
        cipher
            .decrypt(ChaChaNonce::from_slice(nonce.as_bytes()), Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let cipher = Chacha20Poly1305Cipher;
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let aad = b"barrier:v3";
        let plaintext = b"bastionvault-chacha20poly1305-roundtrip";

        let ciphertext = cipher.encrypt(&key, &nonce, aad, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, aad, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decryption_fails_with_wrong_aad() {
        let cipher = Chacha20Poly1305Cipher;
        let key = SymmetricKey::generate();
        let nonce = Nonce::generate();
        let plaintext = b"barrier-payload";

        let ciphertext = cipher.encrypt(&key, &nonce, b"barrier:v3", plaintext).unwrap();
        let err = cipher.decrypt(&key, &nonce, b"barrier:v4", &ciphertext).unwrap_err();

        assert!(matches!(err, CryptoError::DecryptFailed));
    }

    #[test]
    fn rejects_invalid_key_and_nonce_lengths() {
        assert!(matches!(SymmetricKey::try_from_slice(&[0u8; 31]), Err(CryptoError::InvalidKeyLength)));
        assert!(matches!(Nonce::try_from_slice(&[0u8; 11]), Err(CryptoError::InvalidNonceLength)));
    }
}
