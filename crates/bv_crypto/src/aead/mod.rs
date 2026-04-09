mod chacha20_poly1305;

pub use chacha20_poly1305::{Chacha20Poly1305Cipher, Nonce, SymmetricKey};

use crate::CryptoError;

pub trait AeadCipher {
    fn encrypt(&self, key: &SymmetricKey, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn decrypt(&self, key: &SymmetricKey, nonce: &Nonce, aad: &[u8], ciphertext: &[u8])
        -> Result<Vec<u8>, CryptoError>;
}
