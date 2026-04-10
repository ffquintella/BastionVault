//! Legacy crypto adaptor compatibility surface.
//!
//! New cryptographic work in BastionVault lives in `crates/bv_crypto`. The previous adaptor-based
//! OpenSSL layer has been retired from the default build to remove the OpenSSL dependency.

use crate::errors::RvError;

pub mod crypto_adaptors;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    CBC,
    GCM,
    CCM,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AESKeySize {
    AES128,
    AES192,
    AES256,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyType {
    RSA,
    ECDSA,
    SM2,
}

pub trait BlockCipher {
    fn encrypt(&mut self, _plaintext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn encrypt_update(&mut self, _plaintext: Vec<u8>, _ciphertext: &mut Vec<u8>) -> Result<usize, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn encrypt_final(&mut self, _ciphertext: &mut Vec<u8>) -> Result<usize, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn decrypt(&mut self, _ciphertext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn decrypt_update(&mut self, _ciphertext: Vec<u8>, _plaintext: &mut Vec<u8>) -> Result<usize, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn decrypt_final(&mut self, _plaintext: &mut Vec<u8>) -> Result<usize, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }
}

pub trait AEADCipher: BlockCipher {
    fn set_aad(&mut self, _aad: Vec<u8>) -> Result<(), RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn get_tag(&mut self) -> Result<Vec<u8>, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn set_tag(&mut self, _tag: Vec<u8>) -> Result<(), RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }
}

pub trait PublicKeyCipher {
    fn sign(&mut self, _data: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn verify(&mut self, _data: &Vec<u8>, _sig: &Vec<u8>) -> Result<bool, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn encrypt(&mut self, _plaintext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }

    fn decrypt(&mut self, _ciphertext: &Vec<u8>) -> Result<Vec<u8>, RvError> {
        Err(RvError::ErrCryptoCipherOPNotSupported)
    }
}

#[derive(Default)]
pub struct AES;

impl AES {
    pub fn new(
        _padding: bool,
        _key_size: Option<AESKeySize>,
        _mode: Option<CipherMode>,
        _key: Option<Vec<u8>>,
        _iv: Option<Vec<u8>>,
    ) -> Result<Self, RvError> {
        Ok(Self)
    }
}

impl BlockCipher for AES {}
impl AEADCipher for AES {}

#[derive(Default)]
pub struct SM4;

impl SM4 {
    pub fn new(
        _padding: bool,
        _mode: Option<CipherMode>,
        _key: Option<Vec<u8>>,
        _iv: Option<Vec<u8>>,
    ) -> Result<Self, RvError> {
        Ok(Self)
    }
}

impl BlockCipher for SM4 {}
impl AEADCipher for SM4 {}
