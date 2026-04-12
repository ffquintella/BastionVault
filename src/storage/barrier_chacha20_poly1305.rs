//! Experimental versioned barrier implementation backed by ChaCha20-Poly1305.
//!
//! This barrier is intentionally kept parallel to the active AES-GCM barrier so the
//! format and operational behavior can be tested before any default cutover.

use std::{any::Any, sync::Arc};

use arc_swap::ArcSwap;
use better_default::Default;
use blake3::hash;
use bv_crypto::{AeadCipher, Chacha20Poly1305Cipher, CryptoError, Nonce, SymmetricKey, ML_KEM_768_SEED_LEN};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{
    barrier::{SecurityBarrier, BARRIER_INIT_PATH},
    barrier_chacha20_poly1305_init::BarrierInitRecord,
    pq_key_envelope::PostQuantumKeyEnvelope,
    Backend, BackendEntry, Storage, StorageEntry,
};
use crate::errors::RvError;

const EPOCH_SIZE: usize = 4;
const KEY_EPOCH: u8 = 1;
pub const BARRIER_CHACHA20_POLY1305_VERSION: u8 = 0x3;
const CHACHA_KEY_SIZE: usize = 32;

#[derive(Debug, Clone, Default, Zeroize)]
#[zeroize(drop)]
struct BarrierInfo {
    #[default(true)]
    sealed: bool,
    key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BarrierCiphertextV3 {
    version: u8,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl BarrierCiphertextV3 {
    fn encrypt(path: &str, key: &[u8], plaintext: &[u8]) -> Result<Self, RvError> {
        let cipher = Chacha20Poly1305Cipher;
        let key = SymmetricKey::try_from_slice(key).map_err(map_crypto_error)?;
        let nonce = Nonce::generate();
        let ciphertext = cipher.encrypt(&key, &nonce, path.as_bytes(), plaintext).map_err(map_crypto_error)?;

        Ok(Self { version: BARRIER_CHACHA20_POLY1305_VERSION, nonce: nonce.as_bytes().to_vec(), ciphertext })
    }

    fn decrypt(&self, path: &str, key: &[u8]) -> Result<Vec<u8>, RvError> {
        if self.version != BARRIER_CHACHA20_POLY1305_VERSION {
            return Err(RvError::ErrBarrierVersionMismatch);
        }

        let cipher = Chacha20Poly1305Cipher;
        let key = SymmetricKey::try_from_slice(key).map_err(map_crypto_error)?;
        let nonce = Nonce::try_from_slice(&self.nonce).map_err(map_crypto_error)?;

        cipher.decrypt(&key, &nonce, path.as_bytes(), &self.ciphertext).map_err(|_| RvError::ErrBarrierKeyInvalid)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EPOCH_SIZE + 1 + self.nonce.len() + self.ciphertext.len());
        out.extend_from_slice(&[0, 0, 0, KEY_EPOCH]);
        out.push(self.version);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    fn decode(encoded: &[u8]) -> Result<Self, RvError> {
        if encoded.len() < EPOCH_SIZE + 1 {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        if encoded[0] != 0 || encoded[1] != 0 || encoded[2] != 0 || encoded[3] != KEY_EPOCH {
            return Err(RvError::ErrBarrierEpochMismatch);
        }

        let version = encoded[4];
        if version != BARRIER_CHACHA20_POLY1305_VERSION {
            return Err(RvError::ErrBarrierVersionMismatch);
        }

        let nonce_end = EPOCH_SIZE + 1 + 12;
        if encoded.len() <= nonce_end {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        Ok(Self {
            version,
            nonce: encoded[EPOCH_SIZE + 1..nonce_end].to_vec(),
            ciphertext: encoded[nonce_end..].to_vec(),
        })
    }
}

pub struct ChaCha20Poly1305Barrier {
    barrier_info: ArcSwap<BarrierInfo>,
    backend: Arc<dyn Backend>,
}

#[maybe_async::maybe_async]
impl Storage for ChaCha20Poly1305Barrier {
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
        if self.barrier_info.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        let mut ret = self.backend.list(prefix).await?;
        ret.sort();
        Ok(ret)
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
        if self.barrier_info.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        let pe = self.backend.get(key).await?;
        if pe.is_none() {
            return Ok(None);
        }

        let plain = self.decrypt(key, pe.as_ref().unwrap().value.as_slice())?;
        Ok(Some(StorageEntry { key: key.to_string(), value: plain }))
    }

    async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
        if self.barrier_info.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        let ciphertext = self.encrypt(&entry.key, entry.value.as_slice())?;
        let be = BackendEntry { key: entry.key.clone(), value: ciphertext };
        self.backend.put(&be).await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), RvError> {
        if self.barrier_info.load().sealed {
            return Err(RvError::ErrBarrierSealed);
        }

        self.backend.delete(key).await
    }

    async fn lock(&self, lock_name: &str) -> Result<Box<dyn Any>, RvError> {
        self.backend.lock(lock_name).await
    }
}

#[maybe_async::maybe_async]
impl SecurityBarrier for ChaCha20Poly1305Barrier {
    async fn inited(&self) -> Result<bool, RvError> {
        Ok(self.backend.get(BARRIER_INIT_PATH).await?.is_some())
    }

    async fn init(&self, kek: &[u8]) -> Result<(), RvError> {
        let (min, max) = self.key_length_range();
        if kek.len() < min || kek.len() > max {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        if self.inited().await? {
            return Err(RvError::ErrBarrierAlreadyInit);
        }

        let encrypt_key = self.generate_encryption_key()?;
        let barrier_init = BarrierInitRecord::new(encrypt_key.to_vec());
        let value = barrier_init.encode_ml_kem_768_from_seed(kek)?;
        let be = BackendEntry { key: BARRIER_INIT_PATH.to_string(), value };
        self.backend.put(&be).await?;
        Ok(())
    }

    fn generate_key(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let mut buf = Zeroizing::new(vec![0u8; ML_KEM_768_SEED_LEN]);
        rand::rng().fill_bytes(buf.as_mut_slice());
        Ok(buf)
    }

    fn key_length_range(&self) -> (usize, usize) {
        (ML_KEM_768_SEED_LEN, ML_KEM_768_SEED_LEN)
    }

    fn sealed(&self) -> Result<bool, RvError> {
        Ok(self.barrier_info.load().sealed)
    }

    async fn unseal(&self, kek: &[u8]) -> Result<(), RvError> {
        if !self.sealed()? {
            return Ok(());
        }

        let entry = self.backend.get(BARRIER_INIT_PATH).await?;
        if entry.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }

        let barrier_init = BarrierInitRecord::decode_ml_kem_768_from_seed(entry.unwrap().value.as_slice(), kek)
            .map_err(|_| RvError::ErrBarrierUnsealFailed)?;

        self.init_cipher(barrier_init.key.as_slice())?;
        let mut barrier_info = (*self.barrier_info.load_full()).clone();
        barrier_info.sealed = false;
        self.barrier_info.store(Arc::new(barrier_info));

        Ok(())
    }

    fn seal(&self) -> Result<(), RvError> {
        self.reset_cipher()?;
        let mut barrier_info = (*self.barrier_info.load_full()).clone();
        barrier_info.sealed = true;
        self.barrier_info.store(Arc::new(barrier_info));
        Ok(())
    }

    fn derive_hmac_key(&self) -> Result<Vec<u8>, RvError> {
        let barrier_info = self.barrier_info.load();
        if barrier_info.key.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }
        if self.sealed()? {
            return Err(RvError::ErrBarrierSealed);
        }

        let key = Zeroizing::new(barrier_info.key.clone().unwrap());
        Ok(hash(key.as_slice()).as_bytes().to_vec())
    }

    fn as_storage(&self) -> &dyn Storage {
        self
    }
}

impl ChaCha20Poly1305Barrier {
    pub fn new(physical: Arc<dyn Backend>) -> Self {
        Self { backend: physical, barrier_info: ArcSwap::from_pointee(BarrierInfo::default()) }
    }

    fn generate_encryption_key(&self) -> Result<Zeroizing<Vec<u8>>, RvError> {
        let mut buf = Zeroizing::new(vec![0u8; CHACHA_KEY_SIZE]);
        rand::rng().fill_bytes(buf.as_mut_slice());
        Ok(buf)
    }

    fn init_cipher(&self, key: &[u8]) -> Result<(), RvError> {
        let mut barrier_info = (*self.barrier_info.load_full()).clone();
        barrier_info.key = Some(key.to_vec());
        self.barrier_info.store(Arc::new(barrier_info));
        Ok(())
    }

    fn reset_cipher(&self) -> Result<(), RvError> {
        let mut barrier_info = (*self.barrier_info.load_full()).clone();
        barrier_info.key.zeroize();
        barrier_info.key = None;
        self.barrier_info.store(Arc::new(barrier_info));
        Ok(())
    }

    fn encrypt(&self, path: &str, plaintext: &[u8]) -> Result<Vec<u8>, RvError> {
        let barrier_info = self.barrier_info.load();
        if barrier_info.key.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }

        let key = Zeroizing::new(barrier_info.key.clone().unwrap());
        let envelope = BarrierCiphertextV3::encrypt(path, key.as_slice(), plaintext)?;
        Ok(envelope.encode())
    }

    fn decrypt(&self, path: &str, ciphertext: &[u8]) -> Result<Vec<u8>, RvError> {
        let barrier_info = self.barrier_info.load();
        if barrier_info.key.is_none() {
            return Err(RvError::ErrBarrierNotInit);
        }

        let key = Zeroizing::new(barrier_info.key.clone().unwrap());
        let envelope = BarrierCiphertextV3::decode(ciphertext)?;
        envelope.decrypt(path, key.as_slice())
    }

    pub async fn init_with_pq(&self, public_key: &[u8]) -> Result<(), RvError> {
        if self.inited().await? {
            return Err(RvError::ErrBarrierAlreadyInit);
        }

        let encrypt_key = self.generate_encryption_key()?;
        let barrier_init = BarrierInitRecord::new(encrypt_key.to_vec());
        let be = BackendEntry {
            key: BARRIER_INIT_PATH.to_string(),
            value: PostQuantumKeyEnvelope::seal_ml_kem_768(
                public_key,
                BARRIER_INIT_PATH.as_bytes(),
                &barrier_init.encode_direct()?,
            )?
            .encode()?,
        };
        self.backend.put(&be).await?;

        Ok(())
    }

    pub async fn unseal_with_pq(&self, secret_key: &[u8]) -> Result<(), RvError> {
        if !self.sealed()? {
            return Ok(());
        }

        let entry = self.backend.get(BARRIER_INIT_PATH).await?;
        let entry = entry.ok_or(RvError::ErrBarrierNotInit)?;
        let envelope =
            PostQuantumKeyEnvelope::decode(entry.value.as_slice()).map_err(|_| RvError::ErrBarrierUnsealFailed)?;
        let barrier_init_bytes = envelope
            .open_ml_kem_768(secret_key, BARRIER_INIT_PATH.as_bytes())
            .map_err(|_| RvError::ErrBarrierUnsealFailed)?;
        let barrier_init =
            BarrierInitRecord::decode_direct(&barrier_init_bytes).map_err(|_| RvError::ErrBarrierUnsealFailed)?;

        self.init_cipher(barrier_init.key.as_slice())?;
        let mut barrier_info = (*self.barrier_info.load_full()).clone();
        barrier_info.sealed = false;
        self.barrier_info.store(Arc::new(barrier_info));

        Ok(())
    }
}

fn map_crypto_error(err: CryptoError) -> RvError {
    match err {
        CryptoError::InvalidKeyLength
        | CryptoError::InvalidNonceLength
        | CryptoError::InvalidSeedLength
        | CryptoError::InvalidPublicKey
        | CryptoError::InvalidSecretKey
        | CryptoError::InvalidKemCiphertext
        | CryptoError::InvalidSignatureSeedLength
        | CryptoError::InvalidSignaturePublicKey
        | CryptoError::InvalidSignatureSecretKey
        | CryptoError::InvalidSignature
        | CryptoError::InvalidEnvelopeVersion
        | CryptoError::UnsupportedAlgorithm => RvError::ErrBarrierKeyInvalid,
        CryptoError::EncryptFailed | CryptoError::SignFailed => RvError::ErrCryptoCipherInitFailed,
        CryptoError::DecryptFailed => RvError::ErrBarrierKeyInvalid,
        CryptoError::VerifyFailed => RvError::ErrBarrierKeyInvalid,
    }
}

#[cfg(test)]
mod tests {
    use super::{super::*, *};
    use crate::test_utils::new_test_backend;

    #[test]
    fn barrier_v3_round_trip() {
        let backend = new_test_backend("test_chacha_encrypt_decrypt");
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(key.as_mut_slice());

        let barrier = ChaCha20Poly1305Barrier {
            backend,
            barrier_info: ArcSwap::from_pointee(BarrierInfo { sealed: true, key: Some(key), ..Default::default() }),
        };

        let path = "test/";
        let plaintext = "bastionvault barrier v3 payload";
        let ciphertext = barrier.encrypt(path, plaintext.as_bytes()).unwrap();
        let decrypted = barrier.decrypt(path, ciphertext.as_slice()).unwrap();
        assert_eq!(plaintext.as_bytes(), decrypted);
        assert!(barrier.decrypt("test2/", ciphertext.as_slice()).is_err());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_barrier_chacha20poly1305() {
        let backend = new_test_backend("test_barrier_chacha20poly1305");
        let barrier = ChaCha20Poly1305Barrier::new(backend.clone());

        assert!(!barrier.inited().await.unwrap());
        assert!(barrier.sealed().unwrap());

        let mut key = vec![0u8; ML_KEM_768_SEED_LEN];
        rand::rng().fill_bytes(key.as_mut_slice());
        barrier.init(key.as_slice()).await.unwrap();
        assert!(barrier.sealed().unwrap());
        barrier.unseal(key.as_slice()).await.unwrap();
        assert!(!barrier.sealed().unwrap());
        barrier.seal().unwrap();
        assert!(barrier.sealed().unwrap());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_barrier_chacha20poly1305_storage_api() {
        let backend = new_test_backend("test_barrier_chacha20poly1305_storage_api");
        let barrier = ChaCha20Poly1305Barrier::new(backend.clone());

        let mut key = vec![0u8; ML_KEM_768_SEED_LEN];
        rand::rng().fill_bytes(key.as_mut_slice());
        barrier.init(key.as_slice()).await.unwrap();
        barrier.unseal(key.as_slice()).await.unwrap();

        assert!(barrier.list("/bin").await.is_err());
        assert_eq!(barrier.list("").await.unwrap().len(), 1);
        assert_eq!(barrier.list("xxx").await.unwrap().len(), 0);
        assert!(barrier.get("").await.unwrap().is_none());
        assert!(barrier.get("bar").await.unwrap().is_none());
        assert!(barrier.get("/").await.is_err());

        let entry1 = StorageEntry { key: "bar".to_string(), value: "test1".as_bytes().to_vec() };
        let entry2 = StorageEntry { key: "bar/foo".to_string(), value: "test2".as_bytes().to_vec() };
        let entry3 = StorageEntry { key: "bar/foo/goo".to_string(), value: "test3".as_bytes().to_vec() };

        barrier.put(&entry1).await.unwrap();
        barrier.put(&entry2).await.unwrap();
        barrier.put(&entry3).await.unwrap();

        let keys = barrier.list("").await.unwrap();
        assert_eq!(keys.len(), 3);

        let get = barrier.get("bar").await.unwrap().unwrap();
        assert_eq!(get.value, entry1.value);

        let keys = barrier.list("bar/").await.unwrap();
        assert_eq!(keys.len(), 2);

        barrier.delete("bar").await.unwrap();
        assert!(barrier.get("bar").await.unwrap().is_none());
    }

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_barrier_chacha20poly1305_pq_init_unseal() {
        use bv_crypto::{KemProvider, MlKem768Provider};

        let backend = new_test_backend("test_barrier_chacha20poly1305_pq_init_unseal");
        let barrier = ChaCha20Poly1305Barrier::new(backend.clone());
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();

        barrier.init_with_pq(keypair.public_key()).await.unwrap();
        assert!(barrier.sealed().unwrap());
        barrier.unseal_with_pq(keypair.secret_key()).await.unwrap();
        assert!(!barrier.sealed().unwrap());

        let entry = StorageEntry { key: "pq/bar".to_string(), value: b"payload".to_vec() };
        barrier.put(&entry).await.unwrap();
        let get = barrier.get("pq/bar").await.unwrap().unwrap();
        assert_eq!(get.value, entry.value);
    }
}
