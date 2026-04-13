//! This module is a Rust replica of
//! <https://github.com/hashicorp/vault/blob/main/sdk/helper/salt/salt.go>

use better_default::Default;
use derivative::Derivative;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::generate_uuid;
use crate::{
    errors::RvError,
    storage::{Storage, StorageEntry},
};

static DEFAULT_LOCATION: &str = "salt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestAlgorithm {
    Sha1,
    #[default]
    Sha256,
}

impl DigestAlgorithm {
    fn hmac_label(self) -> &'static str {
        match self {
            Self::Sha1 => "hmac-sha1",
            Self::Sha256 => "hmac-sha256",
        }
    }

    #[cfg(test)]
    fn output_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Salt {
    pub config: Config,
    #[default(generate_uuid())]
    pub salt: String,
    #[default(true)]
    pub generated: bool,
}

#[derive(Derivative, Default)]
#[derivative(Debug, Clone)]
pub struct Config {
    #[default(DEFAULT_LOCATION.to_string())]
    pub location: String,
    #[derivative(Debug = "ignore")]
    #[default(DigestAlgorithm::Sha256)]
    pub hash_type: DigestAlgorithm,
    #[derivative(Debug = "ignore")]
    #[default(DigestAlgorithm::Sha256)]
    pub hmac_type: DigestAlgorithm,
}

#[maybe_async::maybe_async]
impl Salt {
    pub async fn new(storage: Option<&dyn Storage>, config: Option<&Config>) -> Result<Self, RvError> {
        let mut salt = Salt::default();
        if let Some(c) = config {
            if salt.config.location != c.location && !c.location.is_empty() {
                salt.config.location.clone_from(&c.location);
            }

            if salt.config.hash_type != c.hash_type {
                salt.config.hash_type = c.hash_type;
            }

            if salt.config.hmac_type != c.hmac_type {
                salt.config.hmac_type = c.hmac_type;
            }
        }

        if let Some(s) = storage {
            if let Some(raw) = s.get(&salt.config.location).await? {
                salt.salt = String::from_utf8_lossy(&raw.value).to_string();
                salt.generated = false;
            } else {
                let entry = StorageEntry { key: salt.config.location.clone(), value: salt.salt.as_bytes().to_vec() };

                s.put(&entry).await?;
            }
        }

        Ok(salt)
    }

    pub fn new_nonpersistent() -> Self {
        let mut salt = Salt::default();
        salt.config.location = "".to_string();
        salt
    }

    pub fn get_hmac(&self, data: &str) -> Result<String, RvError> {
        match self.config.hmac_type {
            DigestAlgorithm::Sha1 => {
                let mut mac = Hmac::<sha1::Sha1>::new_from_slice(self.salt.as_bytes())
                    .map_err(|_| RvError::ErrResponse("invalid hmac key".to_string()))?;
                mac.update(data.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
            DigestAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.salt.as_bytes())
                    .map_err(|_| RvError::ErrResponse("invalid hmac key".to_string()))?;
                mac.update(data.as_bytes());
                Ok(hex::encode(mac.finalize().into_bytes()))
            }
        }
    }

    pub fn get_identified_hamc(&self, data: &str) -> Result<String, RvError> {
        let hmac = self.get_hmac(data)?;
        Ok(format!("{}:{hmac}", self.config.hmac_type.hmac_label()))
    }

    pub fn get_hash(&self, data: &str) -> Result<String, RvError> {
        match self.config.hash_type {
            DigestAlgorithm::Sha1 => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(data.as_bytes());
                Ok(hex::encode(hasher.finalize()))
            }
            DigestAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data.as_bytes());
                Ok(hex::encode(hasher.finalize()))
            }
        }
    }

    pub fn salt_id(&self, id: &str) -> Result<String, RvError> {
        let comb = format!("{}{}", self.salt, id);
        self.get_hash(&comb)
    }

    pub fn did_generate(&self) -> bool {
        self.generated
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rand::Rng;

    use super::*;
    use crate::{
        storage::{barrier::SecurityBarrier, barrier_aes_gcm, barrier_view},
        test_utils::new_test_backend,
    };

    #[maybe_async::test(feature = "sync_handler", async(all(not(feature = "sync_handler")), tokio::test))]
    async fn test_salt() {
        // init the storage backend
        let backend = new_test_backend("test_salt");

        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(key.as_mut_slice());
        let aes_gcm_view = barrier_aes_gcm::AESGCMBarrier::new(backend);

        let init = aes_gcm_view.init(key.as_slice()).await;
        assert!(init.is_ok());

        let result = aes_gcm_view.unseal(key.as_slice()).await;
        assert!(result.is_ok());

        let view = barrier_view::BarrierView::new(Arc::new(aes_gcm_view), "test");

        //test salt
        let salt = Salt::new(Some(&view), None).await;
        assert!(salt.is_ok());

        let salt = salt.unwrap();
        assert!(salt.did_generate());

        let ss = view.get(DEFAULT_LOCATION).await;
        assert!(ss.is_ok());
        assert!(ss.unwrap().is_some());

        let salt2 = Salt::new(Some(&view), Some(&salt.config)).await;
        assert!(salt2.is_ok());

        let salt2 = salt2.unwrap();
        assert!(!salt2.did_generate());

        assert_eq!(salt.salt, salt2.salt);

        let id = "foobarbaz";
        let sid1 = salt.salt_id(id);
        let sid2 = salt2.salt_id(id);
        assert!(sid1.is_ok());
        assert!(sid2.is_ok());

        let sid1 = sid1.unwrap();
        let sid2 = sid2.unwrap();
        assert_eq!(sid1, sid2);
        assert_eq!(sid1.len(), salt.config.hash_type.output_size() * 2);
    }
}
