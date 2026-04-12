use better_default::Default;
use bv_crypto::{
    KemDemEnvelopeV1, MlDsa65Provider, MlKem768Provider, ML_DSA_65_SEED_LEN, ML_KEM_768_SEED_LEN,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{errors::RvError, utils::generate_uuid};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyBundle {
    #[default(generate_uuid())]
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub bits: u32,
}

#[derive(Debug, Clone)]
pub enum EncryptExtraData<'a> {
    Aad(&'a [u8]),
    Flag(bool),
}

fn key_bits_default(key_type: &str) -> u32 {
    match key_type {
        "ml-kem-768" => 768,
        "ml-dsa-65" => 65,
        _ => 0,
    }
}

pub fn is_pq_key_type(key_type: &str) -> bool {
    matches!(key_type, "ml-kem-768" | "ml-dsa-65")
}

pub fn is_pq_kem_key_type(key_type: &str) -> bool {
    matches!(key_type, "ml-kem-768")
}

pub fn is_pq_signature_key_type(key_type: &str) -> bool {
    matches!(key_type, "ml-dsa-65")
}

fn validate_key_bits(key_type: &str, bits: u32) -> Result<(), RvError> {
    match (key_type, bits) {
        ("ml-kem-768", 768) => Ok(()),
        ("ml-dsa-65", 65) => Ok(()),
        _ => Err(RvError::ErrPkiKeyBitsInvalid),
    }
}

fn aad_from_extra<'a>(default_aad: &'a [u8], extra: Option<EncryptExtraData<'a>>) -> &'a [u8] {
    extra.map_or(default_aad, |ex| match ex {
        EncryptExtraData::Aad(aad) => aad,
        _ => default_aad,
    })
}

impl KeyBundle {
    pub fn new(name: &str, key_type: &str, key_bits: u32) -> Self {
        let bits = if key_bits == 0 { key_bits_default(key_type) } else { key_bits };
        Self { name: name.to_string(), key_type: key_type.to_string(), bits, ..KeyBundle::default() }
    }

    pub fn generate(&mut self) -> Result<(), RvError> {
        if !is_pq_key_type(self.key_type.as_str()) {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }

        validate_key_bits(self.key_type.as_str(), self.bits)?;
        self.iv.clear();

        let seed_len = if is_pq_signature_key_type(self.key_type.as_str()) {
            ML_DSA_65_SEED_LEN
        } else {
            ML_KEM_768_SEED_LEN
        };
        self.key = vec![0u8; seed_len];
        rand::rng().fill_bytes(&mut self.key);

        Ok(())
    }

    pub fn import_pem(&mut self, _pem_bundle: &[u8]) -> Result<(), RvError> {
        Err(RvError::ErrPkiKeyTypeInvalid)
    }

    pub fn import_pq_seed(&mut self, seed: &[u8]) -> Result<(), RvError> {
        if !is_pq_key_type(self.key_type.as_str()) {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }

        let expected_len = if is_pq_signature_key_type(self.key_type.as_str()) {
            ML_DSA_65_SEED_LEN
        } else {
            ML_KEM_768_SEED_LEN
        };

        if seed.len() != expected_len {
            return Err(RvError::ErrPkiKeyBitsInvalid);
        }

        self.key = seed.to_vec();
        self.bits = match self.key_type.as_str() {
            "ml-kem-768" => 768,
            "ml-dsa-65" => 65,
            _ => 0,
        };
        self.iv.clear();

        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RvError> {
        if !is_pq_signature_key_type(self.key_type.as_str()) {
            return Err(RvError::ErrPkiKeyOperationInvalid);
        }

        let provider = MlDsa65Provider;
        provider.sign(&self.key, data, &[]).map_err(|_| RvError::ErrPkiInternal)
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, RvError> {
        if !is_pq_signature_key_type(self.key_type.as_str()) {
            return Err(RvError::ErrPkiKeyOperationInvalid);
        }

        let provider = MlDsa65Provider;
        match provider.verify(&self.key, data, signature, &[]) {
            Ok(result) => Ok(result),
            Err(_) => Ok(false),
        }
    }

    pub fn encrypt(&self, data: &[u8], extra: Option<EncryptExtraData>) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            key_type if is_pq_kem_key_type(key_type) => {
                validate_key_bits(self.key_type.as_str(), self.bits)?;
                let aad = aad_from_extra(self.iv.as_slice(), extra);
                let provider = MlKem768Provider;
                let keypair =
                    provider.keypair_from_seed(&self.key).map_err(|_| RvError::ErrPkiInternal)?;
                let envelope =
                    KemDemEnvelopeV1::seal(&provider, keypair.public_key(), aad, data).map_err(|_| RvError::ErrPkiInternal)?;
                serde_json::to_vec(&envelope).map_err(From::from)
            }
            _ => Err(RvError::ErrPkiKeyOperationInvalid),
        }
    }

    pub fn decrypt(&self, data: &[u8], extra: Option<EncryptExtraData>) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            key_type if is_pq_kem_key_type(key_type) => {
                validate_key_bits(self.key_type.as_str(), self.bits)?;
                let aad = aad_from_extra(self.iv.as_slice(), extra);
                let envelope: KemDemEnvelopeV1 = serde_json::from_slice(data)?;
                let provider = MlKem768Provider;
                let keypair =
                    provider.keypair_from_seed(&self.key).map_err(|_| RvError::ErrPkiInternal)?;
                envelope.open(&provider, keypair.secret_key(), aad).map_err(|_| RvError::ErrPkiInternal)
            }
            _ => Err(RvError::ErrPkiKeyOperationInvalid),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_key_encrypt_decrypt(key_bundle: &mut KeyBundle, extra: Option<EncryptExtraData>) {
        assert!(key_bundle.generate().is_ok());
        let data = "123456789";
        let result = key_bundle.encrypt(data.as_bytes(), extra.clone());
        assert!(result.is_ok());
        let encrypted_data = result.unwrap();
        let result = key_bundle.decrypt(&encrypted_data, extra);
        assert!(result.is_ok());
        let decrypted_data = result.unwrap();
        assert_eq!(std::str::from_utf8(&decrypted_data).unwrap(), data);
    }

    #[test]
    fn test_ml_kem_key_operation() {
        let mut key_bundle = KeyBundle::new("ml-kem-768", "ml-kem-768", 768);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Aad("bastion_vault".as_bytes())));
    }

    #[test]
    fn test_ml_dsa_key_operation() {
        let mut key_bundle = KeyBundle::new("ml-dsa-65", "ml-dsa-65", 65);
        assert!(key_bundle.generate().is_ok());
        let data = b"123456789";
        let signature = key_bundle.sign(data).unwrap();
        assert!(signature.len() > data.len());
        assert!(key_bundle.verify(data, &signature).unwrap());
        assert!(!key_bundle.verify(b"bad", &signature).unwrap());
        assert!(key_bundle.encrypt(data, None).is_err());
        assert!(key_bundle.decrypt(&signature, None).is_err());
    }

    #[test]
    fn test_non_kem_and_non_signature_operations_fail() {
        let mut key_bundle = KeyBundle::new("ml-dsa-65", "ml-dsa-65", 65);
        assert!(key_bundle.generate().is_ok());
        assert!(key_bundle.encrypt(b"123456789", None).is_err());
        assert!(key_bundle.decrypt(b"payload", None).is_err());

        let mut key_bundle = KeyBundle::new("ml-kem-768", "ml-kem-768", 768);
        assert!(key_bundle.generate().is_ok());
        assert!(key_bundle.sign(b"123456789").is_err());
        assert!(key_bundle.verify(b"123456789", b"signature").is_err());
    }

}
