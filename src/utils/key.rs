use better_default::Default;
use bv_crypto::{
    KemDemEnvelopeV1, MlDsa65Provider, MlKem768Provider, ML_DSA_65_SEED_LEN, ML_KEM_768_SEED_LEN,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{errors::RvError, utils::generate_uuid};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyBundle {
    #[default(generate_uuid())]
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub key: Vec<u8>,
    //for aes-gcm | aes-cbc
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
        "aes-gcm" | "aes-cbc" | "aes-ecb" => 256,
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

pub fn is_symmetric_key_type(key_type: &str) -> bool {
    matches!(key_type, "aes-gcm" | "aes-cbc" | "aes-ecb")
}

pub fn is_envelope_key_type(key_type: &str) -> bool {
    is_pq_key_type(key_type) || is_symmetric_key_type(key_type)
}

pub fn symmetric_key_uses_iv(key_type: &str) -> bool {
    matches!(key_type, "aes-gcm" | "aes-cbc")
}

fn validate_key_bits(key_type: &str, bits: u32) -> Result<(), RvError> {
    match (key_type, bits) {
        ("ml-kem-768", 768) => Ok(()),
        ("ml-dsa-65", 65) => Ok(()),
        ("aes-gcm", 128 | 192 | 256) => Ok(()),
        ("aes-cbc", 128 | 192 | 256) => Ok(()),
        ("aes-ecb", 128 | 192 | 256) => Ok(()),
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
        if !is_pq_key_type(self.key_type.as_str()) && !is_symmetric_key_type(self.key_type.as_str()) {
            return Err(RvError::ErrPkiKeyTypeInvalid);
        }

        validate_key_bits(self.key_type.as_str(), self.bits)?;

        if is_symmetric_key_type(self.key_type.as_str()) {
            self.bits = 256;
            self.iv = vec![0u8; 16];
            OsRng.fill_bytes(&mut self.iv);
        } else {
            self.iv.clear();
        }

        let seed_len = if is_pq_signature_key_type(self.key_type.as_str()) {
            ML_DSA_65_SEED_LEN
        } else {
            ML_KEM_768_SEED_LEN
        };
        self.key = vec![0u8; seed_len];
        OsRng.fill_bytes(&mut self.key);

        Ok(())
    }

    pub fn import_pem(&mut self, _pem_bundle: &[u8]) -> Result<(), RvError> {
        Err(RvError::ErrPkiKeyTypeInvalid)
    }

    pub fn import_symmetric_seed(&mut self, seed: &[u8], iv: Option<Vec<u8>>) -> Result<(), RvError> {
        if !is_envelope_key_type(self.key_type.as_str()) {
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
            _ => 256,
        };

        if symmetric_key_uses_iv(self.key_type.as_str()) {
            self.iv = iv.ok_or(RvError::ErrRequestFieldNotFound)?;
        } else {
            self.iv.clear();
        }

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
            key_type if is_pq_kem_key_type(key_type) || is_symmetric_key_type(key_type) => {
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
            key_type if is_pq_kem_key_type(key_type) || is_symmetric_key_type(key_type) => {
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
    fn test_aes_key_operation() {
        // test aes-gcm
        let mut key_bundle = KeyBundle::new("aes-gcm-128", "aes-gcm", 128);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Aad("bastion_vault".as_bytes())));
        let mut key_bundle = KeyBundle::new("aes-gcm-192", "aes-gcm", 192);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Aad("bastion_vault".as_bytes())));
        let mut key_bundle = KeyBundle::new("aes-gcm-256", "aes-gcm", 256);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Aad("bastion_vault".as_bytes())));
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Aad("bastion_vault".as_bytes())));

        // test aes-cbc
        let mut key_bundle = KeyBundle::new("aes-cbc-128", "aes-cbc", 128);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-cbc-192", "aes-cbc", 192);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-cbc-256", "aes-cbc", 256);
        test_key_encrypt_decrypt(&mut key_bundle, None);

        // test aes-ecb
        let mut key_bundle = KeyBundle::new("aes-ecb-128", "aes-ecb", 128);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-ecb-192", "aes-ecb", 192);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        let mut key_bundle = KeyBundle::new("aes-ecb-256", "aes-ecb", 256);
        test_key_encrypt_decrypt(&mut key_bundle, None);

        assert!(key_bundle.sign(b"123456789").is_err());
        assert!(key_bundle.verify(b"123456789", b"signature").is_err());
    }

}
