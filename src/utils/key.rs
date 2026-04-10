use better_default::Default;
use bv_crypto::{KemDemEnvelopeV1, MlKem768Provider, ML_KEM_768_SEED_LEN};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::{Padding, Rsa},
    sign::{Signer, Verifier},
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
        "rsa" => 2048,
        "ec" => 256,
        "aes-gcm" | "aes-cbc" | "aes-ecb" => 256,
        _ => 0,
    }
}

pub fn is_symmetric_key_type(key_type: &str) -> bool {
    matches!(key_type, "aes-gcm" | "aes-cbc" | "aes-ecb")
}

pub fn is_pem_key_type(key_type: &str) -> bool {
    matches!(key_type, "rsa" | "ec")
}

pub fn symmetric_key_uses_iv(key_type: &str) -> bool {
    matches!(key_type, "aes-gcm" | "aes-cbc")
}

fn validate_symmetric_key_bits(key_type: &str, bits: u32) -> Result<(), RvError> {
    match (key_type, bits) {
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
        let key_bits = self.bits;
        let priv_key = match self.key_type.as_str() {
            "rsa" => match key_bits {
                2048 | 3072 | 4096 => {
                    let rsa_key = Rsa::generate(key_bits)?;
                    PKey::from_rsa(rsa_key)?.private_key_to_pem_pkcs8()?
                }
                _ => return Err(RvError::ErrPkiKeyBitsInvalid),
            },
            "ec" => {
                let curve_name = match key_bits {
                    224 => Nid::SECP224R1,
                    256 => Nid::SECP256K1,
                    384 => Nid::SECP384R1,
                    521 => Nid::SECP521R1,
                    _ => return Err(RvError::ErrPkiKeyBitsInvalid),
                };
                let ec_group = EcGroup::from_curve_name(curve_name)?;
                let ec_key = EcKey::generate(&ec_group)?;
                PKey::from_ec_key(ec_key)?.private_key_to_pem_pkcs8()?
            }
            key_type if is_symmetric_key_type(key_type) => {
                validate_symmetric_key_bits(self.key_type.as_str(), self.bits)?;
                self.bits = 256;

                self.iv = vec![0u8; 16];
                OsRng.fill_bytes(&mut self.iv);

                let mut key = vec![0u8; ML_KEM_768_SEED_LEN];
                OsRng.fill_bytes(&mut key);
                key
            }
            _ => return Err(RvError::ErrPkiKeyTypeInvalid),
        };

        self.key = priv_key;

        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, RvError> {
        let digest = match self.key_type.as_str() {
            "rsa" | "ec" => MessageDigest::sha256(),
            _ => return Err(RvError::ErrPkiKeyOperationInvalid),
        };

        let pkey = PKey::private_key_from_pem(&self.key)?;

        let mut signer = Signer::new(digest, &pkey)?;
        if self.key_type == "rsa" {
            signer.set_rsa_padding(Padding::PKCS1)?;
        }

        signer.update(data)?;
        signer.sign_to_vec().map_err(From::from)
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, RvError> {
        let digest = match self.key_type.as_str() {
            "rsa" | "ec" => MessageDigest::sha256(),
            _ => return Err(RvError::ErrPkiKeyOperationInvalid),
        };

        let pkey = PKey::private_key_from_pem(&self.key)?;

        let mut verifier = Verifier::new(digest, &pkey)?;
        if self.key_type == "rsa" {
            verifier.set_rsa_padding(Padding::PKCS1)?;
        }

        verifier.update(data)?;
        Ok(verifier.verify(signature).unwrap_or(false))
    }

    pub fn encrypt(&self, data: &[u8], extra: Option<EncryptExtraData>) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            key_type if is_symmetric_key_type(key_type) => {
                validate_symmetric_key_bits(self.key_type.as_str(), self.bits)?;
                let aad = aad_from_extra(self.iv.as_slice(), extra);
                let provider = MlKem768Provider;
                let keypair =
                    provider.keypair_from_seed(&self.key).map_err(|_| RvError::ErrPkiInternal)?;
                let envelope =
                    KemDemEnvelopeV1::seal(&provider, keypair.public_key(), aad, data).map_err(|_| RvError::ErrPkiInternal)?;
                serde_json::to_vec(&envelope).map_err(From::from)
            }
            "rsa" => {
                let rsa = Rsa::private_key_from_pem(&self.key)?;
                if data.len() > rsa.size() as usize {
                    return Err(RvError::ErrPkiInternal);
                }

                let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

                let flag = extra.map_or(false, |ex| match ex {
                    EncryptExtraData::Flag(flag) => flag,
                    _ => false,
                });
                if !flag {
                    let _ = rsa.private_encrypt(data, &mut buf, Padding::PKCS1)?;
                } else {
                    let _ = rsa.public_encrypt(data, &mut buf, Padding::PKCS1)?;
                }

                Ok(buf)
            }
            _ => Err(RvError::ErrPkiKeyOperationInvalid),
        }
    }

    pub fn decrypt(&self, data: &[u8], extra: Option<EncryptExtraData>) -> Result<Vec<u8>, RvError> {
        match self.key_type.as_str() {
            key_type if is_symmetric_key_type(key_type) => {
                validate_symmetric_key_bits(self.key_type.as_str(), self.bits)?;
                let aad = aad_from_extra(self.iv.as_slice(), extra);
                let envelope: KemDemEnvelopeV1 = serde_json::from_slice(data)?;
                let provider = MlKem768Provider;
                let keypair =
                    provider.keypair_from_seed(&self.key).map_err(|_| RvError::ErrPkiInternal)?;
                envelope.open(&provider, keypair.secret_key(), aad).map_err(|_| RvError::ErrPkiInternal)
            }
            "rsa" => {
                let rsa = Rsa::private_key_from_pem(&self.key)?;
                if data.len() > rsa.size() as usize {
                    return Err(RvError::ErrPkiDataInvalid);
                }

                let mut buf: Vec<u8> = vec![0; rsa.size() as usize];

                let flag = extra.map_or(false, |ex| match ex {
                    EncryptExtraData::Flag(flag) => flag,
                    _ => false,
                });
                if !flag {
                    let rsa_pub_der = rsa.public_key_to_der()?;
                    let rsa_pub = Rsa::public_key_from_der(&rsa_pub_der)?;
                    let _ = rsa_pub.public_decrypt(data, &mut buf, Padding::PKCS1)?;
                } else {
                    let rsa_pri_der = rsa.private_key_to_der()?;
                    let rsa_pri = Rsa::private_key_from_der(&rsa_pri_der)?;
                    let _ = rsa_pri.private_decrypt(data, &mut buf, Padding::PKCS1)?;
                }

                let pos = buf.iter().position(|&x| x == 0).ok_or(RvError::ErrPkiInternal)?;
                buf.truncate(pos);

                Ok(buf)
            }
            _ => Err(RvError::ErrPkiKeyOperationInvalid),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_key_sign_verify(key_bundle: &mut KeyBundle) {
        assert!(key_bundle.generate().is_ok());
        let data = "123456789";
        let signature = key_bundle.sign(data.as_bytes());
        assert!(signature.is_ok());
        assert!(signature.as_ref().unwrap().len() > data.len());
        let verify = key_bundle.verify(data.as_bytes(), signature.as_ref().unwrap());
        assert!(verify.is_ok());
        assert!(verify.unwrap());
    }

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
    fn test_rsa_key_operation() {
        let mut key_bundle = KeyBundle::new("rsa-2048", "rsa", 2048);
        test_key_sign_verify(&mut key_bundle);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Flag(true)));

        let mut key_bundle = KeyBundle::new("rsa-3072", "rsa", 3072);
        test_key_sign_verify(&mut key_bundle);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Flag(true)));

        let mut key_bundle = KeyBundle::new("rsa-4096", "rsa", 4096);
        test_key_sign_verify(&mut key_bundle);
        test_key_encrypt_decrypt(&mut key_bundle, None);
        test_key_encrypt_decrypt(&mut key_bundle, Some(EncryptExtraData::Flag(true)));
    }

    #[test]
    fn test_ec_key_operation() {
        let mut key_bundle = KeyBundle::new("ec-224", "ec", 224);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("ec-256", "ec", 256);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("ec-384", "ec", 384);
        test_key_sign_verify(&mut key_bundle);
        let mut key_bundle = KeyBundle::new("ec-521", "ec", 521);
        test_key_sign_verify(&mut key_bundle);
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
    }

}
