//! Shared initialization record helpers for the ChaCha20-Poly1305 barrier.

use bv_crypto::{MlKem768Provider, ML_KEM_768_SEED_LEN};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{barrier::BARRIER_INIT_PATH, pq_key_envelope::PostQuantumKeyEnvelope};
use crate::errors::RvError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
#[zeroize(drop)]
pub struct BarrierInitRecord {
    pub version: u32,
    pub key: Vec<u8>,
}

impl BarrierInitRecord {
    pub fn new(key: Vec<u8>) -> Self {
        Self { version: 1, key }
    }

    pub fn encode_direct(&self) -> Result<Vec<u8>, RvError> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode_direct(value: &[u8]) -> Result<Self, RvError> {
        Ok(serde_json::from_slice(value)?)
    }

    pub fn encode_ml_kem_768_from_seed(&self, seed: &[u8]) -> Result<Vec<u8>, RvError> {
        let provider = MlKem768Provider;
        let keypair = provider.keypair_from_seed(seed).map_err(map_crypto_error)?;
        let envelope = PostQuantumKeyEnvelope::seal_ml_kem_768(
            keypair.public_key(),
            BARRIER_INIT_PATH.as_bytes(),
            &self.encode_direct()?,
        )?;
        envelope.encode()
    }

    pub fn decode_ml_kem_768_from_seed(encoded: &[u8], seed: &[u8]) -> Result<Self, RvError> {
        if seed.len() != ML_KEM_768_SEED_LEN {
            return Err(RvError::ErrBarrierKeyInvalid);
        }

        let provider = MlKem768Provider;
        let keypair = provider.keypair_from_seed(seed).map_err(map_crypto_error)?;
        let envelope = PostQuantumKeyEnvelope::decode(encoded)?;
        let record_bytes = envelope.open_ml_kem_768(keypair.secret_key(), BARRIER_INIT_PATH.as_bytes())?;
        Self::decode_direct(&record_bytes)
    }
}

fn map_crypto_error(_err: bv_crypto::CryptoError) -> RvError {
    RvError::ErrBarrierKeyInvalid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_record_round_trip() {
        let record = BarrierInitRecord::new(b"barrier-key".to_vec());
        let encoded = record.encode_direct().unwrap();
        let decoded = BarrierInitRecord::decode_direct(&encoded).unwrap();

        assert_eq!(decoded, record);
    }

    #[test]
    fn pq_record_round_trip() {
        let seed = [9u8; ML_KEM_768_SEED_LEN];
        let record = BarrierInitRecord::new(b"barrier-key".to_vec());

        let encoded = record.encode_ml_kem_768_from_seed(&seed).unwrap();
        let decoded = BarrierInitRecord::decode_ml_kem_768_from_seed(&encoded, &seed).unwrap();

        assert_eq!(decoded, record);
    }
}
