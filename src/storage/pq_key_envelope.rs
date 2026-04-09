//! Versioned storage-facing wrapper for post-quantum key envelopes.
//!
//! This keeps serialization concerns in the storage layer while delegating the
//! actual KEM+DEM cryptography to `crates/bv_crypto`.

use bv_crypto::{KemDemEnvelopeV1, MlKem768Provider};
use serde::{Deserialize, Serialize};

use crate::errors::RvError;

pub const PQ_KEY_ENVELOPE_VERSION_1: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostQuantumKeyEnvelope {
    pub version: u8,
    pub envelope: KemDemEnvelopeV1,
}

impl PostQuantumKeyEnvelope {
    pub fn seal_ml_kem_768(public_key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Self, RvError> {
        let provider = MlKem768Provider;
        let envelope = KemDemEnvelopeV1::seal(&provider, public_key, aad, plaintext).map_err(map_crypto_error)?;
        Ok(Self { version: PQ_KEY_ENVELOPE_VERSION_1, envelope })
    }

    pub fn open_ml_kem_768(&self, secret_key: &[u8], aad: &[u8]) -> Result<Vec<u8>, RvError> {
        if self.version != PQ_KEY_ENVELOPE_VERSION_1 {
            return Err(RvError::ErrBarrierVersionMismatch);
        }

        let provider = MlKem768Provider;
        self.envelope.open(&provider, secret_key, aad).map_err(map_crypto_error)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RvError> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, RvError> {
        Ok(serde_json::from_slice(encoded)?)
    }
}

fn map_crypto_error(_err: bv_crypto::CryptoError) -> RvError {
    RvError::ErrBarrierKeyInvalid
}

#[cfg(test)]
mod tests {
    use bv_crypto::{KemProvider, MlKem768Provider};

    use super::*;

    #[test]
    fn pq_key_envelope_round_trip() {
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();
        let aad = b"storage:pq-key-envelope:path=core/barrier-key";
        let plaintext = b"wrapped barrier key material";

        let encoded =
            PostQuantumKeyEnvelope::seal_ml_kem_768(keypair.public_key(), aad, plaintext).unwrap().encode().unwrap();
        let decoded = PostQuantumKeyEnvelope::decode(&encoded).unwrap();
        let decrypted = decoded.open_ml_kem_768(keypair.secret_key(), aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn pq_key_envelope_rejects_wrong_aad() {
        let provider = MlKem768Provider;
        let keypair = provider.generate_keypair().unwrap();
        let envelope =
            PostQuantumKeyEnvelope::seal_ml_kem_768(keypair.public_key(), b"aad:v1", b"barrier-key").unwrap();

        let err = envelope.open_ml_kem_768(keypair.secret_key(), b"aad:v2").unwrap_err();
        assert_eq!(err, RvError::ErrBarrierKeyInvalid);
    }
}
