//! Argon2id wrapper for password-based key derivation.
//!
//! Defaults match the OWASP 2024 cheat-sheet recommendation:
//! `m_cost = 65536 KiB` (64 MiB), `t_cost = 3`, `p_cost = 1`.
//! These target ~1 second on a modern desktop. KDF parameters are embedded
//! in the `.bvx` envelope so future tuning is forward-compatible.

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::errors::RvError;

pub const KDF_ALG_ARGON2ID: &str = "argon2id";
pub const ARGON2_SALT_LEN: usize = 16;
pub const DERIVED_KEY_LEN: usize = 32;

pub const DEFAULT_M_COST_KIB: u32 = 65536;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;

// Sanity bounds. Below the floor weakens security; above the ceiling lets
// a malicious file weaponize the importer into a memory-exhaustion DoS.
const MIN_M_COST_KIB: u32 = 16_384;
const MAX_M_COST_KIB: u32 = 1_048_576;
const MIN_T_COST: u32 = 2;
const MAX_T_COST: u32 = 100;
const MIN_P_COST: u32 = 1;
const MAX_P_COST: u32 = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub alg: String,
    pub version: u32,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_b64: String,
}

impl KdfParams {
    /// Build a fresh parameter block with a random salt and the documented
    /// default costs.
    pub fn fresh_default() -> Self {
        use base64::Engine;
        use rand::Rng;
        let mut salt = [0u8; ARGON2_SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        Self {
            alg: KDF_ALG_ARGON2ID.to_string(),
            version: Version::V0x13 as u32,
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
            salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        }
    }

    fn validate(&self) -> Result<(), RvError> {
        if self.alg != KDF_ALG_ARGON2ID {
            return Err(RvError::ErrRequestInvalid);
        }
        if self.version != Version::V0x13 as u32 {
            return Err(RvError::ErrRequestInvalid);
        }
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib)
            || !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost)
            || !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost)
        {
            return Err(RvError::ErrRequestInvalid);
        }
        Ok(())
    }

    fn salt_bytes(&self) -> Result<Vec<u8>, RvError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(self.salt_b64.as_bytes())
            .map_err(|_| RvError::ErrRequestInvalid)
    }
}

/// Derive a 32-byte key from a password using Argon2id with the given
/// parameters. The returned buffer is `Zeroize`-able by the caller.
pub fn derive_key(password: &str, params: &KdfParams) -> Result<[u8; DERIVED_KEY_LEN], RvError> {
    params.validate()?;

    let salt = params.salt_bytes()?;
    let argon_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(DERIVED_KEY_LEN))
        .map_err(|_| RvError::ErrRequestInvalid)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; DERIVED_KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|_| {
            // Don't leak distinguishable failure reasons to the caller.
            let mut tmp = out;
            tmp.zeroize();
            RvError::ErrRequestInvalid
        })?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // Speed up tests; still inside the validate() bounds.
        let mut p = KdfParams::fresh_default();
        p.m_cost_kib = MIN_M_COST_KIB;
        p.t_cost = MIN_T_COST;
        p.p_cost = MIN_P_COST;
        p
    }

    #[test]
    fn deterministic_derivation() {
        let p = fast_params();
        let a = derive_key("hunter2-but-stronger", &p).unwrap();
        let b = derive_key("hunter2-but-stronger", &p).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_password_yields_different_key() {
        let p = fast_params();
        let a = derive_key("password-one", &p).unwrap();
        let b = derive_key("password-two", &p).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_weak_parameters() {
        let mut p = fast_params();
        p.m_cost_kib = 1024;
        assert!(derive_key("x", &p).is_err());

        let mut p = fast_params();
        p.t_cost = 1;
        assert!(derive_key("x", &p).is_err());
    }

    #[test]
    fn rejects_dos_parameters() {
        let mut p = fast_params();
        p.m_cost_kib = u32::MAX;
        assert!(derive_key("x", &p).is_err());

        let mut p = fast_params();
        p.t_cost = 10_000;
        assert!(derive_key("x", &p).is_err());
    }
}
