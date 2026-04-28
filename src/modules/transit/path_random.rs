//! `/v1/transit/random` and `/v1/transit/hash`.
//!
//! Random-bytes passthrough (CSPRNG via `OsRng`) and hash
//! passthrough (SHA2-256 / 384 / 512). Cheap utility endpoints that
//! save callers from having to ship their own crypto when they're
//! already authenticated to the engine.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngExt;
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{hash, HashAlgo},
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const RANDOM_HELP: &str = "Return base64-encoded CSPRNG bytes. `bytes` defaults to 32; capped at 4096.";
const HASH_HELP: &str = "Hash a base64 input under SHA2-{256,384,512}.";

const RANDOM_MAX_BYTES: u64 = 4096;

impl TransitBackend {
    pub fn random_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"random",
            fields: {
                "bytes": { field_type: FieldType::Int, default: 32, description: "Number of bytes to return." }
            },
            operations: [{op: Operation::Write, handler: h.handle_random}],
            help: RANDOM_HELP
        })
    }

    pub fn hash_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"hash",
            fields: {
                "input":     { field_type: FieldType::Str, default: "", description: "Base64-encoded input." },
                "algorithm": { field_type: FieldType::Str, default: "sha2-256", description: "sha2-256, sha2-384, or sha2-512." }
            },
            operations: [{op: Operation::Write, handler: h.handle_hash}],
            help: HASH_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub async fn handle_random(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let n = req
            .get_data("bytes")
            .ok()
            .and_then(|v| v.as_i64())
            .filter(|n| *n > 0)
            .map(|n| n as u64)
            .unwrap_or(32);
        if n > RANDOM_MAX_BYTES {
            return Err(RvError::ErrString(format!(
                "bytes capped at {RANDOM_MAX_BYTES}, got {n}"
            )));
        }
        let mut buf = vec![0u8; n as usize];
        rand::rng().fill(&mut buf[..]);
        let mut data = Map::new();
        data.insert("random_bytes".into(), Value::String(B64.encode(&buf)));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_hash(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let input_b64 = req
            .get_data("input")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let algo = req
            .get_data("algorithm")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let algo = HashAlgo::parse(&algo).map_err(RvError::ErrString)?;
        let input = B64
            .decode(input_b64.as_bytes())
            .map_err(|e| RvError::ErrString(format!("input: not base64 ({e})")))?;
        let digest = hash(algo, &input);
        let mut data = Map::new();
        data.insert("sum".into(), Value::String(B64.encode(&digest)));
        Ok(Some(Response::data_response(Some(data))))
    }
}
