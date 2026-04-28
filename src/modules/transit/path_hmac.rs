//! `/v1/transit/hmac/:name` and `/v1/transit/verify/:name/hmac`.

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    crypto::{ciphertext, ct_eq, hmac, HashAlgo},
    TransitBackend, TransitBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const HMAC_HELP: &str = "Compute HMAC-SHA-{256,384,512} over a base64 message under the latest version of the named key.";
const HMAC_VERIFY_HELP: &str = "Verify a `bvault:vN:<base64>` HMAC against a message. Constant-time comparison.";

impl TransitBackend {
    pub fn hmac_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"hmac/(?P<name>\w[\w-]*\w)",
            fields: {
                "name":      { field_type: FieldType::Str, required: true, description: "Key name." },
                "input":     { field_type: FieldType::Str, default: "", description: "Base64-encoded message." },
                "algorithm": { field_type: FieldType::Str, default: "sha2-256", description: "Hash algorithm." }
            },
            operations: [{op: Operation::Write, handler: h.handle_hmac}],
            help: HMAC_HELP
        })
    }

    pub fn hmac_verify_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"verify/(?P<name>\w[\w-]*\w)/hmac",
            fields: {
                "name":      { field_type: FieldType::Str, required: true, description: "Key name." },
                "input":     { field_type: FieldType::Str, default: "", description: "Base64-encoded message." },
                "hmac":      { field_type: FieldType::Str, default: "", description: "`bvault:vN:<base64>` HMAC." },
                "algorithm": { field_type: FieldType::Str, default: "sha2-256", description: "Hash algorithm used to compute the HMAC." }
            },
            operations: [{op: Operation::Write, handler: h.handle_hmac_verify}],
            help: HMAC_VERIFY_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TransitBackendInner {
    pub async fn handle_hmac(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let input_b64 = take_str(req, "input");
        let algo = HashAlgo::parse(&take_str(req, "algorithm")).map_err(RvError::ErrString)?;
        let input = B64
            .decode(input_b64.as_bytes())
            .map_err(|e| RvError::ErrString(format!("input: not base64 ({e})")))?;

        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        if !p.key_type.supports_hmac() {
            return Err(RvError::ErrString(format!(
                "{} keys do not support /hmac",
                p.key_type.as_str()
            )));
        }
        let v = p.latest().ok_or_else(|| RvError::ErrString("key has no versions".into()))?;
        let mac = hmac(algo, &v.material, &input);
        let wire = ciphertext::build(v.version, None, &mac);
        let mut data = Map::new();
        data.insert("hmac".into(), Value::String(wire));
        data.insert("key_version".into(), Value::Number(v.version.into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_hmac_verify(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = take_str(req, "name");
        let input_b64 = take_str(req, "input");
        let mac_str = take_str(req, "hmac");
        let algo = HashAlgo::parse(&take_str(req, "algorithm")).map_err(RvError::ErrString)?;
        let input = B64
            .decode(input_b64.as_bytes())
            .map_err(|e| RvError::ErrString(format!("input: not base64 ({e})")))?;

        let framed = ciphertext::parse(&mac_str)?;
        if framed.pqc_algo.is_some() {
            return Err(RvError::ErrString(
                "HMAC framing must not carry a pqc tag".into(),
            ));
        }
        let p = self
            .get_policy(req, &name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown key `{name}`")))?;
        let v = p
            .version_for_decrypt(framed.version)
            .map_err(RvError::ErrString)?;
        let expected = hmac(algo, &v.material, &input);
        let mut data = Map::new();
        data.insert("valid".into(), Value::Bool(ct_eq(&expected, &framed.bytes)));
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}
