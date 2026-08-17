//! `/v1/totp/keys` LIST and `/v1/totp/keys/:name` CRUD.
//!
//! Generate-mode and provider-mode share this handler — the discriminator
//! is the request body's `generate` flag.

use std::{collections::HashMap, sync::Arc};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    barcode::render_png_b64,
    crypto::otpauth::{build_url, encode_secret, parse_url, ParsedOtpAuth},
    policy::{
        Algorithm, KeyPolicy, DEFAULT_DIGITS, DEFAULT_KEY_SIZE, DEFAULT_PERIOD, DEFAULT_QR_SIZE,
        DEFAULT_SKEW,
    },
    TotpBackend, TotpBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const KEYS_HELP: &str = r#"
Manage TOTP keys. POST creates either a generated key (engine picks
the seed and returns a one-shot QR-encoded `otpauth://` URL) or a
provider key (operator imports an existing seed). GET returns
metadata; the seed is never re-disclosed after the create response.
"#;

const KEYS_LIST_HELP: &str = "List configured TOTP key names.";

impl TotpBackend {
    pub fn keys_path(&self) -> Path {
        let read_handler = self.inner.clone();
        let write_handler = self.inner.clone();
        let delete_handler = self.inner.clone();

        new_path!({
            pattern: r"keys/(?P<name>\w[\w-]*\w)",
            fields: {
                "name": { field_type: FieldType::Str, required: true, description: "Key name." },
                "generate": { field_type: FieldType::Bool, default: false, description: "If true, the engine generates the seed (generate mode). If false, the operator must supply `key` or `url` (provider mode)." },
                "key": { field_type: FieldType::Str, default: "", description: "Provider mode: base32-encoded seed (RFC 4648, padding optional)." },
                "url": { field_type: FieldType::Str, default: "", description: "Provider mode alternative: full `otpauth://totp/...` URL." },
                "key_size": { field_type: FieldType::Int, default: 20, description: "Generate mode: random seed size in bytes." },
                "issuer": { field_type: FieldType::Str, default: "", description: "Issuer for the otpauth URL." },
                "account_name": { field_type: FieldType::Str, default: "", description: "Account name for the otpauth URL." },
                "algorithm": { field_type: FieldType::Str, default: "SHA1", description: "Hash algorithm: SHA1 (default), SHA256, or SHA512." },
                "digits": { field_type: FieldType::Int, default: 6, description: "6 (default) or 8." },
                "period": { field_type: FieldType::Int, default: 30, description: "Step in seconds." },
                "skew": { field_type: FieldType::Int, default: 1, description: "Number of preceding/following steps accepted on validate." },
                "qr_size": { field_type: FieldType::Int, default: 200, description: "Pixel size of the returned PNG QR. 0 disables PNG rendering." },
                "exported": { field_type: FieldType::Bool, default: true, description: "Generate mode: include the seed in the create response. Always false for provider mode." },
                "replay_check": { field_type: FieldType::Bool, default: true, description: "Refuse a second validation of the same step+code. Disable for strict HashiCorp Vault parity." }
            },
            operations: [
                {op: Operation::Read, handler: read_handler.handle_key_read},
                {op: Operation::Write, handler: write_handler.handle_key_write},
                {op: Operation::Delete, handler: delete_handler.handle_key_delete}
            ],
            help: KEYS_HELP
        })
    }

    pub fn keys_list_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"keys/?$",
            operations: [
                {op: Operation::List, handler: h.handle_keys_list}
            ],
            help: KEYS_LIST_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl TotpBackendInner {
    pub async fn handle_key_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        match self.get_key(req, &name).await? {
            Some(p) => {
                // Metadata only — seed never reappears here.
                let mut data = Map::new();
                data.insert("generate".into(), Value::Bool(p.generate));
                data.insert("issuer".into(), Value::String(p.issuer));
                data.insert("account_name".into(), Value::String(p.account_name));
                data.insert("algorithm".into(), Value::String(p.algorithm.as_str().into()));
                data.insert("digits".into(), Value::Number(p.digits.into()));
                data.insert("period".into(), Value::Number(p.period.into()));
                data.insert("skew".into(), Value::Number(p.skew.into()));
                data.insert("replay_check".into(), Value::Bool(p.replay_check));
                Ok(Some(Response::data_response(Some(data))))
            }
            None => Ok(None),
        }
    }

    pub async fn handle_key_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();

        let generate = req
            .get_data("generate")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let issuer = take_str(req, "issuer");
        let account_name = take_str(req, "account_name");
        let algorithm_str = take_str(req, "algorithm");
        let algorithm = if algorithm_str.is_empty() {
            Algorithm::Sha1
        } else {
            Algorithm::parse(&algorithm_str).map_err(RvError::ErrString)?
        };

        let digits = take_int(req, "digits", DEFAULT_DIGITS as i64) as u32;
        let period = take_int(req, "period", DEFAULT_PERIOD as i64) as u64;
        let skew = take_int(req, "skew", DEFAULT_SKEW as i64) as u32;
        let qr_size = take_int(req, "qr_size", DEFAULT_QR_SIZE as i64) as u32;
        let exported = req
            .get_data("exported")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let replay_check = req
            .get_data("replay_check")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let key_in = take_str(req, "key");
        let url_in = take_str(req, "url");

        // The two provider-mode inputs are mutually exclusive — accepting
        // both would force a precedence rule that surprises operators
        // when the URL's parameters disagree with the discrete fields.
        if !key_in.is_empty() && !url_in.is_empty() {
            return Err(RvError::ErrString(
                "`key` and `url` are mutually exclusive; supply one or the other".into(),
            ));
        }

        let policy = if generate {
            if !key_in.is_empty() || !url_in.is_empty() {
                return Err(RvError::ErrString(
                    "generate=true forbids `key` and `url`; the engine picks the seed".into(),
                ));
            }
            let key_size = take_int(req, "key_size", DEFAULT_KEY_SIZE as i64) as usize;
            if !(10..=128).contains(&key_size) {
                return Err(RvError::ErrString(format!(
                    "key_size must be in 10..=128 bytes, got {key_size}"
                )));
            }
            if account_name.is_empty() {
                return Err(RvError::ErrString(
                    "account_name is required when generate=true".into(),
                ));
            }
            let mut bytes = vec![0u8; key_size];
            use rand::RngExt;
            rand::rng().fill(&mut bytes[..]);
            KeyPolicy {
                generate: true,
                key: bytes,
                issuer,
                account_name,
                algorithm,
                digits,
                period,
                skew,
                replay_check,
                exported,
            }
        } else {
            // Provider mode. Either `url` (parsed) or `key` (decoded).
            let mut p = if !url_in.is_empty() {
                let parsed: ParsedOtpAuth = parse_url(&url_in).map_err(RvError::ErrString)?;
                KeyPolicy {
                    generate: false,
                    key: parsed.key,
                    // Discrete fields override URL fields when the
                    // operator supplied both — they're explicit input.
                    issuer: if !issuer.is_empty() { issuer } else { parsed.issuer },
                    account_name: if !account_name.is_empty() {
                        account_name
                    } else {
                        parsed.account_name
                    },
                    algorithm: if algorithm_str.is_empty() {
                        parsed.algorithm
                    } else {
                        algorithm
                    },
                    digits: if take_int(req, "digits", -1) >= 0 {
                        digits
                    } else {
                        parsed.digits
                    },
                    period: if take_int(req, "period", -1) >= 0 {
                        period
                    } else {
                        parsed.period
                    },
                    skew,
                    replay_check,
                    // Provider-mode keys never re-export the seed —
                    // the operator already has it, and a second
                    // disclosure path is just attack surface.
                    exported: false,
                }
            } else if !key_in.is_empty() {
                let key_bytes = super::crypto::otpauth::decode_secret(&key_in)
                    .map_err(RvError::ErrString)?;
                KeyPolicy {
                    generate: false,
                    key: key_bytes,
                    issuer,
                    account_name,
                    algorithm,
                    digits,
                    period,
                    skew,
                    replay_check,
                    exported: false,
                }
            } else {
                return Err(RvError::ErrString(
                    "provider mode requires `key` or `url`".into(),
                ));
            };
            // Account name is what authenticator apps display; refuse
            // an empty one rather than write a key the user can't tell
            // apart from any other.
            if p.account_name.is_empty() {
                return Err(RvError::ErrString(
                    "account_name is required (or pass it via the otpauth url path label)".into(),
                ));
            }
            p.exported = false;
            p
        };

        policy.validate().map_err(RvError::ErrString)?;

        // Build the otpauth URL and (optionally) the QR before
        // persisting so a render failure aborts the create cleanly
        // rather than leaving a key the GUI can't enroll.
        let url = build_url(&policy);
        let barcode = if policy.generate && policy.exported && qr_size > 0 {
            Some(render_png_b64(&url, qr_size)?)
        } else {
            None
        };

        self.put_key(req, &name, &policy).await?;

        // Generate-mode + exported = one-shot disclosure response.
        // Provider-mode and exported=false return only metadata.
        let mut data = Map::new();
        if policy.generate && policy.exported {
            data.insert("key".into(), Value::String(encode_secret(&policy.key)));
            data.insert("url".into(), Value::String(url));
            if let Some(b) = barcode {
                data.insert("barcode".into(), Value::String(b));
            }
        }
        data.insert("name".into(), Value::String(name));
        data.insert("generate".into(), Value::Bool(policy.generate));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_key_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let name = req
            .get_data("name")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();
        self.delete_key(req, &name).await?;
        Ok(None)
    }

    pub async fn handle_keys_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let keys = self.list_keys(req).await?;
        Ok(Some(Response::list_response(&keys)))
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn take_int(req: &Request, key: &str, default: i64) -> i64 {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_i64())
        .unwrap_or(default)
}
