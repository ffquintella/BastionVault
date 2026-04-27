//! `/v1/ssh/sign/:role` — sign an operator-supplied SSH public key
//! into an OpenSSH user/host certificate, gated by the role's policy.
//!
//! Phase 1 surface:
//!
//!   * Algorithm: Ed25519 only (the role's `algorithm_signer` is read
//!     and validated, but generation hard-codes Ed25519).
//!   * `valid_principals` — caller picks a subset of role's
//!     `allowed_users` (or `*` lets through any list); empty caller
//!     list falls back to `default_user`.
//!   * `extensions` / `critical_options` — caller-supplied maps are
//!     filtered against the role whitelist, then merged with the
//!     role's `default_*` maps. Defaults always win on key absence;
//!     caller-supplied overrides win on key collision so a per-call
//!     `force-command` can tighten beyond a default.
//!   * `ttl` — `humantime` parsed; clamped to `max_ttl`.
//!   * `key_id` — literal `{{role}}` substitution today; full
//!     identity templating arrives in Phase 3 next to the PKI engine's
//!     templater. The default `vault-{{role}}-…` keeps cert audit logs
//!     traceable to the issuing role.
//!   * Serial number — fresh `u64` from the OS RNG per cert. Audit
//!     logs surface this so revocation / forensics has a stable
//!     identifier (Phase 2 wires KRL emission).
//!
//! Returned shape mirrors Vault's `signed_key` / `serial_number`
//! contract so existing `vault ssh` clients work unchanged against
//! this engine.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::SystemTime,
};

use humantime::parse_duration;
use rand::RngExt;
#[allow(unused_imports)]
use serde_json::{json, Map, Value};
use ssh_key::{
    certificate::{Builder as CertBuilder, CertType},
    rand_core::OsRng,
    Algorithm, PrivateKey, PublicKey,
};

use super::{SshBackend, SshBackendInner};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
};

const SIGN_HELP: &str = r#"
Sign a client public key into an OpenSSH certificate, constrained by
the named role. Returns `signed_key` (single-line OpenSSH cert) and
`serial_number`. The CA private key never leaves the barrier.
"#;

impl SshBackend {
    pub fn sign_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"sign/(?P<role>\w[\w-]*\w)",
            fields: {
                "role": { field_type: FieldType::Str, required: true, description: "Role name." },
                "public_key": { field_type: FieldType::Str, required: true, description: "OpenSSH-format client public key to sign." },
                "valid_principals": { field_type: FieldType::Str, default: "", description: "Comma-separated subset of `allowed_users`. Empty falls back to role's `default_user`." },
                "ttl": { field_type: FieldType::Str, default: "", description: "Requested validity (e.g. `30m`). Clamped to role's `max_ttl`." },
                "cert_type": { field_type: FieldType::Str, default: "", description: "`user` or `host`; empty inherits role default." },
                "key_id": { field_type: FieldType::Str, default: "", description: "Override for the cert's `key id` field." },
                "extensions": { field_type: FieldType::Map, default: "", description: "Caller-requested extensions. Filtered against role whitelist." },
                "critical_options": { field_type: FieldType::Map, default: "", description: "Caller-requested critical options. Filtered against role whitelist." }
            },
            operations: [
                {op: Operation::Write, handler: h.handle_sign}
            ],
            help: SIGN_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl SshBackendInner {
    pub async fn handle_sign(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        // ── Inputs ──────────────────────────────────────────────────
        let role_name = req
            .get_data("role")?
            .as_str()
            .ok_or(RvError::ErrRequestFieldInvalid)?
            .to_string();

        let public_key_str = req
            .get_data("public_key")?
            .as_str()
            .ok_or_else(|| RvError::ErrString("public_key is required".into()))?
            .to_string();
        if public_key_str.trim().is_empty() {
            return Err(RvError::ErrString("public_key is required".into()));
        }

        let role = self
            .get_role(req, &role_name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown role `{role_name}`")))?;

        // Sign is for CA-mode roles only; OTP roles use /creds.
        if role.key_type != "ca" {
            return Err(RvError::ErrString(format!(
                "role `{role_name}` has key_type `{}`; /sign is for CA-mode roles (use /creds for OTP)",
                role.key_type
            )));
        }

        // ── CA load + PQC dispatch ─────────────────────────────────
        let ca = self
            .load_ca(req)
            .await?
            .ok_or_else(|| RvError::ErrString("ssh CA not configured; POST /config/ca first".into()))?;

        // PQC dispatch: when the persisted CA is ML-DSA-65, the whole
        // sign flow runs through `pqc.rs` (different wire format,
        // different signer). The role's `algorithm_signer` must
        // either be empty (auto-match the CA) or match the CA's
        // algo — we don't synthesise one when the operator was
        // explicit, just refuse the mismatch.
        #[cfg(feature = "ssh_pqc")]
        {
            if ca.algorithm == super::pqc::MLDSA65_ALGO {
                return self.handle_sign_pqc(req, &role, &ca, &public_key_str).await;
            }
        }

        // Classical path requires Ed25519 today (Phase 1 scope). RSA
        // / ECDSA become a small extension to this match later.
        if role.algorithm_signer != "ssh-ed25519" {
            return Err(RvError::ErrString(format!(
                "role `{role_name}` requests algorithm `{}`; only `ssh-ed25519` is supported on classical CAs today",
                role.algorithm_signer
            )));
        }
        if role.pqc_only {
            return Err(RvError::ErrString(
                "role has pqc_only=true but the CA is classical; configure a PQC CA first".into(),
            ));
        }
        let ca_private_key = PrivateKey::from_openssh(ca.private_key_openssh.as_bytes())
            .map_err(|e| RvError::ErrString(format!("CA key load failed: {e}")))?;
        if ca_private_key.algorithm() != Algorithm::Ed25519 {
            return Err(RvError::ErrString(format!(
                "CA key algorithm `{}` not supported on the classical sign path",
                ca_private_key.algorithm().as_str()
            )));
        }

        // ── Client public key ──────────────────────────────────────
        let client_pk = PublicKey::from_openssh(public_key_str.trim())
            .map_err(|e| RvError::ErrString(format!("public_key parse failed: {e}")))?;

        // ── cert_type (request override → role default) ────────────
        let req_cert_type = req
            .get_data("cert_type")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let cert_type_str = if req_cert_type.is_empty() { role.cert_type.clone() } else { req_cert_type };
        let cert_type = match cert_type_str.as_str() {
            "user" => CertType::User,
            "host" => CertType::Host,
            other => {
                return Err(RvError::ErrString(format!(
                    "cert_type must be `user` or `host`, got `{other}`"
                )))
            }
        };

        // ── valid_principals: caller subset, or default_user ───────
        let req_principals = req
            .get_data("valid_principals")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let mut requested: Vec<String> = req_principals
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if requested.is_empty() {
            if !role.default_user.is_empty() {
                requested.push(role.default_user.clone());
            } else {
                return Err(RvError::ErrString(
                    "no valid_principals supplied and role has no default_user".into(),
                ));
            }
        }

        // Allowed-list check. `*` (a single-element list with `"*"`)
        // means any principal is fine — used for break-glass roles
        // where the auth layer above is the real gate.
        let allowed = role.allowed_users_list();
        let allow_any = allowed.iter().any(|u| u == "*");
        if !allow_any {
            // Empty `allowed_users` and no wildcard = nothing the caller
            // can ask for. Surface that loudly rather than letting an
            // operator-typo silently disable the role.
            if allowed.is_empty() {
                return Err(RvError::ErrString(format!(
                    "role `{role_name}` has empty allowed_users; sign refused"
                )));
            }
            for p in &requested {
                if !allowed.iter().any(|a| a == p) {
                    return Err(RvError::ErrString(format!(
                        "principal `{p}` is not in role's allowed_users"
                    )));
                }
            }
        }

        // ── TTL (request → role.ttl), clamped to max_ttl ───────────
        let req_ttl_str = req
            .get_data("ttl")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let req_ttl = if req_ttl_str.trim().is_empty() {
            None
        } else {
            Some(parse_duration(&req_ttl_str).map_err(|e| {
                RvError::ErrString(format!(
                    "ttl: '{req_ttl_str}' is not a valid duration ({e}); use a unit suffix like '30m'"
                ))
            })?)
        };
        let ttl = role.effective_ttl(req_ttl);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| RvError::ErrString(format!("system clock pre-epoch: {e}")))?
            .as_secs();
        // `not_before_duration` backdates `valid_after` so a small
        // skew between the bastion and the target host doesn't reject
        // a freshly-issued cert.
        let valid_after = now.saturating_sub(role.not_before_duration.as_secs());
        let valid_before = now.saturating_add(ttl.as_secs());

        // ── extensions / critical_options merge ────────────────────
        let req_extensions = collect_string_map(req, "extensions");
        let req_options = collect_string_map(req, "critical_options");

        let allowed_ext = role.allowed_extensions_list();
        let allow_any_ext = allowed_ext.iter().any(|e| e == "*");
        let allowed_opt = role.allowed_critical_options_list();
        let allow_any_opt = allowed_opt.iter().any(|o| o == "*");

        // Defaults first; caller-supplied (filtered) entries overwrite
        // on key collision so a per-call `force-command` can tighten
        // beyond what the default carries.
        let mut extensions: BTreeMap<String, String> = role.default_extensions.clone();
        for (k, v) in req_extensions {
            if allow_any_ext || allowed_ext.iter().any(|e| e == &k) {
                extensions.insert(k, v);
            }
        }
        let mut critical_options: BTreeMap<String, String> = role.default_critical_options.clone();
        for (k, v) in req_options {
            if allow_any_opt || allowed_opt.iter().any(|o| o == &k) {
                critical_options.insert(k, v);
            }
        }

        // ── key_id ─────────────────────────────────────────────────
        let req_key_id = req
            .get_data("key_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let key_id = if !req_key_id.is_empty() {
            req_key_id
        } else {
            // Phase 1 templating: literal `{{role}}` substitution.
            // Phase 3 reaches into the identity templater the PKI
            // engine already uses so `{{token_display_name}}` and the
            // rest start working.
            role.key_id_format.replace("{{role}}", &role_name)
        };

        // ── Serial: random u64 from OS RNG ─────────────────────────
        // `rand::rng()` (rand 0.10's TLS RNG) is used elsewhere in the
        // crate (`shamir.rs`, `exchange/preview.rs`, …); ssh-key's
        // `OsRng` re-export is on a different `rand_core` major and
        // can't share a trait import with us.
        let serial: u64 = rand::rng().random();

        // ── Build + sign ───────────────────────────────────────────
        let mut builder = CertBuilder::new_with_random_nonce(
            &mut OsRng,
            client_pk.key_data().clone(),
            valid_after,
            valid_before,
        )
        .map_err(|e| RvError::ErrString(format!("cert builder init failed: {e}")))?;

        builder
            .serial(serial)
            .map_err(|e| RvError::ErrString(format!("cert serial set failed: {e}")))?;
        builder
            .cert_type(cert_type)
            .map_err(|e| RvError::ErrString(format!("cert type set failed: {e}")))?;
        builder
            .key_id(key_id)
            .map_err(|e| RvError::ErrString(format!("cert key_id set failed: {e}")))?;
        for p in &requested {
            builder
                .valid_principal(p.clone())
                .map_err(|e| RvError::ErrString(format!("cert principal set failed: {e}")))?;
        }
        for (k, v) in &critical_options {
            builder
                .critical_option(k.clone(), v.clone())
                .map_err(|e| RvError::ErrString(format!("cert critical_option set failed: {e}")))?;
        }
        for (k, v) in &extensions {
            builder
                .extension(k.clone(), v.clone())
                .map_err(|e| RvError::ErrString(format!("cert extension set failed: {e}")))?;
        }

        let cert = builder
            .sign(&ca_private_key)
            .map_err(|e| RvError::ErrString(format!("cert sign failed: {e}")))?;

        let signed_key = cert
            .to_openssh()
            .map_err(|e| RvError::ErrString(format!("cert serialise failed: {e}")))?;

        // ── Response ───────────────────────────────────────────────
        let mut data = Map::new();
        data.insert("signed_key".into(), Value::String(signed_key));
        data.insert("serial_number".into(), Value::String(format!("{serial:016x}")));
        Ok(Some(Response::data_response(Some(data))))
    }

    /// PQC sign path. Mirrors `handle_sign`'s policy enforcement,
    /// then routes the cert build through `pqc::sign_cert`. Kept as
    /// a separate method so the classical handler stays readable and
    /// the PQC code only compiles when the feature is on.
    #[cfg(feature = "ssh_pqc")]
    pub async fn handle_sign_pqc(
        &self,
        req: &mut Request,
        role: &super::policy::RoleEntry,
        ca_cfg: &super::policy::CaConfig,
        public_key_str: &str,
    ) -> Result<Option<Response>, RvError> {
        use super::pqc::{self, CaKeypair, CertSpec};

        // Client public key must be ML-DSA-65 if `pqc_only`. If it
        // isn't and the client supplied a classical key, the
        // hand-rolled parser returns None — surface the mismatch
        // explicitly so operators understand why a Phase-1 client
        // can't be issued a PQC cert.
        let client_pk_bytes = pqc::parse_pqc_public_key(public_key_str.trim());
        let client_pk_bytes = match client_pk_bytes {
            Some(b) => b,
            None => {
                if role.pqc_only {
                    return Err(RvError::ErrString(
                        "role has pqc_only=true; client public key must be ssh-mldsa65@openssh.com".into(),
                    ));
                }
                return Err(RvError::ErrString(
                    "PQC CA can only sign ML-DSA-65 client public keys; supply an `ssh-mldsa65@openssh.com` key".into(),
                ));
            }
        };

        // Load the CA from on-disk hex fields and feed it to the
        // PQC signer. The `algorithm` mismatch case is impossible
        // here because the dispatch in `handle_sign` already gated
        // on `ca.algorithm == MLDSA65_ALGO`.
        let ca = CaKeypair::from_hex(&ca_cfg.pqc_secret_seed_hex, &ca_cfg.pqc_public_key_hex)?;

        // ── Policy: principals (subset of allowed_users) ───────────
        let req_principals = req
            .get_data("valid_principals")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let mut requested: Vec<String> = req_principals
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        if requested.is_empty() {
            if !role.default_user.is_empty() {
                requested.push(role.default_user.clone());
            } else {
                return Err(RvError::ErrString(
                    "no valid_principals supplied and role has no default_user".into(),
                ));
            }
        }
        let allowed = role.allowed_users_list();
        let allow_any = allowed.iter().any(|u| u == "*");
        if !allow_any {
            if allowed.is_empty() {
                return Err(RvError::ErrString(
                    "role has empty allowed_users; sign refused".into(),
                ));
            }
            for p in &requested {
                if !allowed.iter().any(|a| a == p) {
                    return Err(RvError::ErrString(format!(
                        "principal `{p}` is not in role's allowed_users"
                    )));
                }
            }
        }

        // ── cert_type ──────────────────────────────────────────────
        let req_cert_type = req
            .get_data("cert_type")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let cert_type_str = if req_cert_type.is_empty() { role.cert_type.clone() } else { req_cert_type };
        let cert_type_u32: u32 = match cert_type_str.as_str() {
            "user" => 1,
            "host" => 2,
            other => return Err(RvError::ErrString(format!(
                "cert_type must be `user` or `host`, got `{other}`"
            ))),
        };

        // ── TTL / validity window ──────────────────────────────────
        let req_ttl_str = req
            .get_data("ttl")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let req_ttl = if req_ttl_str.trim().is_empty() {
            None
        } else {
            Some(humantime::parse_duration(&req_ttl_str).map_err(|e| {
                RvError::ErrString(format!(
                    "ttl: '{req_ttl_str}' is not a valid duration ({e})"
                ))
            })?)
        };
        let ttl = role.effective_ttl(req_ttl);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|e| RvError::ErrString(format!("system clock pre-epoch: {e}")))?
            .as_secs();
        let valid_after = now.saturating_sub(role.not_before_duration.as_secs());
        let valid_before = now.saturating_add(ttl.as_secs());

        // ── Extension / critical_option merge ──────────────────────
        let req_ext = collect_string_map(req, "extensions");
        let req_opt = collect_string_map(req, "critical_options");
        let allowed_ext = role.allowed_extensions_list();
        let allow_any_ext = allowed_ext.iter().any(|e| e == "*");
        let allowed_opt = role.allowed_critical_options_list();
        let allow_any_opt = allowed_opt.iter().any(|o| o == "*");
        let mut extensions: BTreeMap<String, String> = role.default_extensions.clone();
        for (k, v) in req_ext {
            if allow_any_ext || allowed_ext.iter().any(|e| e == &k) {
                extensions.insert(k, v);
            }
        }
        let mut critical_options: BTreeMap<String, String> = role.default_critical_options.clone();
        for (k, v) in req_opt {
            if allow_any_opt || allowed_opt.iter().any(|o| o == &k) {
                critical_options.insert(k, v);
            }
        }

        // ── key_id ─────────────────────────────────────────────────
        let req_key_id = req
            .get_data("key_id")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let role_name_for_key_id = req
            .get_data("role")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        let key_id = if !req_key_id.is_empty() {
            req_key_id
        } else {
            role.key_id_format.replace("{{role}}", &role_name_for_key_id)
        };

        // ── Random serial + nonce ──────────────────────────────────
        let serial: u64 = rand::rng().random();
        let mut nonce = [0u8; 32];
        // Reuse the same TLS RNG `path_sign.rs` already uses; OS RNG
        // for the nonce isn't a security distinction at this scale —
        // the TLS RNG is seeded from getrandom() too.
        rand::rng().fill(&mut nonce[..]);

        // ── Build + sign ───────────────────────────────────────────
        let spec = CertSpec {
            client_pubkey: &client_pk_bytes,
            serial,
            cert_type: cert_type_u32,
            key_id: &key_id,
            valid_principals: &requested,
            valid_after,
            valid_before,
            critical_options: &critical_options,
            extensions: &extensions,
            nonce: &nonce,
        };
        let signed_key = pqc::sign_cert(&ca, &spec)?;

        let mut data = Map::new();
        data.insert("signed_key".into(), Value::String(signed_key));
        data.insert("serial_number".into(), Value::String(format!("{serial:016x}")));
        data.insert("algorithm".into(), Value::String(super::pqc::MLDSA65_ALGO.into()));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Pull a `Map`-typed field as `BTreeMap<String, String>`. Anything
/// not a string-valued JSON object entry is dropped — we don't want
/// to surface obscure type errors to operators when the OpenSSH cert
/// format only carries string-valued options anyway.
fn collect_string_map(req: &Request, key: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Ok(v) = req.get_data(key) {
        if let Value::Object(obj) = v {
            for (k, val) in obj {
                if let Some(s) = val.as_str() {
                    out.insert(k, s.to_string());
                } else if val.is_null() {
                    // `null` → empty string. Matches OpenSSH's encoding
                    // for valueless options (the empty string is the
                    // absent-value marker on the wire).
                    out.insert(k, String::new());
                }
            }
        }
    }
    out
}
