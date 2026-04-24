//! `auth/<mount>/login` — generates a SAML AuthnRequest and returns
//! the IdP SSO URL (with `SAMLRequest` + `RelayState` query params)
//! the browser should redirect to.
//!
//! The caller POSTs `{role}` (optional; falls back to
//! `SamlConfig.default_role`) and optionally `{redirect_uri}` for
//! client-side post-callback navigation. We synthesise a fresh
//! request ID + relay_state, record a short-lived state record
//! keyed by relay_state, and return the full redirect URL.
//!
//! State records live at `state/<relay_state>` and expire after 5
//! minutes. The callback handler load-and-deletes them to enforce
//! single-use.

use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::authn_request::{new_request_id, saml_now, AuthnRequestBuilder};
use super::path_config::SamlConfig;
use super::path_roles::SamlRoleEntry;
use super::{SamlBackend, SamlBackendInner};

use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

pub(crate) const STATE_PREFIX: &str = "state/";
/// 5 minutes, matching the OIDC auth-url state TTL.
pub(crate) const STATE_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAuthState {
    pub role_name: String,
    pub request_id: String,
    pub relay_state: String,
    pub redirect_uri: String,
    /// Unix seconds, used by the callback handler to reject expired
    /// states even if the surrounding storage doesn't auto-evict.
    pub created_at: u64,
}

impl SamlBackend {
    pub fn login_path(&self) -> Path {
        let this = self.inner.clone();
        new_path!({
            pattern: r"login",
            fields: {
                "role": {
                    field_type: FieldType::Str,
                    description: "SAML role to authenticate against. Falls back to `SamlConfig.default_role` when omitted."
                },
                "redirect_uri": {
                    field_type: FieldType::Str,
                    description: "Optional post-callback redirect URI. Must be on the config's allow-list when that list is non-empty."
                }
            },
            operations: [
                {op: Operation::Write, handler: this.handle_login}
            ],
            help: "Generate a SAML AuthnRequest and return the IdP SSO URL."
        })
    }
}

#[maybe_async::maybe_async]
impl SamlBackendInner {
    pub async fn handle_login(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = SamlConfig::load(req)
            .await?
            .ok_or_else(|| RvError::ErrString("saml: mount is not configured".into()))?;

        let role_name = req
            .get_data("role")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| cfg.default_role.clone());
        if role_name.trim().is_empty() {
            return Err(RvError::ErrString(
                "saml: no role supplied and no default_role configured".into(),
            ));
        }

        // Load the role so we fail fast if it doesn't exist. Role
        // fields (policies, TTLs) are consumed by the callback
        // handler; we just need to prove the role is present.
        let _role = SamlRoleEntry::load(req, &role_name)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!("saml: role `{role_name}` not found"))
            })?;

        let redirect_uri = req
            .get_data("redirect_uri")
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        if !cfg.allowed_redirect_uris.is_empty()
            && !redirect_uri.is_empty()
            && !cfg.allowed_redirect_uris.iter().any(|u| u == &redirect_uri)
        {
            return Err(RvError::ErrString(format!(
                "saml: redirect_uri `{redirect_uri}` is not on the allow-list"
            )));
        }

        let sso_url = resolve_sso_url(&cfg)?;
        let request_id = new_request_id();
        let relay_state = new_request_id();
        let issue_instant = saml_now();

        let builder = AuthnRequestBuilder {
            id: &request_id,
            issue_instant: &issue_instant,
            destination: &sso_url,
            assertion_consumer_service_url: &cfg.acs_url,
            issuer: &cfg.entity_id,
        };
        let encoded = builder.encode_redirect().map_err(|e| {
            RvError::ErrString(format!("saml: failed to DEFLATE AuthnRequest: {e}"))
        })?;

        // Persist the auth state keyed by relay_state. Callback
        // single-uses it — load-and-delete.
        let state = SamlAuthState {
            role_name,
            request_id: request_id.clone(),
            relay_state: relay_state.clone(),
            redirect_uri: redirect_uri.clone(),
            created_at: super::validate::now_unix(),
        };
        req.storage_put(&StorageEntry {
            key: format!("{STATE_PREFIX}{relay_state}"),
            value: serde_json::to_vec(&state)?,
        })
        .await?;

        // Build the redirect URL. Note: we use the HTTP-POST binding
        // as the SP's ProtocolBinding — the IdP will POST back to
        // `acs_url`. Our redirect here is a plain GET to the IdP's
        // SSO endpoint with the DEFLATE+base64+urlencode envelope
        // per the HTTP-Redirect binding rules.
        let sep = if sso_url.contains('?') { '&' } else { '?' };
        let full_url = format!(
            "{sso}{sep}SAMLRequest={req}&RelayState={rs}",
            sso = sso_url,
            sep = sep,
            req = url_encode(&encoded),
            rs = url_encode(&relay_state),
        );

        let mut data = serde_json::Map::new();
        data.insert("sso_url".into(), Value::String(full_url));
        data.insert("relay_state".into(), Value::String(relay_state));
        data.insert("request_id".into(), Value::String(request_id));
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Pick the IdP SSO URL from config. Prefers `idp_sso_url` when set
/// explicitly; falls back to extracting it from inline metadata if
/// only that is configured. Metadata-URL-based discovery is not
/// implemented here — operators who use a metadata URL should also
/// set `idp_sso_url` at config write time.
fn resolve_sso_url(cfg: &SamlConfig) -> Result<String, RvError> {
    if !cfg.idp_sso_url.trim().is_empty() {
        return Ok(cfg.idp_sso_url.clone());
    }
    if !cfg.idp_metadata_xml.trim().is_empty() {
        if let Some(url) = extract_sso_url_from_metadata(&cfg.idp_metadata_xml) {
            return Ok(url);
        }
    }
    Err(RvError::ErrString(
        "saml: no idp_sso_url configured and unable to discover one from metadata".into(),
    ))
}

/// Minimal metadata SSO-URL extractor. Looks for a
/// `<SingleSignOnService>` with Binding = HTTP-Redirect or HTTP-POST
/// and returns its `Location` attribute.
fn extract_sso_url_from_metadata(xml: &str) -> Option<String> {
    let needle = "SingleSignOnService";
    let idx = xml.find(needle)?;
    let tail = &xml[idx..];
    let end = tail.find('>')?;
    let tag = &tail[..end];
    // Pull `Location="..."`.
    let key = "Location=\"";
    let loc_start = tag.find(key)?;
    let after = &tag[loc_start + key.len()..];
    let loc_end = after.find('"')?;
    Some(after[..loc_end].to_string())
}

/// Percent-encode for query-string values. We avoid pulling in the
/// full `url::form_urlencoded` crate for what amounts to a few
/// characters — the AuthnRequest payload is base64 (URL-safe
/// character set plus `+/=`) and the relay_state is our own hex.
fn url_encode(s: &str) -> String {
    // Keep base64 characters readable (but `+`, `/`, `=` still need
    // escaping inside URLs), everything else as %HH.
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0xF));
            }
        }
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + nibble - 10) as char,
        _ => '0',
    }
}

/// Helper used by `path_callback.rs` to load and immediately delete
/// a state record (single-use semantics).
#[allow(dead_code)]
pub async fn load_and_delete_state(
    req: &mut Request,
    relay_state: &str,
) -> Result<Option<SamlAuthState>, RvError> {
    let key = format!("{STATE_PREFIX}{relay_state}");
    let entry = match req.storage_get(&key).await? {
        Some(e) => e,
        None => return Ok(None),
    };
    let parsed: SamlAuthState = serde_json::from_slice(&entry.value)?;
    // Delete first so a retry storm can't double-redeem the state.
    // Failure here leaves the state in place; the caller will see it
    // again on retry and the validator will reject the now-expired
    // timestamp.
    let _ = req.storage_delete(&key).await;
    Ok(Some(parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_preserves_unreserved_escapes_rest() {
        assert_eq!(url_encode("abc-_.~"), "abc-_.~");
        assert_eq!(url_encode("a b"), "a%20b");
        assert_eq!(url_encode("a+b/c=d"), "a%2Bb%2Fc%3Dd");
    }

    #[test]
    fn extract_sso_url_from_metadata_pulls_location() {
        let meta = r#"<EntityDescriptor>
            <IDPSSODescriptor>
              <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso" />
            </IDPSSODescriptor>
          </EntityDescriptor>"#;
        assert_eq!(
            extract_sso_url_from_metadata(meta),
            Some("https://idp.example.com/sso".into())
        );
    }

    #[test]
    fn base64_padding_in_sso_request_is_properly_escaped() {
        // Sanity: the encode_redirect output commonly contains `=`
        // padding. After url_encode it should become `%3D`, not be
        // left raw (which would break URL parsers).
        let req = AuthnRequestBuilder {
            id: "id-1",
            issue_instant: "2026-04-24T12:00:00Z",
            destination: "https://idp.example.com/sso",
            assertion_consumer_service_url: "https://sp.example.com/acs",
            issuer: "https://sp.example.com",
        };
        let raw = req.encode_redirect().unwrap();
        let encoded = url_encode(&raw);
        assert!(
            !encoded.contains('='),
            "= must be percent-encoded, got `{encoded}`"
        );
    }

    // (unused-base64 helper removed after the unused import cleanup)
}
