//! `POST resources/v2/connect/session/open` — the vault-side audit row for a
//! session that is about to dial its target.
//!
//! A direct SSH, RDP or SFTP session is dialled by the desktop host without a
//! vault request, so the request pipeline never sees the connection. The host
//! posts the open here before it dials; the pipeline then writes the row to
//! every audit device like any other request. The post is fail-closed: if the
//! audit write fails, the host does not dial.
//!
//! The shape is a closed vocabulary, the same discipline as
//! `connect_clipboard.rs`: protocol and transport are enumerated, the target
//! is a host and a port, and no credential, secret or token is accepted.

use serde_json::{Map, Value};

use crate::{bv_error_response_status, errors::RvError, logical::Request};

const PROTOCOLS: &[&str] = &["ssh", "rdp", "sftp", "web"];
const TRANSPORTS: &[&str] = &["direct", "rustion"];
const MAX_HOST_LEN: usize = 255;

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return Err(format!("`host` must be 1..={MAX_HOST_LEN} characters"));
    }
    if !host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')) {
        return Err("`host` may contain only hostname or IP characters".into());
    }
    Ok(())
}

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    /// `POST resources/v2/connect/session/open`.
    ///
    /// Gated like the other connect endpoints: the caller must hold the connect
    /// grant on the resource, and the profile's protocol must match the
    /// declared `protocol`, so a caller cannot record an SSH open against an
    /// RDP profile.
    pub async fn handle_connect_session_open(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        let (resource, profile_id, meta) = self.connect_target_record(req).await?;
        let profile =
            meta.as_ref().and_then(|m| crate::connect_mfa::find_profile(m, &profile_id)).ok_or_else(|| {
                bv_error_response_status!(404, &format!("profile `{profile_id}` not found on resource `{resource}`"))
            })?;

        let protocol = str_field(req, "protocol")?;
        if !PROTOCOLS.contains(&protocol.as_str()) {
            return Err(bv_error_response_status!(400, "`protocol` must be one of ssh, rdp, sftp, web"));
        }
        if profile.get("protocol").and_then(|v| v.as_str()) != Some(protocol.as_str()) {
            return Err(bv_error_response_status!(400, "`protocol` does not match the connection profile"));
        }
        let transport = str_field(req, "transport")?;
        if !TRANSPORTS.contains(&transport.as_str()) {
            return Err(bv_error_response_status!(400, "`transport` must be one of direct, rustion"));
        }
        let host = str_field(req, "host")?;
        validate_host(&host).map_err(|e| bv_error_response_status!(400, &e))?;
        let port = req
            .get_data("port")
            .ok()
            .and_then(|v| v.as_u64())
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or_else(|| bv_error_response_status!(400, "`port` must be an integer in 1..=65535"))?;

        let mut data = Map::new();
        data.insert("protocol".into(), Value::from(protocol));
        data.insert("transport".into(), Value::from(transport));
        data.insert("port".into(), Value::from(port));
        Ok(Some(crate::logical::Response::data_response(Some(data))))
    }
}

fn str_field(req: &Request, key: &str) -> Result<String, RvError> {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bv_error_response_status!(400, &format!("`{key}` is required")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_accepts_hostnames_and_addresses() {
        assert!(validate_host("srv1.example.internal").is_ok());
        assert!(validate_host("10.0.0.5").is_ok());
        assert!(validate_host("[2001:db8::1]").is_ok());
    }

    #[test]
    fn host_rejects_empty_oversized_and_free_text() {
        assert!(validate_host("").is_err());
        assert!(validate_host(&"a".repeat(MAX_HOST_LEN + 1)).is_err());
        assert!(validate_host("srv1 password=hunter2").is_err());
        assert!(validate_host("srv1/../x").is_err());
    }
}
