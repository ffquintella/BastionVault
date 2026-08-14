//! `/v1/openldap/config` CRUD + `/v1/openldap/rotate-root`.

use std::{collections::HashMap, sync::Arc};

#[allow(unused_imports)]
use serde_json::{json, Map, Value};

use super::{
    client,
    config::{DirectoryType, LdapConfig, TlsMinVersion, CONFIG_KEY, DEFAULT_REQUEST_TIMEOUT},
    LdapBackend, LdapBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const CONFIG_HELP: &str = r#"
Configure the connection to the directory server. One config per
mount. `bindpass` is barrier-encrypted; reads redact it. Plain
`ldap://` requires either `starttls = true` or both
`insecure_tls = true` + `acknowledge_insecure_tls = true`.
"#;

const ROTATE_ROOT_HELP: &str = r#"
Generate a fresh password, write it to the directory under the
configured `binddn`, and persist the new value as the engine's
bind password. Use this on a schedule to rotate the engine's own
service account.
"#;

impl LdapBackend {
    pub fn config_path(&self) -> Path {
        let read = self.inner.clone();
        let write = self.inner.clone();
        let delete = self.inner.clone();
        new_path!({
            pattern: r"config",
            fields: {
                "url":              { field_type: FieldType::Str,  default: "", description: "`ldap://` or `ldaps://` URL." },
                "binddn":           { field_type: FieldType::Str,  default: "", description: "DN used to authenticate." },
                "bindpass":         { field_type: FieldType::Str,  default: "", description: "Bind password (write-only on read)." },
                "userdn":           { field_type: FieldType::Str,  default: "", description: "Search base for short-name lookups." },
                "directory_type":   { field_type: FieldType::Str,  default: "openldap", description: "`openldap` (default) or `active_directory`." },
                "password_policy":  { field_type: FieldType::Str,  default: "", description: "Optional generator-policy reference. Phase 1 ignores this; the built-in policy is always used." },
                "request_timeout":  { field_type: FieldType::Int,  default: 10, description: "LDAP request timeout in seconds." },
                "starttls":         { field_type: FieldType::Bool, default: false, description: "Issue a StartTLS upgrade after `ldap://` connect." },
                "client_tls_cert":  { field_type: FieldType::Str,  default: "", description: "Client cert PEM for mTLS." },
                "client_tls_key":   { field_type: FieldType::Str,  default: "", description: "Client key PEM for mTLS." },
                "tls_min_version":  { field_type: FieldType::Str,  default: "tls12", description: "`tls12` or `tls13`." },
                "insecure_tls":     { field_type: FieldType::Bool, default: false, description: "Disable cert validation. Refused without `acknowledge_insecure_tls`." },
                "acknowledge_insecure_tls": { field_type: FieldType::Bool, default: false, description: "Operator confirmation that `insecure_tls = true` is intentional." },
                "userattr":         { field_type: FieldType::Str,  default: "cn", description: "Attribute matched against short usernames." }
            },
            operations: [
                {op: Operation::Read,   handler: read.handle_config_read},
                {op: Operation::Write,  handler: write.handle_config_write},
                {op: Operation::Delete, handler: delete.handle_config_delete}
            ],
            help: CONFIG_HELP
        })
    }

    pub fn rotate_root_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"rotate-root",
            operations: [{op: Operation::Write, handler: h.handle_rotate_root}],
            help: ROTATE_ROOT_HELP
        })
    }

    pub fn check_connection_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"check-connection",
            operations: [{op: Operation::Read, handler: h.handle_check_connection}],
            help: "Probe the configured directory: connect, bind, unbind. Returns latency_ms and an error message on failure. Does not modify any directory state."
        })
    }
}

#[maybe_async::maybe_async]
impl LdapBackendInner {
    pub async fn load_config(&self, req: &Request) -> Result<Option<LdapConfig>, RvError> {
        match req.storage_get(CONFIG_KEY).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn save_config(&self, req: &mut Request, cfg: &LdapConfig) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(cfg)?;
        req.storage_put(&StorageEntry {
            key: CONFIG_KEY.to_string(),
            value: bytes,
        })
        .await
    }

    pub async fn handle_config_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        match self.load_config(req).await? {
            None => Ok(None),
            Some(cfg) => {
                let r = cfg.redacted();
                let mut data = Map::new();
                data.insert("url".into(), Value::String(r.url));
                data.insert("binddn".into(), Value::String(r.binddn));
                data.insert("userdn".into(), Value::String(r.userdn));
                data.insert(
                    "directory_type".into(),
                    Value::String(match r.directory_type {
                        DirectoryType::OpenLdap => "openldap".into(),
                        DirectoryType::ActiveDirectory => "active_directory".into(),
                    }),
                );
                data.insert("password_policy".into(), Value::String(r.password_policy));
                data.insert(
                    "request_timeout".into(),
                    Value::Number(r.request_timeout.as_secs().into()),
                );
                data.insert("starttls".into(), Value::Bool(r.starttls));
                data.insert(
                    "tls_min_version".into(),
                    Value::String(match r.tls_min_version {
                        TlsMinVersion::Tls12 => "tls12".into(),
                        TlsMinVersion::Tls13 => "tls13".into(),
                    }),
                );
                data.insert("insecure_tls".into(), Value::Bool(r.insecure_tls));
                data.insert("userattr".into(), Value::String(r.userattr));
                // bindpass + client_tls_key already stripped by `redacted()`.
                Ok(Some(Response::data_response(Some(data))))
            }
        }
    }

    pub async fn handle_config_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let existing = self.load_config(req).await?;

        let bindpass_in = take_str(req, "bindpass");
        let bindpass = if bindpass_in.is_empty() {
            existing
                .as_ref()
                .map(|c| c.bindpass.clone())
                .unwrap_or_default()
        } else {
            bindpass_in
        };

        let cfg = LdapConfig {
            url: take_or(req, "url", existing.as_ref().map(|c| c.url.as_str()).unwrap_or("")),
            binddn: take_or(req, "binddn", existing.as_ref().map(|c| c.binddn.as_str()).unwrap_or("")),
            bindpass,
            userdn: take_or(req, "userdn", existing.as_ref().map(|c| c.userdn.as_str()).unwrap_or("")),
            directory_type: DirectoryType::parse(&take_str(req, "directory_type"))
                .map_err(RvError::ErrString)?,
            password_policy: take_str(req, "password_policy"),
            request_timeout: std::time::Duration::from_secs(
                req.get_data("request_timeout")
                    .ok()
                    .and_then(|v| v.as_u64())
                    .unwrap_or(DEFAULT_REQUEST_TIMEOUT.as_secs()),
            ),
            client_tls_cert: take_str(req, "client_tls_cert"),
            client_tls_key: take_str(req, "client_tls_key"),
            tls_min_version: TlsMinVersion::parse(&take_str(req, "tls_min_version"))
                .map_err(RvError::ErrString)?,
            insecure_tls: take_bool(req, "insecure_tls", false),
            userattr: take_or(req, "userattr", "cn"),
            starttls: take_bool(req, "starttls", false),
        };
        let acknowledge = take_bool(req, "acknowledge_insecure_tls", false);

        cfg.validate(acknowledge).map_err(RvError::ErrString)?;
        self.save_config(req, &cfg).await?;
        Ok(None)
    }

    pub async fn handle_config_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        req.storage_delete(CONFIG_KEY).await?;
        Ok(None)
    }

    pub async fn handle_rotate_root(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let mut cfg = self
            .load_config(req)
            .await?
            .ok_or_else(|| RvError::ErrString("ldap engine not configured".into()))?;

        let new_password = super::password::generate(super::password::DEFAULT_LENGTH);

        // Bind with the *current* password, then write the new one
        // to the bind DN. Directory-write-first is essential: if we
        // wrote storage first and the LDAP write failed, the engine
        // would be unable to bind on the next call.
        let mut ldap = client::bind(&cfg)
            .await
            .map_err(|e| RvError::ErrString(format!("rotate-root: bind: {e}")))?;
        client::set_password(&mut ldap, &cfg, &cfg.binddn, &new_password)
            .await
            .map_err(|e| RvError::ErrString(format!("rotate-root: write: {e}")))?;

        cfg.bindpass = new_password;
        self.save_config(req, &cfg).await?;
        let _ = ldap.unbind().await;
        Ok(None)
    }

    pub async fn handle_check_connection(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let cfg = match self.load_config(req).await? {
            Some(c) => c,
            None => {
                let mut data = Map::new();
                data.insert("ok".into(), Value::Bool(false));
                data.insert("stage".into(), Value::String("config".into()));
                data.insert(
                    "error".into(),
                    Value::String("ldap engine not configured".into()),
                );
                return Ok(Some(Response::data_response(Some(data))));
            }
        };

        // Stage the probe so the operator-facing error pinpoints which
        // layer failed — a 10s "timeout" by itself is hard to act on.
        // Stages: dns → tcp → ldap (bind+TLS through ldap3).
        let mut data = Map::new();
        data.insert("url".into(), Value::String(cfg.url.clone()));
        data.insert("binddn".into(), Value::String(cfg.binddn.clone()));

        let (host, port, scheme) = match parse_ldap_url(&cfg.url) {
            Ok(x) => x,
            Err(e) => {
                data.insert("ok".into(), Value::Bool(false));
                data.insert("stage".into(), Value::String("url".into()));
                data.insert("error".into(), Value::String(e));
                return Ok(Some(Response::data_response(Some(data))));
            }
        };
        data.insert("host".into(), Value::String(host.clone()));
        data.insert("port".into(), Value::Number(port.into()));
        data.insert("scheme".into(), Value::String(scheme.to_string()));

        // Stage 1: DNS resolution. Bound to 5 s so a misconfigured
        // resolver doesn't burn the operator's whole timeout window
        // before the more useful errors get a chance.
        let dns_start = std::time::Instant::now();
        let host_for_dns = host.clone();
        let resolved: Vec<std::net::SocketAddr> = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                (host_for_dns.as_str(), port).to_socket_addrs().map(|i| i.collect::<Vec<_>>())
            }),
        )
        .await
        {
            Err(_) => {
                data.insert("ok".into(), Value::Bool(false));
                data.insert("stage".into(), Value::String("dns".into()));
                data.insert(
                    "dns_ms".into(),
                    Value::Number((dns_start.elapsed().as_millis() as u64).into()),
                );
                data.insert(
                    "error".into(),
                    Value::String(format!("DNS resolution for `{host}` timed out after 5s")),
                );
                return Ok(Some(Response::data_response(Some(data))));
            }
            Ok(Err(join_err)) => {
                data.insert("ok".into(), Value::Bool(false));
                data.insert("stage".into(), Value::String("dns".into()));
                data.insert(
                    "error".into(),
                    Value::String(format!("DNS task failed: {join_err}")),
                );
                return Ok(Some(Response::data_response(Some(data))));
            }
            Ok(Ok(Err(e))) => {
                data.insert("ok".into(), Value::Bool(false));
                data.insert("stage".into(), Value::String("dns".into()));
                data.insert(
                    "dns_ms".into(),
                    Value::Number((dns_start.elapsed().as_millis() as u64).into()),
                );
                data.insert(
                    "error".into(),
                    Value::String(format!("DNS resolution failed for `{host}`: {e}")),
                );
                return Ok(Some(Response::data_response(Some(data))));
            }
            Ok(Ok(Ok(addrs))) => addrs,
        };
        data.insert(
            "dns_ms".into(),
            Value::Number((dns_start.elapsed().as_millis() as u64).into()),
        );
        data.insert(
            "resolved".into(),
            Value::Array(
                resolved
                    .iter()
                    .map(|sa| Value::String(sa.to_string()))
                    .collect(),
            ),
        );
        if resolved.is_empty() {
            data.insert("ok".into(), Value::Bool(false));
            data.insert("stage".into(), Value::String("dns".into()));
            data.insert(
                "error".into(),
                Value::String(format!("DNS returned no addresses for `{host}`")),
            );
            return Ok(Some(Response::data_response(Some(data))));
        }

        // Stage 2: raw TCP connect. Try every resolved address with
        // a 5s budget per address — RR-DNS pools commonly have one
        // dead member and one live member, and ldap3 itself iterates
        // through all `getaddrinfo` answers. If we only probed the
        // first, we'd report failure even when the bind would have
        // succeeded against the second IP.
        let tcp_start = std::time::Instant::now();
        let mut tcp_attempts: Vec<String> = Vec::with_capacity(resolved.len());
        let mut tcp_ok: Option<std::net::SocketAddr> = None;
        for target in &resolved {
            let attempt_start = std::time::Instant::now();
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(*target),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    drop(stream);
                    tcp_attempts.push(format!(
                        "{target} ok ({}ms)",
                        attempt_start.elapsed().as_millis()
                    ));
                    tcp_ok = Some(*target);
                    break;
                }
                Err(_) => {
                    tcp_attempts.push(format!(
                        "{target} timeout ({}ms)",
                        attempt_start.elapsed().as_millis()
                    ));
                }
                Ok(Err(e)) => {
                    tcp_attempts.push(format!(
                        "{target} {e} ({}ms)",
                        attempt_start.elapsed().as_millis()
                    ));
                }
            }
        }
        data.insert(
            "tcp_ms".into(),
            Value::Number((tcp_start.elapsed().as_millis() as u64).into()),
        );
        data.insert(
            "tcp_attempts".into(),
            Value::Array(
                tcp_attempts
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        if tcp_ok.is_none() {
            data.insert("ok".into(), Value::Bool(false));
            data.insert("stage".into(), Value::String("tcp".into()));
            data.insert(
                "error".into(),
                Value::String(format!(
                    "TCP connect failed for every resolved address ({} tried) — host unreachable, firewall blocking port {port}, or wrong port. Attempts: {}",
                    resolved.len(),
                    tcp_attempts.join("; ")
                )),
            );
            return Ok(Some(Response::data_response(Some(data))));
        }

        // Stage 3: full LDAP connect + TLS + simple bind. Anything
        // that fails here is almost certainly TLS (cert validation,
        // SNI, name mismatch, StartTLS misconfig) or auth (bad
        // binddn/bindpass) rather than network.
        let bind_start = std::time::Instant::now();
        match client::bind(&cfg).await {
            Ok(mut ldap) => {
                let _ = ldap.unbind().await;
                data.insert("ok".into(), Value::Bool(true));
                data.insert("stage".into(), Value::String("bind".into()));
                data.insert(
                    "bind_ms".into(),
                    Value::Number((bind_start.elapsed().as_millis() as u64).into()),
                );
                let total = dns_start.elapsed().as_millis() as u64;
                data.insert("latency_ms".into(), Value::Number(total.into()));
            }
            Err(e) => {
                let bind_ms = bind_start.elapsed().as_millis() as u64;
                let total = dns_start.elapsed().as_millis() as u64;
                let stage = match &e {
                    client::LdapClientError::Connect(_) => "ldap-connect",
                    client::LdapClientError::Bind(_) => "ldap-bind",
                    _ => "ldap",
                };
                data.insert("ok".into(), Value::Bool(false));
                data.insert("stage".into(), Value::String(stage.into()));
                data.insert("bind_ms".into(), Value::Number(bind_ms.into()));
                data.insert("latency_ms".into(), Value::Number(total.into()));
                let hint = match stage {
                    "ldap-connect" => " (TCP succeeded earlier — likely TLS handshake or StartTLS upgrade failure: check `tls_min_version`, `insecure_tls`, server cert SAN/CN, or for an `ldaps://` vs `ldap://` mismatch)",
                    "ldap-bind" => " (server reachable — check `binddn` and `bindpass`)",
                    _ => "",
                };
                data.insert(
                    "error".into(),
                    Value::String(format!("{e}{hint}")),
                );
            }
        }
        Ok(Some(Response::data_response(Some(data))))
    }
}

/// Parse an `ldap://host[:port]` or `ldaps://host[:port]` URL into
/// `(host, port, scheme)`. Default ports per RFC 4516 §2: `389` for
/// `ldap`, `636` for `ldaps`.
fn parse_ldap_url(url: &str) -> Result<(String, u16, &'static str), String> {
    let s = url.trim();
    let (scheme, rest, default_port) = if let Some(r) = s.strip_prefix("ldaps://") {
        ("ldaps", r, 636u16)
    } else if let Some(r) = s.strip_prefix("ldap://") {
        ("ldap", r, 389u16)
    } else {
        return Err(format!("url `{url}` must start with ldap:// or ldaps://"));
    };
    // Strip any path the operator may have appended.
    let host_port = rest.split('/').next().unwrap_or(rest);
    // IPv6 literal in brackets: `[::1]:636`.
    if let Some(stripped) = host_port.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| format!("url `{url}` has unclosed `[` for IPv6 literal"))?;
        let host = &stripped[..end];
        let after = &stripped[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| format!("url `{url}` has invalid port `{p}`"))?
        } else {
            default_port
        };
        return Ok((host.to_string(), port, scheme));
    }
    // host[:port]
    if let Some((h, p)) = host_port.rsplit_once(':') {
        // Avoid mis-treating an empty host like `:636`.
        if !h.is_empty() {
            let port = p
                .parse::<u16>()
                .map_err(|_| format!("url `{url}` has invalid port `{p}`"))?;
            return Ok((h.to_string(), port, scheme));
        }
    }
    if host_port.is_empty() {
        return Err(format!("url `{url}` has empty host"));
    }
    Ok((host_port.to_string(), default_port, scheme))
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn take_or(req: &Request, key: &str, default: &str) -> String {
    let s = take_str(req, key);
    if s.is_empty() {
        default.to_string()
    } else {
        s
    }
}

fn take_bool(req: &Request, key: &str, default: bool) -> bool {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

#[cfg(test)]
mod url_tests {
    use super::parse_ldap_url;

    #[test]
    fn defaults_implicit_ports() {
        assert_eq!(parse_ldap_url("ldap://h").unwrap(), ("h".into(), 389, "ldap"));
        assert_eq!(parse_ldap_url("ldaps://h").unwrap(), ("h".into(), 636, "ldaps"));
    }
    #[test]
    fn explicit_port() {
        assert_eq!(
            parse_ldap_url("ldap://h:1389").unwrap(),
            ("h".into(), 1389, "ldap")
        );
    }
    #[test]
    fn ipv6_literal() {
        assert_eq!(
            parse_ldap_url("ldaps://[::1]").unwrap(),
            ("::1".into(), 636, "ldaps")
        );
        assert_eq!(
            parse_ldap_url("ldaps://[::1]:1636").unwrap(),
            ("::1".into(), 1636, "ldaps")
        );
    }
    #[test]
    fn rejects_missing_scheme() {
        assert!(parse_ldap_url("h:389").is_err());
    }
}
