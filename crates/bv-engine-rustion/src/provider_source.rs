//! The `provider` credential source on `rustion/v2/session/open`
//! (`features/self-accounts.md` §6, T103 Phase 3).
//!
//! A connection profile whose `credential_source` is
//! `{"kind": "provider", "provider": "<plugin>"}` takes the operator's own
//! account from an approved credential-provider plugin. On this route the
//! **server** releases it and seals it into the bastion envelope, exactly like
//! the `secret` source: the desktop host never holds it.
//!
//! The request names the account (`provider_account_id`) and repeats the
//! source; everything else the provider is told comes from the **stored**
//! resource record and profile. The request's `target_host` / `target_port` /
//! `target_protocol`, which the envelope dials, must equal the target the
//! account is released for, and are overwritten with it — so a credential
//! bound to `dc01.corp` cannot be sealed into an envelope that dials anywhere
//! else (spec §5).
//!
//! Like the `secret` source, a passphrase-protected private key is refused:
//! the envelope has no passphrase channel.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::kernel_api::{
    engines::PluginHost,
    provider::{
        host_target, profile_provider, provider_name, provider_resource, reason, refusal, refusal_reason,
        require_not_brokered_for, CallerIdentity, ProviderAudit, ProviderConnectContext, ProviderNeeds,
        ProviderReleaseRequest, ProviderResource, ProviderTarget, ReleasedCredential, ReleasedSecret,
    },
};
use crate::{
    errors::RvError,
    logical::{Operation, Request},
};

/// Longest `provider_account_id` accepted (the resource engine's bound).
const MAX_ACCOUNT_ID_LEN: usize = 128;

/// A provider open checked as far as it can be before the MFA gate: the
/// stored profile names this provider, the target is the stored one, the
/// caller has an entity and the provider is live for the protocol.
pub(crate) struct ProviderOpen {
    parts: OpenParts,
    audit: ProviderAudit,
}

impl ProviderOpen {
    /// Audit a refusal that happened between the pre-flight and the release
    /// (the MFA gate).
    pub(crate) fn denied(&self, reason: &str) {
        self.audit.denied(reason);
    }
}

struct OpenParts {
    host: Arc<dyn PluginHost>,
    provider: String,
    caller: CallerIdentity,
    protocol: &'static str,
    resource: ProviderResource,
    target: ProviderTarget,
    account_id: String,
}

/// What a released credential becomes on the envelope.
pub(crate) struct BrokeredMaterial {
    pub kind: &'static str,
    pub username: String,
    /// Base64 of the password bytes or of the OpenSSH private key.
    pub material_b64: Zeroizing<String>,
}

/// Never prints the material: base64 is an encoding, not a protection.
impl std::fmt::Debug for BrokeredMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokeredMaterial")
            .field("kind", &self.kind)
            .field("username", &self.username)
            .field("material_b64", &"<redacted>")
            .finish()
    }
}

/// Map a released credential onto the envelope's credential kinds, the same
/// ones the desktop host sends for a resolved secret: `ssh-password`,
/// `ssh-key` (OpenSSH PEM), `rdp-password`. RDP has no domain field on the
/// wire for a password, so a domain travels as `DOMAIN\user`; SSH has no
/// domain at all, and the released username is used as is.
pub(crate) fn brokered_material(protocol: &str, cred: &ReleasedCredential) -> Result<BrokeredMaterial, RvError> {
    match (&cred.secret, protocol) {
        (ReleasedSecret::Password { password, .. }, "ssh") => Ok(BrokeredMaterial {
            kind: "ssh-password",
            username: cred.username.clone(),
            material_b64: Zeroizing::new(STANDARD.encode(password.as_bytes())),
        }),
        (ReleasedSecret::Password { password, .. }, "rdp") => Ok(BrokeredMaterial {
            kind: "rdp-password",
            username: match &cred.domain {
                Some(d) if !d.is_empty() => format!("{d}\\{}", cred.username),
                _ => cred.username.clone(),
            },
            material_b64: Zeroizing::new(STANDARD.encode(password.as_bytes())),
        }),
        (ReleasedSecret::SshKey { private_key }, "ssh") => {
            let parsed = ssh_key::PrivateKey::from_openssh(private_key.as_bytes()).map_err(|_| {
                refusal(
                    502,
                    reason::BAD_PROVIDER_OUTPUT,
                    "the credential provider released a private key that is not an OpenSSH private key",
                )
            })?;
            if parsed.is_encrypted() {
                return Err(refusal(
                    422,
                    reason::BAD_PROVIDER_OUTPUT,
                    "the credential provider released a passphrase-protected SSH private key, which cannot be \
                     brokered through a bastion (the envelope has no passphrase channel)",
                ));
            }
            drop(parsed);
            Ok(BrokeredMaterial {
                kind: "ssh-key",
                username: cred.username.clone(),
                material_b64: Zeroizing::new(STANDARD.encode(private_key.as_bytes())),
            })
        }
        _ => Err(refusal(
            502,
            reason::BAD_PROVIDER_OUTPUT,
            format!("the credential provider released a {} for protocol `{protocol}`", cred.secret.kind()),
        )),
    }
}

/// The request's `provider_account_id`, strictly: `Ok(None)` when absent or
/// empty, an error when wrong-typed or malformed.
fn account_id_field(req: &Request) -> Result<Option<String>, RvError> {
    let invalid = || refusal(400, reason::INVALID_REQUEST, "`provider_account_id` must be an account id string");
    match req.get_data("provider_account_id") {
        Ok(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            if s.len() > MAX_ACCOUNT_ID_LEN || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(invalid());
            }
            Ok(Some(s.to_string()))
        }
        Ok(_) | Err(RvError::ErrRequestFieldInvalid) => Err(invalid()),
        Err(_) => Ok(None),
    }
}

fn str_field(req: &Request, key: &str) -> String {
    req.get_data(key).ok().and_then(|v| v.as_str().map(|s| s.trim().to_string())).unwrap_or_default()
}

#[maybe_async::maybe_async]
impl super::RustionBackendInner {
    /// The `provider` pre-flight. `Ok(None)` for any other source — after
    /// refusing a `provider_account_id` that came with one. Runs before the
    /// MFA gate, so a refusal here costs the operator no ticket; every
    /// refusal is audited as `connect.provider.release outcome=denied`.
    pub(crate) async fn provider_open_preflight(
        &self,
        req: &mut Request,
        ns_prefix: &str,
        resource_name: &str,
    ) -> Result<Option<ProviderOpen>, RvError> {
        let cs = req.get_data("credential_source").ok().and_then(|v| v.as_object().cloned());
        let is_provider = cs.as_ref().and_then(|c| c.get("kind")).and_then(Value::as_str) == Some("provider");
        if !is_provider {
            if account_id_field(req)?.is_some() {
                return Err(refusal(
                    400,
                    reason::INVALID_REQUEST,
                    "`provider_account_id` applies only to a `provider` credential source",
                ));
            }
            return Ok(None);
        }
        let cs = cs.unwrap_or_default();

        let mut audit = ProviderAudit::new("release", "rustion", req);
        audit.resource = resource_name.to_string();
        audit.profile_id = str_field(req, "profile_id");
        audit.provider = cs.get("provider").and_then(Value::as_str).unwrap_or_default().to_string();
        match self.provider_open_checks(req, ns_prefix, resource_name, &cs, &mut audit).await {
            Ok(parts) => Ok(Some(ProviderOpen { parts, audit })),
            Err(e) => {
                audit.denied(match refusal_reason(&e) {
                    reason::ERROR => reason::INVALID_REQUEST,
                    r => r,
                });
                Err(e)
            }
        }
    }

    async fn provider_open_checks(
        &self,
        req: &mut Request,
        ns_prefix: &str,
        resource_name: &str,
        cs: &Map<String, Value>,
        audit: &mut ProviderAudit,
    ) -> Result<OpenParts, RvError> {
        let invalid_request = |m: String| refusal(400, reason::INVALID_REQUEST, m);
        let invalid_profile = |m: String| refusal(422, reason::INVALID_PROFILE, m);

        // The bastion is given the provider's credential and nothing else.
        let material =
            req.get_data("credential_material").ok().and_then(|v| v.as_str().map(|s| !s.is_empty())).unwrap_or(false);
        if material {
            return Err(invalid_request(
                "`credential_material` cannot be combined with a `provider` credential source".into(),
            ));
        }
        let requested = provider_name(cs).map_err(invalid_request)?;
        let account_id = account_id_field(req)?;
        audit.account_id = account_id.clone().unwrap_or_default();
        let profile_id = str_field(req, "profile_id");
        if profile_id.is_empty() {
            return Err(invalid_request("a `provider` credential source needs `profile_id`".into()));
        }

        // The stored record, under the server's authority: the connect grant
        // on this resource was checked by the caller of this function.
        let path = format!("{ns_prefix}resources/resources/{resource_name}");
        let mut sub = Request::new(&path);
        sub.operation = Operation::Read;
        let meta = self
            .core
            .router()
            .handle_request(&mut sub)
            .await?
            .and_then(|r| r.data)
            .ok_or_else(|| refusal(404, reason::INVALID_REQUEST, format!("resource `{resource_name}` not found")))?;
        let profile = meta
            .get("connection_profiles")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|p| p.get("id").and_then(Value::as_str) == Some(profile_id.as_str())))
            .cloned()
            .ok_or_else(|| {
                refusal(404, reason::INVALID_REQUEST, format!("profile `{profile_id}` not found on `{resource_name}`"))
            })?;

        // The stored profile, not the request, decides that this is a
        // provider launch and which provider.
        match profile_provider(&profile).map_err(invalid_profile)? {
            Some(stored) if stored == requested => {}
            Some(stored) => {
                return Err(invalid_request(format!(
                    "the stored profile takes its credential from provider `{stored}`, not `{requested}`"
                )))
            }
            None => {
                return Err(invalid_request(
                    "the stored profile does not take its credential from a credential provider".into(),
                ))
            }
        }
        let protocol: &'static str = match profile.get("protocol").and_then(Value::as_str) {
            Some("ssh") => "ssh",
            Some("rdp") => "rdp",
            _ => return Err(invalid_profile("a brokered provider profile must be ssh or rdp".into())),
        };
        audit.protocol = protocol.into();
        // The SSH login class: a provider account is a static credential, so
        // it is never sealed for an SSH login to a brokered resource, whose
        // every SSH login the SSH engine mints. Before the MFA gate, like
        // every check here.
        require_not_brokered_for(self.core.as_ref(), resource_name, &meta, protocol).await?;

        let resource = provider_resource(&meta).map_err(invalid_profile)?;
        let target = host_target(&profile, &meta, protocol).map_err(invalid_profile)?;
        let ProviderTarget::Host { host, port } = &target else {
            return Err(invalid_profile("a brokered provider profile needs a host target".into()));
        };

        // The envelope dials what the request says, so the request must say
        // exactly the target the account is released for.
        let req_proto = str_field(req, "target_protocol");
        if !req_proto.is_empty() && req_proto != protocol {
            return Err(invalid_request(format!(
                "`target_protocol` `{req_proto}` does not match the stored profile's `{protocol}`"
            )));
        }
        let req_host = str_field(req, "target_host");
        if !req_host.is_empty() && !req_host.eq_ignore_ascii_case(host) {
            return Err(invalid_request(format!(
                "`target_host` does not match the stored target `{host}` this profile's credential is bound to"
            )));
        }
        if let Ok(v) = req.get_data("target_port") {
            if v.as_u64() != Some(u64::from(*port)) {
                return Err(invalid_request(format!(
                    "`target_port` does not match the stored target port {port} this profile's credential is bound to"
                )));
            }
        }

        let account_id = account_id.ok_or_else(|| {
            invalid_request(
                "`provider_account_id` is required for a provider profile: the account the operator picked from \
                 `resources/v2/connect/provider/candidates`"
                    .into(),
            )
        })?;
        let caller = CallerIdentity::from_request(req);
        if caller.entity_id.is_empty() {
            return Err(refusal(
                403,
                reason::NO_ENTITY,
                "a credential provider releases per-user accounts and needs an identity-backed login; this token \
                 has no identity entity",
            ));
        }
        let not_approved = || {
            refusal(403, reason::NOT_GRANTED, format!("credential provider `{requested}` is not approved on this server"))
        };
        let plugin_host = self.core.plugin_host().ok_or_else(not_approved)?;
        let decl =
            plugin_host.credential_providers().await.into_iter().find(|d| d.plugin == requested).ok_or_else(not_approved)?;
        if !decl.protocols.iter().any(|p| p == protocol) {
            return Err(refusal(
                400,
                reason::UNSUPPORTED_PROTOCOL,
                format!("credential provider `{requested}` does not support protocol `{protocol}`"),
            ));
        }

        // Pin the envelope's target to the stored one.
        let data = req.data.get_or_insert_with(Map::new);
        data.insert("target_host".into(), Value::String(host.clone()));
        data.insert("target_port".into(), Value::from(*port));
        data.insert("target_protocol".into(), Value::String(protocol.into()));

        Ok(OpenParts { host: plugin_host, provider: requested, caller, protocol, resource, target, account_id })
    }

    /// Release the account and put it where the `secret` source puts its
    /// material. `mfa_verified` is true only when the MFA gate redeemed a
    /// ticket for this open. Client-supplied credential fields that do not
    /// belong to this credential are cleared, so nothing the caller sent is
    /// sealed next to it.
    pub(crate) async fn provider_open_release(
        &self,
        req: &mut Request,
        open: ProviderOpen,
        mfa_verified: bool,
    ) -> Result<(), RvError> {
        let ProviderOpen { parts: open, audit } = open;
        let release = ProviderReleaseRequest {
            account_id: open.account_id.clone(),
            protocol: open.protocol.to_string(),
            resource: open.resource.clone(),
            target: open.target.clone(),
            needs: ProviderNeeds { password: true, totp: false },
            connect: ProviderConnectContext { mfa_verified, transport: "rustion".into() },
        };
        let cred = match open.host.provider_release(&open.provider, &open.caller, &release).await {
            Ok(c) => c,
            Err(e) => {
                audit.denied(refusal_reason(&e));
                return Err(e);
            }
        };
        let material = match brokered_material(open.protocol, &cred) {
            Ok(m) => m,
            Err(e) => {
                audit.denied(refusal_reason(&e));
                return Err(e);
            }
        };
        audit.released(&cred.username);
        log::info!(
            target: "security",
            "rustion-connect-resolve: user={:?} resource={:?} source=provider provider={:?} account_id={:?}",
            open.caller.principal(),
            audit.resource,
            open.provider,
            open.account_id
        );

        let data = req.data.get_or_insert_with(Map::new);
        data.insert("credential_kind".into(), Value::String(material.kind.into()));
        data.insert("credential_username".into(), Value::String(material.username.clone()));
        data.insert("credential_material".into(), Value::String(material.material_b64.to_string()));
        data.insert("credential_cert".into(), Value::String(String::new()));
        data.insert("credential_serial".into(), Value::String(String::new()));
        Ok(())
    }
}

/// Overwrite the sealed-in material left on the request once the envelope is
/// built, so the base64 credential does not outlive the open.
pub(crate) fn scrub_material(req: &mut Request) {
    if let Some(Value::String(s)) = req.data.as_mut().and_then(|d| d.get_mut("credential_material")) {
        s.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(domain: Option<&str>) -> ReleasedCredential {
        ReleasedCredential {
            username: "felipe.adm".into(),
            domain: domain.map(String::from),
            secret: ReleasedSecret::Password { password: Zeroizing::new("hunter2-S3CRET".into()), totp_seed: None },
        }
    }

    #[test]
    fn passwords_map_onto_the_envelope_kinds() {
        let m = brokered_material("ssh", &pw(Some("CORP"))).unwrap();
        assert_eq!((m.kind, m.username.as_str()), ("ssh-password", "felipe.adm"), "SSH has no domain");
        assert_eq!(STANDARD.decode(m.material_b64.as_bytes()).unwrap(), b"hunter2-S3CRET");

        let m = brokered_material("rdp", &pw(Some("CORP"))).unwrap();
        assert_eq!((m.kind, m.username.as_str()), ("rdp-password", "CORP\\felipe.adm"));
        let m = brokered_material("rdp", &pw(None)).unwrap();
        assert_eq!(m.username, "felipe.adm");
    }

    fn key(pem: &str) -> ReleasedCredential {
        ReleasedCredential {
            username: "felipe".into(),
            domain: None,
            secret: ReleasedSecret::SshKey { private_key: Zeroizing::new(pem.into()) },
        }
    }

    #[test]
    fn keys_must_be_unencrypted_openssh_keys_and_ssh_only() {
        use ssh_key::{rand_core::OsRng, Algorithm, LineEnding, PrivateKey};
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let plain = k.to_openssh(LineEnding::LF).unwrap().to_string();
        let m = brokered_material("ssh", &key(&plain)).unwrap();
        assert_eq!(m.kind, "ssh-key");
        assert_eq!(STANDARD.decode(m.material_b64.as_bytes()).unwrap(), plain.as_bytes());

        let encrypted = k.encrypt(&mut OsRng, "passphrase").unwrap().to_openssh(LineEnding::LF).unwrap().to_string();
        let e = brokered_material("ssh", &key(&encrypted)).unwrap_err();
        assert_eq!(refusal_reason(&e), reason::BAD_PROVIDER_OUTPUT);
        assert!(format!("{e}").contains("passphrase-protected"));

        assert!(brokered_material("ssh", &key("not a key")).is_err());
        assert!(brokered_material("rdp", &key(&plain)).is_err(), "a key is never an RDP credential");
    }

    #[test]
    fn debug_never_prints_the_material() {
        let m = brokered_material("rdp", &pw(Some("CORP"))).unwrap();
        let shown = format!("{m:?}");
        let encoded = STANDARD.encode("hunter2-S3CRET");
        assert!(!shown.contains("hunter2") && !shown.contains(&encoded), "{shown}");
        assert!(shown.contains("rdp-password") && shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn errors_never_carry_the_secret() {
        let e = brokered_material("web", &pw(None)).unwrap_err();
        assert!(!format!("{e:?}").contains("hunter2"));
        let e = brokered_material("ssh", &key("-----BEGIN OPENSSH PRIVATE KEY----- S3CRET-KEY")).unwrap_err();
        assert!(!format!("{e:?}").contains("S3CRET-KEY"));
    }
}
