//! Credential providers: the host half (spec features/self-accounts.md §4).
//!
//! Three things live here, none of which mentions any particular provider:
//!
//! * the attested **caller** block a `caller_identity` plugin receives;
//! * the **provider grant**, the second key next to the manifest's
//!   `[capabilities.credential_provider]`, pinned to that block's hash;
//! * the **bridge** that turns [`PluginHost`] provider calls into the
//!   `provider.candidates` / `provider.release` envelope ops. The ops are built
//!   only here: `build_envelope` maps the closed `Operation` enum and cannot
//!   produce them, so no HTTP request can invoke one.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::manifest::{CredentialProviderCap, PluginManifest};
use super::{invoke_active_plugin_scoped, InvokeOutcome, PluginCatalog};
use crate::{
    errors::RvError,
    kernel_api::{
        provider::{
            CallerIdentity, CredentialProviderDecl, ProviderCandidate, ProviderQuery,
            ProviderReleaseRequest, ReleasedCredential, ReleasedSecret,
        },
        VaultCtx,
    },
    logical::Request,
    storage::{Storage, StorageEntry},
};

// ── caller attestation ──────────────────────────────────────────────────

/// Build the caller block from the request's authenticated token. Nothing
/// in the request body is consulted. The token, its accessor and its
/// policies are never copied.
pub fn caller_from_request(req: &Request) -> CallerIdentity {
    let Some(auth) = req.auth.as_ref() else {
        return CallerIdentity::default();
    };
    let meta = |k: &str| auth.metadata.get(k).cloned().unwrap_or_default();
    let principal_name = {
        let u = meta("username");
        if u.is_empty() { meta("role_name") } else { u }
    };
    CallerIdentity {
        entity_id: meta("entity_id"),
        display_name: auth.display_name.clone(),
        principal_mount: meta("mount_path"),
        principal_name,
        namespace: req.namespace_path.clone().unwrap_or_default(),
    }
}

/// The wire form of the caller block (spec §4.2).
pub fn caller_json(c: &CallerIdentity) -> Value {
    json!({
        "entity_id": c.entity_id,
        "display_name": c.display_name,
        "principal": { "mount": c.principal_mount, "name": c.principal_name },
        "namespace": c.namespace,
    })
}

// ── provider grant ──────────────────────────────────────────────────────

/// Sibling prefix of the network grants (`core/plugins/engine/grants/<name>`).
/// It is a prefix of its own rather than `grants/<name>/credential-provider`
/// because a key and a "directory" of the same name cannot coexist on the
/// file backend, and the network grant record's format stays untouched.
const GRANT_PREFIX: &str = "core/plugins/engine/provider-grants/";

fn grant_key(name: &str) -> String {
    format!("{GRANT_PREFIX}{name}")
}

/// The admin approval of a plugin's credential-provider capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderGrant {
    pub granted_by: String,
    pub granted_at: String,
    /// SHA-256 (hex) of the manifest's `credential_provider` block at approval
    /// time. Any later change to that block, even a narrowing one, voids the
    /// grant until an admin re-approves.
    pub capability_sha256: String,
}

/// `Ok(None)` when never granted. An unparsable record is treated as absent
/// (fail closed).
pub async fn get_grant(storage: &dyn Storage, name: &str) -> Result<Option<ProviderGrant>, RvError> {
    match storage.get(&grant_key(name)).await? {
        None => Ok(None),
        Some(e) => Ok(serde_json::from_slice(&e.value).ok()),
    }
}

/// Approve `manifest`'s credential-provider capability. Refuses a plugin that
/// declares none: an unrequested capability can never be granted.
pub async fn put_grant(
    storage: &dyn Storage,
    manifest: &PluginManifest,
    granted_by: &str,
    granted_at: String,
) -> Result<ProviderGrant, RvError> {
    let cap = manifest.capabilities.credential_provider.as_ref().ok_or_else(|| {
        RvError::ErrString(format!(
            "plugin `{}` declares no credential_provider capability; nothing to grant",
            manifest.name
        ))
    })?;
    let grant = ProviderGrant {
        granted_by: granted_by.to_string(),
        granted_at,
        capability_sha256: cap.canonical_sha256(),
    };
    storage
        .put(&StorageEntry { key: grant_key(&manifest.name), value: serde_json::to_vec(&grant)? })
        .await?;
    Ok(grant)
}

/// Revoke. Idempotent.
pub async fn delete_grant(storage: &dyn Storage, name: &str) -> Result<(), RvError> {
    storage.delete(&grant_key(name)).await
}

/// The single "is this provider live?" gate: a grant exists and its pin
/// matches the active manifest's current block.
pub async fn grant_is_live(storage: &dyn Storage, manifest: &PluginManifest) -> bool {
    let Some(cap) = manifest.capabilities.credential_provider.as_ref() else {
        return false;
    };
    match get_grant(storage, &manifest.name).await {
        Ok(Some(g)) => g.capability_sha256 == cap.canonical_sha256(),
        _ => false,
    }
}

// ── bridge ──────────────────────────────────────────────────────────────

fn not_approved(provider: &str) -> RvError {
    RvError::ErrResponseStatus(
        403,
        format!("credential provider `{provider}` is not approved on this server"),
    )
}

/// Resolve `provider` to its active manifest iff it is a live, granted
/// credential provider. Fails closed with the same error for every reason
/// (unregistered, quarantined, undeclared, ungranted, stale pin), so a caller
/// cannot probe which plugins exist.
async fn live_provider(
    core: &Arc<dyn VaultCtx>,
    provider: &str,
) -> Result<(PluginManifest, CredentialProviderCap), RvError> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    if let Ok(Some(_)) = super::quarantine::lookup(storage, provider).await {
        return Err(not_approved(provider));
    }
    let record = PluginCatalog::new()
        .get(storage, provider)
        .await?
        .ok_or_else(|| not_approved(provider))?;
    let manifest = record.manifest;
    if !grant_is_live(storage, &manifest).await {
        return Err(not_approved(provider));
    }
    let cap = manifest
        .capabilities
        .credential_provider
        .clone()
        .ok_or_else(|| not_approved(provider))?;
    Ok((manifest, cap))
}

pub async fn credential_providers(core: &Arc<dyn VaultCtx>) -> Vec<CredentialProviderDecl> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    let manifests = PluginCatalog::new().list(storage).await.unwrap_or_default();
    let mut out = Vec::new();
    for m in manifests {
        if let Some(cap) = &m.capabilities.credential_provider {
            if grant_is_live(storage, &m).await
                && super::quarantine::lookup(storage, &m.name).await.ok().flatten().is_none()
            {
                out.push(CredentialProviderDecl {
                    plugin: m.name.clone(),
                    display_name: cap.display_name.clone(),
                    protocols: cap.protocols.clone(),
                    secret_kinds: cap.secret_kinds.clone(),
                });
            }
        }
    }
    out
}

/// One provider call: build the envelope, run the plugin under the caller's
/// entity scope, return the parsed `data` object.
async fn call_provider(
    core: &Arc<dyn VaultCtx>,
    provider: &str,
    caller: &CallerIdentity,
    op: &str,
    data: Value,
) -> Result<Value, RvError> {
    if caller.entity_id.is_empty() {
        return Err(RvError::ErrResponseStatus(
            403,
            "this plugin stores per-user data and needs an identity-backed login".to_string(),
        ));
    }
    let envelope = json!({ "op": op, "caller": caller_json(caller), "data": data });
    // The envelope for a release carries no secret; the *response* does.
    let input = serde_json::to_vec(&envelope)?;
    let output =
        invoke_active_plugin_scoped(core.clone(), provider, &input, Some(&caller.entity_id)).await?;
    let response = Zeroizing::new(output.response);
    if let InvokeOutcome::PluginError(code) = output.outcome {
        // Never echo the response body of a failed release: it is
        // plugin-controlled text on a secret-bearing path.
        return Err(RvError::ErrResponseStatus(
            if code == 2 { 404 } else { 400 },
            format!("credential provider `{provider}` refused the request"),
        ));
    }
    let parsed: Value = serde_json::from_slice(&response).map_err(|_| {
        RvError::ErrString(format!("credential provider `{provider}` returned invalid JSON"))
    })?;
    match parsed.get("data") {
        Some(d @ Value::Object(_)) => Ok(d.clone()),
        _ => Err(RvError::ErrString(format!(
            "credential provider `{provider}` returned no data"
        ))),
    }
}

pub async fn provider_candidates(
    core: &Arc<dyn VaultCtx>,
    provider: &str,
    caller: &CallerIdentity,
    query: &ProviderQuery,
) -> Result<Vec<ProviderCandidate>, RvError> {
    let (_m, cap) = live_provider(core, provider).await?;
    if !cap.protocols.iter().any(|p| p == &query.protocol) {
        return Err(RvError::ErrResponseStatus(
            400,
            format!("credential provider `{provider}` does not support protocol `{}`", query.protocol),
        ));
    }
    let data = call_provider(core, provider, caller, "provider.candidates", serde_json::to_value(query)?)
        .await?;
    let list = data.get("candidates").cloned().unwrap_or(Value::Array(vec![]));
    let mut cands: Vec<ProviderCandidate> = serde_json::from_value(list).map_err(|_| {
        RvError::ErrString(format!("credential provider `{provider}` returned malformed candidates"))
    })?;
    // Metadata only, and only kinds the provider declared and the protocol
    // can use. Anything else is dropped rather than shown to the operator.
    cands.retain(|c| {
        !c.id.is_empty()
            && !c.username.trim().is_empty()
            && cap.secret_kinds.iter().any(|k| k == &c.secret_kind)
            && !(c.secret_kind == "ssh-key" && query.protocol != "ssh")
    });
    Ok(cands)
}

pub async fn provider_release(
    core: &Arc<dyn VaultCtx>,
    provider: &str,
    caller: &CallerIdentity,
    req: &ProviderReleaseRequest,
) -> Result<ReleasedCredential, RvError> {
    let (_m, cap) = live_provider(core, provider).await?;
    if !cap.protocols.iter().any(|p| p == &req.protocol) {
        return Err(RvError::ErrResponseStatus(
            400,
            format!("credential provider `{provider}` does not support protocol `{}`", req.protocol),
        ));
    }
    let data = call_provider(core, provider, caller, "provider.release", serde_json::to_value(req)?)
        .await?;
    let cred = parse_released(provider, &data, req)?;
    cred.validate(&req.protocol, &cap.secret_kinds)
        .map_err(|e| RvError::ErrString(format!("credential provider `{provider}`: {e}")))?;
    Ok(cred)
}

/// Move a provider's `release` output into `Zeroizing` buffers. A TOTP seed
/// the recipe did not ask for is refused rather than discarded: the provider
/// is only supposed to return what `needs` names.
fn parse_released(
    provider: &str,
    data: &Value,
    req: &ProviderReleaseRequest,
) -> Result<ReleasedCredential, RvError> {
    let bad = |m: &str| RvError::ErrString(format!("credential provider `{provider}`: {m}"));
    let text = |v: Option<&Value>| v.and_then(|x| x.as_str()).map(|s| s.to_string());
    let username = text(data.get("username")).ok_or_else(|| bad("release has no username"))?;
    let domain = text(data.get("domain")).filter(|d| !d.is_empty());
    let secret = data.get("secret").ok_or_else(|| bad("release has no secret"))?;
    let secret = match text(secret.get("kind")).as_deref() {
        Some("password") => {
            let password = Zeroizing::new(
                text(secret.get("password")).ok_or_else(|| bad("release has no password"))?,
            );
            let totp_seed = text(secret.get("totp_seed")).map(Zeroizing::new);
            if totp_seed.is_some() && !req.needs.totp {
                return Err(bad("returned a TOTP seed that was not requested"));
            }
            ReleasedSecret::Password { password, totp_seed }
        }
        Some("ssh-key") => ReleasedSecret::SshKey {
            private_key: Zeroizing::new(
                text(secret.get("private_key")).ok_or_else(|| bad("release has no private key"))?,
            ),
        },
        _ => return Err(bad("release has an unknown secret kind")),
    };
    Ok(ReleasedCredential { username, domain, secret })
}

// ── entity lifecycle ────────────────────────────────────────────────────

/// Delete every key under `prefix`, recursively.
pub async fn delete_prefix(storage: &dyn Storage, prefix: &str) -> Result<(), RvError> {
    delete_tree(storage, prefix).await
}

async fn delete_tree(storage: &dyn Storage, prefix: &str) -> Result<(), RvError> {
    let mut stack = vec![prefix.to_string()];
    while let Some(p) = stack.pop() {
        for name in storage.list(&p).await? {
            match name.strip_suffix('/') {
                Some(dir) => stack.push(format!("{p}{dir}/")),
                None => storage.delete(&format!("{p}{name}")).await?,
            }
        }
    }
    Ok(())
}

/// Delete one entity's prefix under every plugin data scope. It walks
/// `core/plugins/` rather than the catalog, so the data of a deleted
/// (quarantined) plugin is purged too.
pub async fn purge_entity_data(core: &Arc<dyn VaultCtx>, entity_id: &str) -> Result<(), RvError> {
    let barrier = core.barrier();
    let storage = barrier.as_storage();
    // Same validation as the runtime's rebasing: the id is interpolated into
    // a storage path.
    if super::runtime::entity_data_root("x", entity_id).is_none() {
        return Err(RvError::ErrRequestInvalid);
    }
    for name in storage.list("core/plugins/").await? {
        let Some(plugin) = name.strip_suffix('/') else { continue };
        if plugin == "engine" {
            continue;
        }
        if let Some(root) = super::runtime::entity_data_root(plugin, entity_id) {
            delete_tree(storage, &root).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_api::provider::{
        ProviderConnectContext, ProviderNeeds, ProviderResource, ProviderTarget,
    };
    use crate::plugins::manifest::{
        CredentialProviderCap, ProviderSelection, RuntimeKind, StorageScope,
    };

    #[derive(Default)]
    struct MemStorage {
        inner: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError> {
            let g = self.inner.lock().unwrap();
            let mut out = std::collections::BTreeSet::new();
            for k in g.keys() {
                if let Some(rest) = k.strip_prefix(prefix) {
                    match rest.split_once('/') {
                        Some((d, _)) => out.insert(format!("{d}/")),
                        None => out.insert(rest.to_string()),
                    };
                }
            }
            Ok(out.into_iter().collect())
        }
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, RvError> {
            let g = self.inner.lock().unwrap();
            Ok(g.get(key).map(|v| StorageEntry { key: key.to_string(), value: v.clone() }))
        }
        async fn put(&self, entry: &StorageEntry) -> Result<(), RvError> {
            self.inner.lock().unwrap().insert(entry.key.clone(), entry.value.clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), RvError> {
            self.inner.lock().unwrap().remove(key);
            Ok(())
        }
    }

    fn manifest(protocols: &[&str]) -> PluginManifest {
        let mut m = PluginManifest {
            name: "self-accounts".into(),
            version: "1.0.0".into(),
            plugin_type: "secret-engine".into(),
            runtime: RuntimeKind::Wasm,
            abi_version: "1.3".into(),
            sha256: "0".repeat(64),
            size: 1,
            capabilities: Default::default(),
            description: String::new(),
            config_schema: vec![],
            signature: String::new(),
            signing_key: String::new(),
            surface: None,
            client_assets: vec![],
        };
        m.capabilities.caller_identity = true;
        m.capabilities.storage_scope = StorageScope::Entity;
        m.capabilities.credential_provider = Some(CredentialProviderCap {
            display_name: "Self-account".into(),
            selection: ProviderSelection::Operator,
            protocols: protocols.iter().map(|p| p.to_string()).collect(),
            secret_kinds: vec!["password".into()],
        });
        m
    }

    #[tokio::test]
    async fn grant_is_not_live_until_approved() {
        let s = MemStorage::default();
        let m = manifest(&["ssh"]);
        assert!(!grant_is_live(&s, &m).await);
        put_grant(&s, &m, "admin", "t".into()).await.unwrap();
        assert!(grant_is_live(&s, &m).await);
    }

    #[tokio::test]
    async fn narrowing_the_block_voids_the_grant() {
        let s = MemStorage::default();
        put_grant(&s, &manifest(&["ssh", "rdp"]), "admin", "t".into()).await.unwrap();
        assert!(!grant_is_live(&s, &manifest(&["ssh"])).await);
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_closes_the_gate() {
        let s = MemStorage::default();
        let m = manifest(&["ssh"]);
        put_grant(&s, &m, "admin", "t".into()).await.unwrap();
        delete_grant(&s, &m.name).await.unwrap();
        delete_grant(&s, &m.name).await.unwrap();
        assert!(!grant_is_live(&s, &m).await);
    }

    #[tokio::test]
    async fn refuses_to_grant_an_undeclared_capability() {
        let s = MemStorage::default();
        let mut m = manifest(&["ssh"]);
        m.capabilities.credential_provider = None;
        assert!(put_grant(&s, &m, "admin", "t".into()).await.is_err());
        assert!(!grant_is_live(&s, &m).await);
    }

    #[tokio::test]
    async fn network_grant_record_is_untouched() {
        let s = MemStorage::default();
        put_grant(&s, &manifest(&["ssh"]), "admin", "t".into()).await.unwrap();
        assert!(crate::plugins::grants::get(&s, "self-accounts").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_tree_removes_only_the_given_prefix() {
        let s = MemStorage::default();
        for k in [
            "core/plugins/p/data/entity/e1/accounts/a/meta",
            "core/plugins/p/data/entity/e1/accounts/a/secret",
            "core/plugins/p/data/entity/e2/accounts/a/meta",
            "core/plugins/p/data/other",
        ] {
            s.put(&StorageEntry { key: k.into(), value: vec![1] }).await.unwrap();
        }
        delete_tree(&s, "core/plugins/p/data/entity/e1/").await.unwrap();
        assert!(s.get("core/plugins/p/data/entity/e1/accounts/a/meta").await.unwrap().is_none());
        assert!(s.get("core/plugins/p/data/entity/e1/accounts/a/secret").await.unwrap().is_none());
        assert!(s.get("core/plugins/p/data/entity/e2/accounts/a/meta").await.unwrap().is_some());
        assert!(s.get("core/plugins/p/data/other").await.unwrap().is_some());
    }

    fn release_req(totp: bool) -> ProviderReleaseRequest {
        ProviderReleaseRequest {
            account_id: "sa_1".into(),
            protocol: "rdp".into(),
            resource: ProviderResource { resource_type: "server".into(), os_type: None },
            target: ProviderTarget::Host { host: "h".into(), port: 3389 },
            needs: ProviderNeeds { password: true, totp },
            connect: ProviderConnectContext { mfa_verified: true, transport: "direct".into() },
        }
    }

    #[test]
    fn parses_a_password_release() {
        let d = json!({"username":"u","domain":"CORP","secret":{"kind":"password","password":"pw"}});
        let c = parse_released("p", &d, &release_req(false)).unwrap();
        assert_eq!(c.username, "u");
        assert_eq!(c.domain.as_deref(), Some("CORP"));
        assert_eq!(c.secret.kind(), "password");
    }

    #[test]
    fn refuses_an_unrequested_totp_seed() {
        let d = json!({"username":"u","secret":{"kind":"password","password":"pw","totp_seed":"S"}});
        assert!(parse_released("p", &d, &release_req(false)).is_err());
        assert!(parse_released("p", &d, &release_req(true)).is_ok());
    }

    #[test]
    fn refuses_malformed_releases() {
        let r = release_req(false);
        for d in [
            json!({"secret":{"kind":"password","password":"x"}}),
            json!({"username":"u"}),
            json!({"username":"u","secret":{"kind":"pgp","password":"x"}}),
            json!({"username":"u","secret":{"kind":"password"}}),
            json!({"username":"u","secret":{"kind":"ssh-key"}}),
        ] {
            assert!(parse_released("p", &d, &r).is_err(), "{d}");
        }
    }

    #[test]
    fn a_failed_parse_error_does_not_echo_secret_text() {
        let d = json!({"username":"u","secret":{"kind":"pgp","password":"S3CRET-VALUE"}});
        let e = parse_released("p", &d, &release_req(false)).unwrap_err();
        assert!(!format!("{e:?}").contains("S3CRET-VALUE"));
    }

    #[test]
    fn caller_block_has_no_token_material() {
        let c = CallerIdentity {
            entity_id: "e".into(),
            display_name: "d".into(),
            principal_mount: "userpass/".into(),
            principal_name: "felipe".into(),
            namespace: "".into(),
        };
        let v = caller_json(&c);
        let keys: std::collections::BTreeSet<_> =
            v.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            ["display_name", "entity_id", "namespace", "principal"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
    }

    #[test]
    fn caller_comes_from_the_token_not_the_body() {
        let mut req = Request::default();
        let mut body = serde_json::Map::new();
        body.insert("entity_id".into(), json!("attacker"));
        body.insert("caller".into(), json!({"entity_id": "attacker"}));
        req.body = Some(body);
        // No auth → no identity, whatever the body claims.
        assert!(caller_from_request(&req).entity_id.is_empty());

        let mut auth = crate::logical::Auth::default();
        auth.metadata.insert("entity_id".into(), "real".into());
        auth.metadata.insert("username".into(), "felipe".into());
        auth.metadata.insert("mount_path".into(), "userpass/".into());
        auth.display_name = "userpass-felipe".into();
        req.auth = Some(auth);
        let c = caller_from_request(&req);
        assert_eq!(c.entity_id, "real");
        assert_eq!(c.principal_name, "felipe");
        assert_eq!(c.principal_mount, "userpass/");
    }
}
