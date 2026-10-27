//! Request handling for a `secret/dynamic` plugin mount.
//!
//! Routes: `creds/<role>` (read: generate), `rotate-root/<connection>`
//! (write), `config/...` and `roles/...` (proxied to the plugin), plus the
//! lease manager's renew and revoke. Every other path is refused. The host
//! generates the credential and expands the statements; the plugin only runs
//! them against its target and asks the host to lease the result.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bv_dynamic::{
    audit::{redact, Actor, DynamicEventKind, DynamicSecretEvent, EventOrigin},
    cache::{CacheKey, Read, MAX_CACHE_TTL},
    connector::ExecPlan,
    credential::{generate_password, generate_username, random_u64, rfc3339_utc},
    records::{
        check_name, DynamicLeaseInternal, RoleRecipe, LEASE_INTERNAL_KEY, LEASE_INTERNAL_VERSION,
        MAX_PLUGIN_INTERNAL_BYTES,
    },
    template::{render, sanitize_value, TemplateVars},
    DynamicError,
};
use serde_json::{json, Map, Value};
use zeroize::{Zeroize, Zeroizing};

use super::{
    cache::{self, Issued},
    pool::{host_pool, target_key},
    session::{DynamicSession, DynamicVerb},
    state,
};
use crate::{
    errors::RvError,
    kernel_api::{auth::MAX_LEASE_DURATION_SECS, provider::CallerIdentity, VaultCtx},
    logical::{lease::Lease, secret::SecretData, Operation, Request, Response},
    modules::auth::expiration::{HOST_MANAGED_LEASE_SLOT, HOST_MANAGED_SECRET_TYPE},
    plugins::{
        logical_backend::{build_envelope, invoke_record, translate_response},
        runtime::{InvokeOutcome, InvokeOutput},
        PluginRecord,
    },
    storage::Storage,
};

/// Keys of a generated credential's response the plugin cannot override.
const RESERVED_DATA_KEYS: [&str; 5] = ["username", "password", "lease_id", "lease_duration", "renewable"];

/// One request against a dynamic mount: the plugin it resolved to.
pub struct DynamicCall<'a> {
    pub core: &'a Arc<dyn VaultCtx>,
    pub record: &'a PluginRecord,
    pub config: &'a BTreeMap<String, String>,
}

impl DynamicCall<'_> {
    fn name(&self) -> &str {
        &self.record.manifest.name
    }

    fn event(&self, kind: DynamicEventKind) -> DynamicSecretEvent {
        let m = &self.record.manifest;
        DynamicSecretEvent::new(kind, EventOrigin::Host, m.engine_type.as_deref().unwrap_or(""), &m.name, &m.version)
    }

    /// Run one host-to-plugin call and return what the plugin answered.
    async fn invoke_output(&self, envelope: &Value, session: &Arc<DynamicSession>) -> Result<InvokeOutput, RvError> {
        // The generate envelope carries the password: wipe its bytes after use.
        let input = Zeroizing::new(serde_json::to_vec(envelope)?);
        let started = std::time::Instant::now();
        let m = &self.record.manifest;
        let result = invoke_record(
            self.name(),
            m,
            &self.record.binary,
            &input,
            self.core.clone(),
            self.config.clone(),
            None,
            // The dynamic host never runs a plugin on a caller's behalf: the
            // ABI 1.4 caller-bound host calls stay refused here.
            None,
            Some(session.clone()),
        )
        .await;
        let elapsed = started.elapsed().as_secs_f64();
        let output = match result {
            Ok(o) => o,
            Err(e) => {
                crate::plugins::metrics::record_invoke(self.name(), "runtime_error", elapsed, 0);
                return Err(e);
            }
        };
        let label = match output.outcome {
            InvokeOutcome::Success => "success",
            InvokeOutcome::PluginError(_) => "plugin_error",
        };
        crate::plugins::metrics::record_invoke(self.name(), label, elapsed, output.fuel_consumed);
        if session.violated() {
            return Err(RvError::ErrResponseStatus(
                502,
                format!(
                    "plugin `{}` made a host call its manifest does not declare and has been quarantined",
                    self.name()
                ),
            ));
        }
        Ok(output)
    }

    /// [`Self::invoke_output`] for a dynamic RPC verb: the plugin's JSON reply,
    /// or a `502` naming its failure with this call's secrets redacted.
    async fn invoke(&self, envelope: &Value, session: &Arc<DynamicSession>) -> Result<Value, RvError> {
        let output = self.invoke_output(envelope, session).await?;
        let owned = session.secrets();
        let secrets = owned.refs();
        if let InvokeOutcome::PluginError(code) = output.outcome {
            let raw = serde_json::from_slice::<Value>(&output.response)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&output.response).into_owned());
            return Err(RvError::ErrResponseStatus(
                502,
                format!(
                    "plugin `{}` failed {} (status {code}): {}",
                    self.name(),
                    session.verb.op(),
                    redact(&raw, &secrets)
                ),
            ));
        }
        if output.response.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&output.response).map_err(|_| {
            RvError::ErrResponseStatus(
                502,
                format!("plugin `{}` answered {} with invalid JSON", self.name(), session.verb.op()),
            )
        })
    }
}

/// Zero every string in `value` (the rendered statements and the credential
/// of a generate envelope both hold the password).
fn wipe_strings(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        Value::Object(map) => map.values_mut().for_each(wipe_strings),
        _ => {}
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn mount_storage(req: &Request) -> Result<Arc<dyn Storage>, RvError> {
    req.storage.clone().ok_or(RvError::ErrBarrierSealed)
}

fn bad_request(msg: impl Into<String>) -> RvError {
    RvError::ErrResponseStatus(400, msg.into())
}

/// The build a cached credential is tied to: a different active version or
/// binary (on any node) makes its entries misses.
fn plugin_build(m: &crate::plugins::manifest::PluginManifest) -> String {
    format!("{}@{}#{}", m.name, m.version, m.sha256)
}

/// Remove the cluster-wide cache marker of a lease being renewed or revoked.
/// Failing it fails the operation (a revoke is then kept `revoke_failed` and
/// retried): other nodes would otherwise keep serving the credential.
async fn forget_cached(storage: &dyn Storage, internal: &DynamicLeaseInternal) -> Result<(), RvError> {
    cache::invalidate_credential(&internal.username);
    if !internal.cached {
        return Ok(());
    }
    cache::forget_credential(storage, &internal.username).await.map_err(|e| {
        RvError::ErrResponseStatus(
            503,
            format!(
                "the credential cache marker of `{}` could not be removed ({e}); nothing was changed on the target",
                internal.username
            ),
        )
    })
}

/// After an attempted change that may have altered what cached credentials
/// were made under: a new epoch, then the change's own result. When both
/// failed, the change's error wins and the epoch's is logged.
async fn settle_cache_epoch<T>(
    storage: &dyn Storage,
    mount_id: &str,
    what: &str,
    result: Result<T, RvError>,
) -> Result<T, RvError> {
    let bumped = bump_cache_epoch(storage, mount_id, what).await;
    match (result, bumped) {
        (Ok(v), Ok(())) => Ok(v),
        (Ok(_), Err(e)) => Err(e),
        (Err(e), Ok(())) => Err(e),
        (Err(e), Err(epoch)) => {
            log::warn!("{epoch}");
            Err(e)
        }
    }
}

/// `Some(None)` when `body` clears `key` (`null`), `Some(Some(v))` when it
/// sets a string, `None` when it leaves `key` as stored (absent, or a type
/// the plugin will refuse anyway).
fn written_string(body: &Map<String, Value>, key: &str) -> Option<Option<String>> {
    match body.get(key) {
        Some(Value::Null) => Some(None),
        Some(Value::String(s)) => Some(Some(s.clone())),
        _ => None,
    }
}

/// After a role write, config write or rotate-root: a new cache epoch.
async fn bump_cache_epoch(storage: &dyn Storage, mount_id: &str, what: &str) -> Result<(), RvError> {
    cache::bump_epoch(storage, mount_id).await.map_err(|e| {
        RvError::ErrResponseStatus(
            503,
            format!(
                "{what} succeeded, but the credential cache epoch could not be advanced ({e}); other nodes may \
                 serve credentials cached before it for up to {} s",
                MAX_CACHE_TTL.as_secs()
            ),
        )
    })
}

/// A fresh session for one call, stamped with what the host knows.
fn session(verb: DynamicVerb, mount_id: &str, storage: &Arc<dyn Storage>, req: &Request) -> DynamicSession {
    let caller = CallerIdentity::from_request(req);
    let mut s = DynamicSession::new(verb, mount_id, Some(storage.clone()));
    s.actor = Some(Actor { entity_id: caller.entity_id, display_name: caller.display_name });
    s.request_id = (!req.id.is_empty()).then(|| req.id.clone());
    s
}

/// Serve one request on a dynamic mount.
pub async fn handle(call: DynamicCall<'_>, req: &mut Request) -> Result<Option<Response>, RvError> {
    match req.operation {
        Operation::Revoke => return revoke(&call, req).await,
        Operation::Renew => return renew(&call, req).await,
        _ => {}
    }
    let path = req.path.trim_start_matches('/').to_string();
    let (head, rest) = path.split_once('/').unwrap_or((path.as_str(), ""));
    match (head, req.operation) {
        ("creds", Operation::Read) if !rest.is_empty() => generate(&call, req, rest).await,
        ("rotate-root", Operation::Write) if !rest.is_empty() => rotate_root(&call, req, rest).await,
        ("config", _) => config(&call, req, rest).await,
        ("roles", op) => {
            // Cache entries are looked up before the role is read: a changed
            // role must not keep serving credentials made under the old one,
            // here (dropped now) or on another node (new epoch after the write).
            let rewrites = matches!(op, Operation::Write | Operation::Delete) && !rest.is_empty();
            let storage = mount_storage(req)?;
            let mount_id = state::mount_id(storage.as_ref()).await?;
            if !rewrites {
                return proxy(&call, req, None).await;
            }
            cache::invalidate_role(&mount_id, rest);
            // Bumped whether or not the plugin reports success: a failed
            // write may still have changed the stored role.
            let resp = proxy(&call, req, None).await;
            settle_cache_epoch(storage.as_ref(), &mount_id, &format!("writing role `{rest}`"), resp).await
        }
        _ => Err(RvError::ErrResponseStatus(
            404,
            format!("`{path}` is not a dynamic-secrets path (config/, roles/, creds/<role>, rotate-root/<connection>)"),
        )),
    }
}

async fn generate(call: &DynamicCall<'_>, req: &Request, role: &str) -> Result<Option<Response>, RvError> {
    check_name("role", role)?;
    let storage = mount_storage(req)?;
    let mount_id = state::mount_id(storage.as_ref()).await?;
    let caller = CallerIdentity::from_request(req);
    let manifest = &call.record.manifest;

    // 0. A cached credential of this identity, if its role opted in; then
    // the namespace's lease quota, before anything exists on the target.
    let cache_key = CacheKey::new(&mount_id, role, &caller.entity_id);
    let build = plugin_build(manifest);
    if let Some(hit) = match &cache_key {
        Some(key) => serve_cached(call, req, storage.as_ref(), key, &build).await,
        None => None,
    } {
        return Ok(Some(hit));
    }
    // The epoch a new entry is checked against, read *before* the role: a
    // role write that lands after this read bumps it and refuses the entry.
    let epoch = match &cache_key {
        Some(_) => cache::read_epoch(storage.as_ref()).await,
        None => Read::Absent,
    };
    let leases = call.core.lease_revoker().ok_or_else(|| {
        RvError::ErrResponseStatus(503, "the lease manager is unavailable; no credential was created".into())
    })?;
    leases.check_lease_quota(req.namespace_path.as_deref().unwrap_or("")).await?;

    // 1. The role, as the plugin stores it. Templates are checked here.
    let mut s = session(DynamicVerb::Role, &mount_id, &storage, req);
    s.role = Some(role.to_string());
    let reply = call.invoke(&json!({ "op": DynamicVerb::Role.op(), "role": role }), &Arc::new(s)).await?;
    let recipe: RoleRecipe = match reply.get("data") {
        None | Some(Value::Null) => {
            return Err(RvError::ErrResponseStatus(404, format!("role `{role}` does not exist on this mount")))
        }
        Some(data) => serde_json::from_value(data.clone()).map_err(|e| {
            RvError::ErrResponseStatus(
                502,
                format!("plugin `{}` described role `{role}` malformedly: {e}", call.name()),
            )
        })?,
    };
    recipe.validate()?;

    // 2. The credential: generated and templated here, never by the plugin.
    let now = unix_now();
    let ttl = recipe.initial_ttl(MAX_LEASE_DURATION_SECS);
    let username = generate_username(&caller.display_name, role, now, recipe.username_max_len)?;
    let password = generate_password()?;
    let expiration = rfc3339_utc(now + ttl.as_secs());
    let display = sanitize_value(&caller.display_name, 64);
    let entity = sanitize_value(&caller.entity_id, 64);
    let vars = TemplateVars {
        name: &username,
        password: password.expose(),
        expiration: &expiration,
        role,
        display_name: &display,
        entity_id: &entity,
    };
    let render_all = |list: &[String]| -> Result<Vec<String>, DynamicError> {
        list.iter().map(|t| render(t, &vars).map_err(DynamicError::from)).collect()
    };
    let mut creation = render_all(&recipe.creation_statements)?;
    let revocation = render_all(&recipe.revocation_statements)?;

    // 3. The plugin creates the identity and asks for its lease.
    // The plan is the only thing a plugin can have the host execute.
    let plan = ExecPlan::Create { statements: creation.iter().map(|c| Zeroizing::new(c.clone())).collect() };
    let mut s = session(DynamicVerb::Generate, &mount_id, &storage, req).with_secret(password.expose()).with_plan(plan);
    s.role = Some(role.to_string());
    s.connection = Some(recipe.connection.clone());
    s.target_identity = Some(username.clone());
    let gen_session = Arc::new(s);
    let mut envelope = json!({
        "op": DynamicVerb::Generate.op(),
        "role": role,
        "connection": recipe.connection,
        "statements": creation,
        "credential": { "username": username, "password": password.expose(), "expiration": expiration },
        "ttl_secs": ttl.as_secs(),
    });
    creation.iter_mut().for_each(Zeroize::zeroize);
    let result = call.invoke(&envelope, &gen_session).await;
    wipe_strings(&mut envelope);
    let lease_request = gen_session.take_lease_request();
    let (reply, lease_request) = match (result, lease_request) {
        (Ok(reply), Some(lr)) => (reply, lr),
        (result, registered) => {
            // No lease came out of it, yet the identity may exist (the plugin
            // failed half-way, timed out, or claimed success without a lease):
            // take it back. After a manifest violation the quarantined plugin
            // is not called again, so the identity is reported instead.
            let orphan = Orphan { role, connection: &recipe.connection, username: &username, revocation: &revocation };
            if gen_session.violated() {
                report_abandoned(call, &orphan, &gen_session).await;
            } else {
                let internal = registered.map(|r| r.internal).unwrap_or(Value::Null);
                compensate(call, req, &mount_id, &storage, orphan, internal, password.expose()).await;
            }
            return Err(match result {
                Err(e) => e,
                Ok(_) => RvError::ErrResponseStatus(
                    502,
                    format!(
                        "plugin `{}` reported success without registering a lease; the credential was \
                         revoked (the host owns every lease)",
                        call.name()
                    ),
                ),
            });
        }
    };

    // 4. The lease: the plugin's lifetimes, never beyond the role's.
    let lease_ttl = match lease_request.ttl_secs {
        0 => ttl,
        s => Duration::from_secs(s).min(ttl),
    };
    let max_ttl_secs = match (lease_request.max_ttl_secs, recipe.max_ttl_secs) {
        (0, r) => r,
        (p, 0) => p,
        (p, r) => p.min(r),
    };
    let renewable = lease_request.renewable && recipe.renewable;

    let mut data = Map::new();
    if let Some(Value::Object(extra)) = reply.get("data") {
        for (k, v) in extra {
            if !RESERVED_DATA_KEYS.contains(&k.as_str()) {
                data.insert(k.clone(), v.clone());
            }
        }
    }
    data.insert("username".into(), Value::String(username.clone()));
    data.insert("password".into(), Value::String(password.expose().to_string()));

    // 5. The cache, if the role opted in: its marker is written first, so
    // every node can refuse the entry later. The kernel writes the lease id
    // into the slot once it registered the lease; until then nothing is served.
    let mut cached = false;
    if let (Some(key), true) = (cache_key, recipe.cache_ttl_secs > 0) {
        let connection = &recipe.connection;
        // As the kernel will clamp it: never past the lease's max_ttl.
        let lease_ttl = match max_ttl_secs {
            0 => lease_ttl,
            m => lease_ttl.min(Duration::from_secs(m)),
        };
        let issued = Issued {
            data: &data,
            lease_ttl,
            renewable,
            plugin: &manifest.name,
            plugin_build: &build,
            role,
            connection,
            username: &username,
        };
        let window = Duration::from_secs(recipe.cache_ttl_secs);
        if let Some(slot) = cache::node().remember(storage.as_ref(), key, issued, window, &epoch).await {
            req.ctx.set_mut(HOST_MANAGED_LEASE_SLOT, slot);
            cached = true;
        }
    }

    let internal = DynamicLeaseInternal {
        v: LEASE_INTERNAL_VERSION,
        plugin: manifest.name.clone(),
        plugin_version: manifest.version.clone(),
        engine_type: manifest.engine_type.clone().unwrap_or_default(),
        role: role.to_string(),
        connection: recipe.connection.clone(),
        username: username.clone(),
        revocation_statements: revocation,
        renew_statements: recipe.renew_statements.clone(),
        max_ttl_secs,
        plugin_internal: lease_request.internal,
        cached,
    };
    let mut lease = Lease::default();
    lease.ttl = lease_ttl;
    lease.max_ttl = Duration::from_secs(max_ttl_secs);
    lease.renewable = renewable;
    let mut internal_data = Map::new();
    internal_data.insert("secret_type".into(), Value::String(HOST_MANAGED_SECRET_TYPE.into()));
    internal_data.insert(LEASE_INTERNAL_KEY.into(), internal.to_value());

    let mut event = call.event(DynamicEventKind::Generate);
    event.role = Some(role.to_string());
    event.connection = Some(recipe.connection.clone());
    event.target_identity = Some(username);
    event.expires_at = Some(rfc3339_utc(now + lease_ttl.as_secs()));
    event.ttl_secs = Some(lease_ttl.as_secs());
    event.actor = gen_session.actor.clone();
    event.request_id.clone_from(&gen_session.request_id);
    super::emit_event(Some(call.core.as_ref()), &event).await;

    Ok(Some(Response {
        data: Some(data),
        secret: Some(SecretData { lease, lease_id: String::new(), internal_data }),
        ..Default::default()
    }))
}

/// A cache hit: the credential of an earlier request of this identity and
/// the lease it already has. No `secret` (so the kernel registers no second
/// lease), no plugin call, nothing minted; the lease is named in `data`.
async fn serve_cached(
    call: &DynamicCall<'_>,
    req: &Request,
    storage: &dyn Storage,
    key: &CacheKey,
    build: &str,
) -> Option<Response> {
    let (entry, lease_id) = cache::node().lookup(storage, key, build).await?;
    let mut data = entry.data()?;
    let remaining = entry.lease_remaining(std::time::Instant::now()).as_secs();
    data.insert("lease_id".into(), Value::String(lease_id.clone()));
    data.insert("lease_duration".into(), Value::from(remaining));
    data.insert("renewable".into(), Value::Bool(entry.renewable));

    let caller = CallerIdentity::from_request(req);
    let mut event = call.event(DynamicEventKind::CacheHit);
    event.lease_id = Some(lease_id);
    event.role = Some(entry.role.clone());
    event.connection = Some(entry.connection.clone());
    event.target_identity = Some(entry.username.clone());
    event.ttl_secs = Some(remaining);
    event.actor = Some(Actor { entity_id: caller.entity_id, display_name: caller.display_name });
    event.request_id = (!req.id.is_empty()).then(|| req.id.clone());
    super::emit_event(Some(call.core.as_ref()), &event).await;

    let warning = "served from the credential cache: this is the credential and lease (data.lease_id) an earlier \
                   request of the same identity received";
    Some(Response { data: Some(data), warnings: vec![warning.to_string()], ..Default::default() })
}

/// An identity the plugin may have created without a lease to show for it.
struct Orphan<'a> {
    role: &'a str,
    connection: &'a str,
    username: &'a str,
    revocation: &'a [String],
}

/// The plugin was quarantined during `generate` and is not called again, so
/// an identity it may have created cannot be revoked: name it (never the
/// password) at ERROR and as a `revoke_failed` event for an operator.
async fn report_abandoned(call: &DynamicCall<'_>, orphan: &Orphan<'_>, gen: &DynamicSession) {
    log::error!(
        "plugin `{}` was quarantined while generating a credential for role `{}` and is not called again; target \
         identity `{}` on connection `{}` may exist without a lease: remove it by hand",
        call.name(),
        orphan.role,
        orphan.username,
        orphan.connection
    );
    let mut event = call.event(DynamicEventKind::RevokeFailed);
    event.role = Some(orphan.role.to_string());
    event.connection = Some(orphan.connection.to_string());
    event.target_identity = Some(orphan.username.to_string());
    event.actor.clone_from(&gen.actor);
    event.request_id.clone_from(&gen.request_id);
    let why = "the plugin made a host call its manifest does not declare and was quarantined before the credential \
               could be revoked";
    super::emit_event(Some(call.core.as_ref()), &event.with_error(why, &[])).await;
}

/// Best-effort revoke of an [`Orphan`]. A failure is logged at ERROR with the
/// identity (never the password) and audited as `revoke_failed`, because no
/// lease exists for the reaper to retry. `password` is redacted from both.
async fn compensate(
    call: &DynamicCall<'_>,
    req: &Request,
    mount_id: &str,
    storage: &Arc<dyn Storage>,
    orphan: Orphan<'_>,
    internal: Value,
    password: &str,
) {
    let plan = ExecPlan::Revoke { statements: orphan.revocation.to_vec(), username: orphan.username.to_string() };
    let mut s = session(DynamicVerb::Revoke, mount_id, storage, req).with_secret(password).with_plan(plan);
    s.role = Some(orphan.role.to_string());
    s.connection = Some(orphan.connection.to_string());
    s.target_identity = Some(orphan.username.to_string());
    let envelope = json!({
        "op": DynamicVerb::Revoke.op(),
        "role": orphan.role,
        "connection": orphan.connection,
        "username": orphan.username,
        "statements": orphan.revocation,
        "internal": internal,
    });
    let outcome = call.invoke(&envelope, &Arc::new(s)).await;
    let mut event = call.event(if outcome.is_ok() { DynamicEventKind::Revoke } else { DynamicEventKind::RevokeFailed });
    event.role = Some(orphan.role.to_string());
    event.connection = Some(orphan.connection.to_string());
    event.target_identity = Some(orphan.username.to_string());
    if let Err(e) = &outcome {
        let error = redact(&e.to_string(), &[password]);
        log::error!(
            "plugin `{}` left target identity `{}` on connection `{}` without a lease and revoking it failed; \
             remove it by hand: {error}",
            call.name(),
            orphan.username,
            orphan.connection
        );
        event = event.with_error(&error, &[password]);
    }
    super::emit_event(Some(call.core.as_ref()), &event).await;
}

/// The lease and its host record, from a renew or revoke request.
fn lease_of(req: &Request) -> Result<(SecretData, DynamicLeaseInternal), RvError> {
    let secret = req.secret.clone().ok_or_else(|| bad_request("no lease accompanies this request"))?;
    let internal = DynamicLeaseInternal::from_internal_data(&secret.internal_data)?;
    Ok((secret, internal))
}

async fn renew(call: &DynamicCall<'_>, req: &Request) -> Result<Option<Response>, RvError> {
    let (secret, mut internal) = lease_of(req)?;
    let storage = mount_storage(req)?;
    // A renewal moves (or fails to move) the expiry a cached copy was sized
    // to: no node serves it again. The marker is gone, so the row says so.
    forget_cached(storage.as_ref(), &internal).await?;
    internal.cached = false;
    let mount_id = state::mount_id(storage.as_ref()).await?;
    let now = SystemTime::now();

    let requested = match (secret.increment.is_zero(), secret.ttl.is_zero()) {
        (false, _) => secret.increment,
        (true, false) => secret.ttl,
        (true, true) => Duration::from_secs(3600),
    };
    // `{{expiration}}` never names a moment past the lease's own ceiling.
    let ceiling = match (internal.max_ttl_secs, secret.issue_time) {
        (0, _) | (_, None) => MAX_LEASE_DURATION_SECS,
        (m, Some(issued)) => (issued + Duration::from_secs(m)).duration_since(now).unwrap_or(Duration::ZERO),
    };
    let new_ttl = requested.min(ceiling).min(MAX_LEASE_DURATION_SECS);
    if new_ttl.is_zero() {
        return Err(bad_request("this lease has reached its max_ttl and cannot be renewed"));
    }
    let now_secs = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let expiration = rfc3339_utc(now_secs + new_ttl.as_secs());
    let vars = TemplateVars {
        name: &internal.username,
        password: "",
        expiration: &expiration,
        role: &internal.role,
        display_name: "",
        entity_id: "",
    };
    let statements: Vec<String> = internal
        .renew_statements
        .iter()
        .map(|t| render(t, &vars).map_err(DynamicError::from))
        .collect::<Result<_, _>>()?;

    let plan = ExecPlan::Renew {
        statements: statements.clone(),
        username: internal.username.clone(),
        expiration: expiration.clone(),
    };
    let mut s = session(DynamicVerb::Renew, &mount_id, &storage, req).with_plan(plan);
    s.role = Some(internal.role.clone());
    s.connection = Some(internal.connection.clone());
    s.target_identity = Some(internal.username.clone());
    let s = Arc::new(s);
    let envelope = json!({
        "op": DynamicVerb::Renew.op(),
        "role": internal.role,
        "connection": internal.connection,
        "username": internal.username,
        "statements": statements,
        "expiration": expiration,
        "ttl_secs": new_ttl.as_secs(),
        "internal": internal.plugin_internal,
    });
    let reply = call.invoke(&envelope, &s).await?;
    if let Some(updated) = reply.get("data").and_then(|d| d.get("internal")) {
        let size = serde_json::to_vec(updated).map(|v| v.len()).unwrap_or(usize::MAX);
        if size > MAX_PLUGIN_INTERNAL_BYTES {
            return Err(RvError::ErrResponseStatus(
                502,
                format!("plugin `{}` returned an oversized internal blob", call.name()),
            ));
        }
        internal.plugin_internal = updated.clone();
    }

    let mut event = call.event(DynamicEventKind::Renew);
    event.role = Some(internal.role.clone());
    event.connection = Some(internal.connection.clone());
    event.target_identity = Some(internal.username.clone());
    event.expires_at = Some(expiration);
    event.ttl_secs = Some(new_ttl.as_secs());
    event.actor = s.actor.clone();
    event.request_id.clone_from(&s.request_id);
    super::emit_event(Some(call.core.as_ref()), &event).await;

    let mut lease = Lease::default();
    lease.ttl = new_ttl;
    lease.renewable = secret.renewable;
    let mut internal_data = secret.internal_data.clone();
    internal_data.insert(LEASE_INTERNAL_KEY.into(), internal.to_value());
    Ok(Some(Response {
        secret: Some(SecretData { lease, lease_id: String::new(), internal_data }),
        ..Default::default()
    }))
}

async fn revoke(call: &DynamicCall<'_>, req: &Request) -> Result<Option<Response>, RvError> {
    let (secret, internal) = lease_of(req)?;
    let storage = mount_storage(req)?;
    let mount_id = state::mount_id(storage.as_ref()).await?;
    let plan =
        ExecPlan::Revoke { statements: internal.revocation_statements.clone(), username: internal.username.clone() };
    let mut s = session(DynamicVerb::Revoke, &mount_id, &storage, req).with_plan(plan);
    // The kernel's take-back of an unregistered lease still has the issued
    // data: the password then only serves to redact the plugin's error.
    if let Some(password) = req.data.as_ref().and_then(|d| d.get("password")).and_then(Value::as_str) {
        s = s.with_secret(password);
    }
    s.role = Some(internal.role.clone());
    s.connection = Some(internal.connection.clone());
    s.target_identity = Some(internal.username.clone());
    s.lease_id = (!secret.lease_id.is_empty()).then(|| secret.lease_id.clone());
    let s = Arc::new(s);
    let envelope = json!({
        "op": DynamicVerb::Revoke.op(),
        "role": internal.role,
        "connection": internal.connection,
        "username": internal.username,
        "statements": internal.revocation_statements,
        "internal": internal.plugin_internal,
    });
    // No node may serve the credential once its revoke has begun; if that
    // cannot be ensured the revoke fails here and the lease manager retries.
    let outcome = match forget_cached(storage.as_ref(), &internal).await {
        Ok(()) => call.invoke(&envelope, &s).await,
        Err(e) => Err(e),
    };
    let kind = if outcome.is_ok() { DynamicEventKind::Revoke } else { DynamicEventKind::RevokeFailed };
    let mut event = call.event(kind);
    event.lease_id.clone_from(&s.lease_id);
    event.role = Some(internal.role.clone());
    event.connection = Some(internal.connection.clone());
    event.target_identity = Some(internal.username.clone());
    if let Err(e) = &outcome {
        event = event.with_error(&e.to_string(), &s.secrets().refs());
    }
    super::emit_event(Some(call.core.as_ref()), &event).await;
    outcome.map(|_| None)
}

/// Audit a dynamic lease whose revoke could not even reach its plugin (the
/// plugin is quarantined or no longer registered): every `generate` is paired
/// with a `revoke` or a `revoke_failed`.
pub async fn audit_unreachable_revoke(core: &dyn VaultCtx, plugin: &str, req: &Request, error: &RvError) {
    let Some(secret) = req.secret.as_ref() else {
        return;
    };
    let Ok(internal) = DynamicLeaseInternal::from_internal_data(&secret.internal_data) else {
        return;
    };
    // Best effort: this lease's mount is refused before the cache anyway
    // while its plugin is unreachable, and the retry removes the marker.
    match req.storage.as_ref() {
        Some(storage) => {
            if let Err(e) = forget_cached(storage.as_ref(), &internal).await {
                log::warn!("{e}");
            }
        }
        None => {
            cache::invalidate_credential(&internal.username);
        }
    }
    let mut event = DynamicSecretEvent::new(
        DynamicEventKind::RevokeFailed,
        EventOrigin::Host,
        &internal.engine_type,
        plugin,
        &internal.plugin_version,
    );
    event.lease_id = (!secret.lease_id.is_empty()).then(|| secret.lease_id.clone());
    event.role = Some(internal.role);
    event.connection = Some(internal.connection);
    event.target_identity = Some(internal.username);
    let password = req.data.as_ref().and_then(|d| d.get("password")).and_then(Value::as_str);
    let event = event.with_error(&error.to_string(), &password.into_iter().collect::<Vec<_>>());
    super::emit_event(Some(core), &event).await;
}

async fn rotate_root(call: &DynamicCall<'_>, req: &Request, connection: &str) -> Result<Option<Response>, RvError> {
    check_name("connection", connection)?;
    let storage = mount_storage(req)?;
    let mount_id = state::mount_id(storage.as_ref()).await?;
    let mut record = state::load_connection(storage.as_ref(), connection).await?.ok_or_else(|| {
        RvError::ErrResponseStatus(404, format!("connection `{connection}` is not configured on this mount"))
    })?;
    // The new root secret is generated here, like every credential the host
    // hands to a plugin; the plugin sets it on the target and stores it.
    let password = generate_password()?;
    let mut s = session(DynamicVerb::RotateRoot, &mount_id, &storage, req).with_secret(password.expose());
    s.connection = Some(connection.to_string());
    let s = Arc::new(s);
    let mut envelope = json!({
        "op": DynamicVerb::RotateRoot.op(),
        "connection": connection,
        "credential": { "password": password.expose() },
    });
    let result = call.invoke(&envelope, &s).await;
    wipe_strings(&mut envelope);
    // Attempted or done, the root changed hands: drop what was cached under
    // it, on every node. Reported after the rotation is recorded.
    let epoch = bump_cache_epoch(storage.as_ref(), &mount_id, &format!("rotating the root of `{connection}`")).await;
    result?;

    record.root_credential_version += 1;
    state::save_connection(storage.as_ref(), connection, &record).await?;
    let drained = host_pool().rotate(&target_key(&mount_id, connection), record.root_credential_version).unwrap_or(0);
    log::info!(
        "dynamic mount connection `{connection}`: root credential rotated to version {}, {drained} idle pool slot(s) drained",
        record.root_credential_version
    );

    let mut event = call.event(DynamicEventKind::RotateRoot);
    event.connection = Some(connection.to_string());
    event.actor = s.actor.clone();
    event.request_id.clone_from(&s.request_id);
    super::emit_event(Some(call.core.as_ref()), &event).await;
    epoch?;

    // Only host fields: whatever the plugin answered may name the new root.
    let mut data = Map::new();
    data.insert("connection".into(), Value::String(connection.to_string()));
    data.insert("root_credential_version".into(), Value::from(record.root_credential_version));
    Ok(Some(Response::data_response(Some(data))))
}

fn take_bool(body: &mut Map<String, Value>, key: &str) -> Result<Option<bool>, RvError> {
    match body.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(b)),
        Some(Value::String(s)) if s == "true" => Ok(Some(true)),
        Some(Value::String(s)) if s == "false" => Ok(Some(false)),
        Some(_) => Err(bad_request(format!("`{key}` must be a boolean"))),
    }
}

/// `config/<name>`: the host keeps the TLS policy (`insecure_skip_tls_verify`,
/// `tls_ca_pem`) itself and strips it from what the plugin receives, so the
/// pool grant is the plugin's only source for it.
async fn config(call: &DynamicCall<'_>, req: &Request, name: &str) -> Result<Option<Response>, RvError> {
    if name.is_empty() {
        return proxy(call, req, None).await;
    }
    check_name("connection", name)?;
    let storage = mount_storage(req)?;
    match req.operation {
        Operation::Write => {
            let mut body = req.body.clone().unwrap_or_default();
            let insecure = take_bool(&mut body, "insecure_skip_tls_verify")?;
            let ca = match body.remove("tls_ca_pem") {
                None | Some(Value::Null) => None,
                Some(Value::String(pem)) if pem.is_empty() || pem.contains("-----BEGIN CERTIFICATE-----") => Some(pem),
                Some(_) => return Err(bad_request("`tls_ca_pem` must be a PEM certificate bundle")),
            };
            // The endpoint the host pins (non-secret): a host execution dials
            // only what the operator wrote here and the plugin accepted.
            let pin_url = written_string(&body, "connection_url");
            let pin_user = written_string(&body, "username");
            let mount_id = state::mount_id(storage.as_ref()).await?;
            let what = format!("writing config/{name}");
            let resp = match proxy(call, req, Some(body)).await {
                Ok(resp) => resp,
                Err(e) => return settle_cache_epoch(storage.as_ref(), &mount_id, &what, Err(e)).await,
            };
            let mut record = state::load_connection(storage.as_ref(), name).await?.unwrap_or_default();
            if let Some(v) = insecure {
                record.insecure_skip_tls_verify = v;
            }
            if let Some(pem) = ca {
                record.tls_ca_pem = (!pem.is_empty()).then_some(pem);
            }
            if let Some(url) = pin_url {
                record.connection_url = url;
            }
            if let Some(user) = pin_user {
                record.username = user;
            }
            // The plugin may hold a new target or root secret now: every
            // node's pool drains connections opened under the previous write.
            // A fresh random value, not an increment, so it never repeats.
            record.config_generation = random_u64()?;
            if record.insecure_skip_tls_verify {
                log::warn!(
                    "dynamic mount connection `{name}` has insecure_skip_tls_verify set: TLS certificates of the \
                     target are not verified (development only)"
                );
            }
            state::save_connection(storage.as_ref(), name, &record).await?;
            host_pool().configure(&target_key(&mount_id, name), record.target_settings());
            settle_cache_epoch(storage.as_ref(), &mount_id, &what, Ok(resp)).await
        }
        Operation::Delete => {
            let mount_id = state::mount_id(storage.as_ref()).await?;
            let what = format!("deleting config/{name}");
            let resp = match proxy(call, req, None).await {
                Ok(resp) => resp,
                Err(e) => return settle_cache_epoch(storage.as_ref(), &mount_id, &what, Err(e)).await,
            };
            state::delete_connection(storage.as_ref(), name).await?;
            host_pool().remove(&target_key(&mount_id, name));
            settle_cache_epoch(storage.as_ref(), &mount_id, &what, Ok(resp)).await
        }
        Operation::Read => {
            let mut resp = proxy(call, req, None).await?;
            if let (Some(r), Some(record)) = (resp.as_mut(), state::load_connection(storage.as_ref(), name).await?) {
                let data = r.data.get_or_insert_with(Map::new);
                data.insert("insecure_skip_tls_verify".into(), Value::Bool(record.insecure_skip_tls_verify));
                data.insert("tls_ca_pem".into(), record.tls_ca_pem.map(Value::String).unwrap_or(Value::Null));
                data.insert("root_credential_version".into(), Value::from(record.root_credential_version));
            }
            Ok(resp)
        }
        _ => proxy(call, req, None).await,
    }
}

/// Hand a request to the plugin as the generic `{op, path, data}` envelope.
/// A proxied answer may not carry a lease: leases come from `creds/` only.
async fn proxy(
    call: &DynamicCall<'_>,
    req: &Request,
    body: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let storage = mount_storage(req)?;
    let mount_id = state::mount_id(storage.as_ref()).await?;
    let manifest = &call.record.manifest;
    let caller = manifest.capabilities.caller_identity.then(|| crate::plugins::provider::caller_from_request(req));
    let mut envelope = build_envelope(req, caller.as_ref())?;
    if let Some(body) = body {
        envelope["data"] = Value::Object(body);
    }
    let s = Arc::new(session(DynamicVerb::Proxy, &mount_id, &storage, req));
    let output = call.invoke_output(&envelope, &s).await?;
    let mut resp = translate_response(call.name(), manifest, &output)?;
    if let Some(r) = resp.as_mut() {
        if r.secret.take().is_some() {
            log::warn!("plugin `{}` returned a lease from a proxied path; dropped", call.name());
        }
    }
    Ok(resp)
}
