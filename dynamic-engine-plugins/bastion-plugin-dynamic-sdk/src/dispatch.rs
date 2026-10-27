//! One host-to-plugin call, shared by both runtimes: decode the envelope,
//! run the backend, register the lease (generate only, exactly once), answer.
//! Envelopes are the host's (`src/plugins/dynamic/backend.rs`): the dynamic
//! verbs `dynamic.role|generate|renew|revoke|rotate_root`, and the generic
//! `{op, path, data}` envelope for the proxied `config/` and `roles/` paths.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::{
    backend::{DynamicCredentialBackend, GenerateRequest, RenewRequest, RevokeRequest, RotateRootRequest},
    connection::Connection,
    ctx::DynamicCtx,
    host::HostCalls,
    lease::MAX_INTERNAL_BYTES,
    role::{check_name, StoredRole},
    secret::{contains_secret, redact, wipe_value, SecretString},
    DynamicError,
};

/// Response keys only the host may set on a generated credential.
const RESERVED_DATA_KEYS: [&str; 5] = ["username", "password", "lease_id", "lease_duration", "renewable"];
/// The ops a diagnostic line may name; anything else is logged as `other`.
const KNOWN_OPS: [&str; 9] = [
    "dynamic.role",
    "dynamic.generate",
    "dynamic.renew",
    "dynamic.revoke",
    "dynamic.rotate_root",
    "read",
    "write",
    "delete",
    "list",
];

/// What the plugin answers: a status (0 = success) and a JSON body.
pub struct Reply {
    pub status: i32,
    pub body: Zeroizing<Vec<u8>>,
}

impl Reply {
    fn ok(value: &Value) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self { status: 0, body: Zeroizing::new(body) }
    }

    pub(crate) fn error(err: &DynamicError, secrets: &[&str]) -> Self {
        let mut body = json!({ "error": redact(&err.to_string(), secrets) });
        if matches!(err, DynamicError::RootNotStored(_)) {
            // The host undoes its target-side rotation only on this.
            body["root_stored"] = json!(false);
        }
        Self { status: err.status(), body: Zeroizing::new(body.to_string().into_bytes()) }
    }

    /// The body as JSON.
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply").field("status", &self.status).field("body_len", &self.body.len()).finish()
    }
}

/// Serve one call. `diag` receives diagnostic lines (stderr in the process
/// runtime): the op and an error kind, never request data.
pub async fn dispatch<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    host: &mut dyn HostCalls,
    input: &[u8],
    diag: &mut dyn FnMut(&str),
) -> Reply {
    let mut envelope: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => return Reply::error(&DynamicError::Protocol("the call input is not JSON".into()), &[]),
    };
    let op = envelope.get("op").and_then(Value::as_str).unwrap_or("").to_string();
    let engine = backend.engine_type();
    let mut ctx = DynamicCtx::new(host, diag);
    let reply = match route(backend, &mut ctx, &op, &envelope).await {
        Ok(v) => Reply::ok(&v),
        Err(e) => {
            let label = if KNOWN_OPS.contains(&op.as_str()) { op.as_str() } else { "other" };
            ctx.warn(&format!("[{engine}] {label} failed ({})", e.kind()));
            Reply::error(&e, &ctx.secret_refs())
        }
    };
    wipe_value(&mut envelope);
    reply
}

fn parse<'a, T: Deserialize<'a>>(op: &str, envelope: &'a Value) -> Result<T, DynamicError> {
    // serde's message can quote a field's value; the envelope may hold the
    // password, so only the op is named.
    T::deserialize(envelope).map_err(|_| DynamicError::Protocol(format!("malformed `{op}` envelope from the host")))
}

async fn route<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    ctx: &mut DynamicCtx<'_>,
    op: &str,
    envelope: &Value,
) -> Result<Value, DynamicError> {
    match op {
        "dynamic.role" => role_recipe(ctx, parse(op, envelope)?).await,
        "dynamic.generate" => generate(backend, ctx, parse(op, envelope)?).await,
        "dynamic.renew" => renew(backend, ctx, parse(op, envelope)?).await,
        "dynamic.revoke" => revoke(backend, ctx, parse(op, envelope)?).await,
        "dynamic.rotate_root" => rotate_root(backend, ctx, parse(op, envelope)?).await,
        "read" | "write" | "delete" | "list" => proxy(backend, ctx, op, envelope).await,
        _ => Err(DynamicError::Unsupported("this operation")),
    }
}

#[derive(Deserialize)]
struct RoleEnvelope {
    role: String,
}

#[derive(Deserialize)]
struct GenerateEnvelope {
    role: String,
    connection: String,
    #[serde(default)]
    statements: Vec<String>,
    credential: CredentialEnvelope,
    #[serde(default)]
    ttl_secs: u64,
}

#[derive(Deserialize)]
struct CredentialEnvelope {
    username: String,
    password: String,
    #[serde(default)]
    expiration: String,
}

#[derive(Deserialize)]
struct LeaseEnvelope {
    role: String,
    connection: String,
    username: String,
    #[serde(default)]
    statements: Vec<String>,
    #[serde(default)]
    expiration: String,
    #[serde(default)]
    ttl_secs: u64,
    #[serde(default)]
    internal: Value,
}

#[derive(Deserialize)]
struct RotateEnvelope {
    connection: String,
    #[serde(default)]
    credential: Option<RotateCredential>,
}

#[derive(Deserialize)]
struct RotateCredential {
    password: String,
}

async fn connection_for(ctx: &mut DynamicCtx<'_>, name: &str, role: Option<&str>) -> Result<Connection, DynamicError> {
    let conn = ctx.load_connection(name).await?.ok_or_else(|| {
        DynamicError::NotFound(format!("connection `{name}` is not configured (write config/{name})"))
    })?;
    if let Some(role) = role {
        if !conn.allows_role(role) {
            return Err(DynamicError::invalid(format!(
                "connection `{name}` does not allow role `{role}` (add it to allowed_roles)"
            )));
        }
    }
    Ok(conn)
}

async fn role_recipe(ctx: &mut DynamicCtx<'_>, env: RoleEnvelope) -> Result<Value, DynamicError> {
    check_name("role", &env.role)?;
    let Some(bytes) = ctx.host().storage_get(&format!("roles/{}", env.role)).await? else {
        return Ok(json!({ "data": null }));
    };
    let recipe = StoredRole::decode(&bytes)?;
    // Refused here, before the host generates anything for the role.
    connection_for(ctx, &recipe.connection, Some(&env.role)).await?;
    Ok(json!({ "data": recipe }))
}

/// Extra response data, without the host's keys and without any secret.
fn response_data(data: Map<String, Value>, secrets: &[&str]) -> Result<Map<String, Value>, DynamicError> {
    let data: Map<String, Value> =
        data.into_iter().filter(|(k, _)| !RESERVED_DATA_KEYS.contains(&k.as_str())).collect();
    if contains_secret(&Value::Object(data.clone()).to_string(), secrets) {
        return Err(DynamicError::invalid("the plugin's response data would carry credential material"));
    }
    Ok(data)
}

async fn generate<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    ctx: &mut DynamicCtx<'_>,
    env: GenerateEnvelope,
) -> Result<Value, DynamicError> {
    let password = SecretString::new(env.credential.password);
    ctx.remember_secret(&password);
    let statements: Vec<SecretString> = env.statements.into_iter().map(SecretString::new).collect();
    check_name("role", &env.role)?;
    if env.credential.username.is_empty() {
        return Err(DynamicError::Protocol("dynamic.generate carried no username".into()));
    }
    let connection = connection_for(ctx, &env.connection, Some(&env.role)).await?;
    let req = GenerateRequest {
        role: env.role,
        connection,
        statements,
        username: env.credential.username,
        password,
        expiration: env.credential.expiration,
        ttl_secs: env.ttl_secs,
    };
    let generated = backend.generate(ctx, req).await?;
    ctx.register_lease(&generated.lease).await?;
    let data = response_data(generated.data, &ctx.secret_refs())?;
    Ok(json!({ "data": data }))
}

async fn renew<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    ctx: &mut DynamicCtx<'_>,
    env: LeaseEnvelope,
) -> Result<Value, DynamicError> {
    let connection = connection_for(ctx, &env.connection, None).await?;
    let req = RenewRequest {
        role: env.role,
        connection,
        username: env.username,
        statements: env.statements,
        expiration: env.expiration,
        ttl_secs: env.ttl_secs,
        internal: env.internal,
    };
    let renewed = backend.renew(ctx, req).await?;
    match renewed.internal {
        None => Ok(json!({ "data": {} })),
        Some(internal) => {
            let blob = internal.to_string();
            if blob.len() > MAX_INTERNAL_BYTES || contains_secret(&blob, &ctx.secret_refs()) {
                return Err(DynamicError::invalid("the renewed internal blob is too large or carries a secret"));
            }
            Ok(json!({ "data": { "internal": internal } }))
        }
    }
}

async fn revoke<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    ctx: &mut DynamicCtx<'_>,
    env: LeaseEnvelope,
) -> Result<Value, DynamicError> {
    let connection = connection_for(ctx, &env.connection, None).await?;
    let req = RevokeRequest {
        role: env.role,
        connection,
        username: env.username,
        statements: env.statements,
        internal: env.internal,
    };
    backend.revoke(ctx, req).await?;
    Ok(json!({}))
}

async fn rotate_root<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    ctx: &mut DynamicCtx<'_>,
    env: RotateEnvelope,
) -> Result<Value, DynamicError> {
    let Some(credential) = env.credential else {
        return Err(DynamicError::Protocol(
            "dynamic.rotate_root carried no new root credential; the host must generate it".into(),
        ));
    };
    let new_secret = SecretString::new(credential.password);
    ctx.remember_secret(&new_secret);
    if new_secret.is_empty() {
        return Err(DynamicError::Protocol("dynamic.rotate_root carried an empty root credential".into()));
    }
    let connection = connection_for(ctx, &env.connection, None).await?;
    backend.rotate_root(ctx, RotateRootRequest { connection, new_secret }).await?;
    Ok(json!({}))
}

async fn list(ctx: &mut DynamicCtx<'_>, prefix: &str) -> Result<Value, DynamicError> {
    let keys: Vec<String> = ctx.host().storage_list(prefix).await?.into_iter().filter(|k| !k.ends_with('/')).collect();
    Ok(json!({ "data": { "keys": keys } }))
}

/// The proxied `config/` and `roles/` paths.
async fn proxy<B: DynamicCredentialBackend + ?Sized>(
    backend: &B,
    ctx: &mut DynamicCtx<'_>,
    op: &str,
    envelope: &Value,
) -> Result<Value, DynamicError> {
    let path = envelope.get("path").and_then(Value::as_str).unwrap_or("").trim_matches('/');
    let (head, name) = path.split_once('/').unwrap_or((path, ""));
    let empty = Map::new();
    let data = envelope.get("data").and_then(Value::as_object).unwrap_or(&empty);
    if name.is_empty() {
        return match (head, op) {
            ("config" | "roles", "list" | "read") => list(ctx, head).await,
            _ => Err(DynamicError::Unsupported("this path")),
        };
    }
    match head {
        "config" => {
            check_name("connection", name)?;
            match op {
                "read" => {
                    let conn = ctx.load_connection(name).await?;
                    Ok(json!({ "data": conn.map(|c| Value::Object(c.metadata())) }))
                }
                "write" => {
                    let mut conn = ctx.load_connection(name).await?.unwrap_or_else(|| Connection::new(name));
                    conn.apply_input(&backend.connection_schema(), data)?;
                    let fresh: Vec<SecretString> = conn.secret_values().cloned().collect();
                    fresh.iter().for_each(|s| ctx.remember_secret(s));
                    backend.validate_connection(&conn)?;
                    ctx.save_connection(&conn).await?;
                    Ok(json!({}))
                }
                "delete" => {
                    ctx.host().storage_delete(&format!("config/{name}")).await?;
                    Ok(json!({}))
                }
                _ => Err(DynamicError::Unsupported("this operation on config/")),
            }
        }
        "roles" => {
            check_name("role", name)?;
            let key = format!("roles/{name}");
            match op {
                "read" => match ctx.host().storage_get(&key).await? {
                    None => Ok(json!({ "data": null })),
                    Some(bytes) => Ok(json!({ "data": StoredRole::decode(&bytes)? })),
                },
                "write" => {
                    let recipe = crate::role::RoleRecipe::from_input(data)?;
                    backend.validate_role(&recipe)?;
                    ctx.host().storage_put(&key, &StoredRole::encode(&recipe)?).await?;
                    Ok(json!({}))
                }
                "delete" => {
                    ctx.host().storage_delete(&key).await?;
                    Ok(json!({}))
                }
                _ => Err(DynamicError::Unsupported("this operation on roles/")),
            }
        }
        _ => Err(DynamicError::Unsupported("this path")),
    }
}
