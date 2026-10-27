//! The `sql` protocol's storage half (features/sql-browser.md §5.4, §9.5):
//! a database resource and one profile's credential, read from the resource
//! mount's barrier view, and the `v2/sql/privileges/<resource>` read. The
//! plugin host (`resource_sql_target` / `resource_sql_credential`) calls the
//! readers only after checking the caller's SQL privilege; a read here is
//! the consequence of that check, never a substitute for it.

use serde_json::{json, Map, Value};

use crate::connect_mfa::find_profile;
use crate::kernel_api::{
    policy::{canonical_resource, SqlCapability, SqlCheck, SqlPurpose, SqlTarget, SqlVerdict},
    VaultCtx,
};
use crate::sql_profile::{
    parse_objects_param, parse_resource_settings, parse_secret_login, parse_sql_profile, profile_view, reason,
    resolve_endpoint, sql_offered_by_type, SqlCredentialSource, SqlEndpoint, SqlEngine, SqlProfile, SqlRefusal,
    SqlResourceSettings, SqlSecretLogin, DATABASE_TYPE, SQL_PROTOCOL,
};
use crate::{
    bv_error_response_status,
    errors::RvError,
    logical::{Backend, Request, Response},
    storage::Storage,
    type_config::{self, TypeConfigError},
};

/// A database resource the `sql` protocol may be used on.
#[derive(Debug, Clone)]
pub struct SqlResourceRecord {
    /// The name the record is stored under (lower-case, or a legacy
    /// mixed-case key).
    pub name: String,
    pub resource_type: String,
    pub engine: SqlEngine,
    pub settings: SqlResourceSettings,
    pub meta: Map<String, Value>,
}

/// A profile's credential, ready for the host's release rules.
pub struct SqlRelease {
    pub profile: SqlProfile,
    pub endpoint: SqlEndpoint,
    pub secret_id: String,
    pub login: SqlSecretLogin,
}

fn refusal(status: u16, code: &'static str, message: impl Into<String>) -> RvError {
    SqlRefusal::new(status, code, message).into_rv()
}

/// Is `profile` an `sql` profile (by its stored `protocol`)?
pub fn is_sql_profile(profile: &Value) -> bool {
    profile.get("protocol").and_then(Value::as_str) == Some(SQL_PROTOCOL)
}

/// The record's type and engine, for a resource the `sql` protocol may be
/// used on: a `database` whose engine is one of the five.
pub fn database_engine(meta: &Map<String, Value>) -> Result<SqlEngine, SqlRefusal> {
    if meta.get("type").and_then(Value::as_str) != Some(DATABASE_TYPE) {
        return Err(SqlRefusal::new(
            403,
            reason::NOT_A_DATABASE,
            "the `sql` protocol is offered on `database` resources only",
        ));
    }
    let engine = meta.get("engine").and_then(Value::as_str).unwrap_or_default();
    SqlEngine::parse(engine).ok_or_else(|| {
        SqlRefusal::new(
            403,
            reason::ENGINE_UNSUPPORTED,
            "the resource's `engine` must be postgresql, mysql, mariadb, mssql or oracle for the `sql` protocol",
        )
    })
}

/// A stored `sql` profile, checked strictly against its resource record:
/// what `connect/mfa/begin|verify` require before costing a factor.
pub fn validate_sql_profile(meta: &Map<String, Value>, profile: &Value) -> Result<SqlProfile, SqlRefusal> {
    let engine = database_engine(meta)?;
    parse_resource_settings(meta)?;
    let parsed = parse_sql_profile(profile, engine)?;
    resolve_endpoint(&parsed, meta, engine)?;
    Ok(parsed)
}

/// Load a database resource for the `sql` protocol from its mount's view.
/// `in_child_namespace` decides whether the root namespace's saved type
/// configuration applies when the mount saved none (`type_config`).
#[maybe_async::maybe_async]
pub async fn load_sql_resource(
    core: &dyn VaultCtx,
    view: &dyn Storage,
    in_child_namespace: bool,
    resource: &str,
) -> Result<SqlResourceRecord, RvError> {
    let name = crate::resolve_resource_name_in(view, resource).await?;
    let Some(entry) = view.get(&format!("meta/{name}")).await? else {
        return Err(refusal(404, reason::RESOURCE_NOT_FOUND, format!("resource `{name}` not found")));
    };
    let meta: Map<String, Value> = serde_json::from_slice(&entry.value)
        .map_err(|_| refusal(422, reason::INVALID_RESOURCE_SETTINGS, "the resource record is not a JSON object"))?;
    let engine = database_engine(&meta)?;
    let types = type_config::effective_type_config_in(core, view, in_child_namespace).await.map_err(|e| match e {
        TypeConfigError::Storage(e) => e,
        TypeConfigError::Malformed(source) => refusal(
            422,
            reason::INVALID_TYPE_CONFIG,
            format!("the {} resource type configuration is not a JSON object", source.as_str()),
        ),
    })?;
    match sql_offered_by_type(types.type_def(DATABASE_TYPE)) {
        Ok(true) => {}
        Ok(false) => {
            return Err(refusal(
                403,
                reason::SQL_DISABLED_FOR_TYPE,
                "the `database` type's Connect settings do not offer the `sql` protocol",
            ))
        }
        Err(m) => return Err(refusal(422, reason::INVALID_TYPE_CONFIG, m)),
    }
    let settings = parse_resource_settings(&meta)?;
    let resource_type = DATABASE_TYPE.to_string();
    Ok(SqlResourceRecord { name, resource_type, engine, settings, meta })
}

/// What `resource_sql_target` returns about a database resource: engine,
/// endpoint fields, enforcement mode and every `sql` profile, strictly
/// parsed. A profile that does not parse is listed under `invalid_profiles`
/// with the reason, never repaired. No credential, only secret ids.
pub fn target_view(rec: &SqlResourceRecord) -> Map<String, Value> {
    let text = |k: &str| rec.meta.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    let mut profiles = Vec::new();
    let mut invalid = Vec::new();
    let stored = match rec.meta.get("connection_profiles") {
        Some(Value::Array(list)) => list.as_slice(),
        _ => &[],
    };
    for p in stored.iter().filter(|p| is_sql_profile(p)) {
        let parsed = parse_sql_profile(p, rec.engine)
            .and_then(|parsed| resolve_endpoint(&parsed, &rec.meta, rec.engine).map(|ep| (parsed, ep)));
        match parsed {
            Ok((parsed, ep)) => profiles.push(profile_view(&parsed, &ep)),
            Err(r) => invalid.push(json!({
                "id": p.get("id").and_then(Value::as_str),
                "reason": r.code,
                "error": r.message,
            })),
        }
    }
    let mut out = Map::new();
    out.insert("resource".into(), json!(rec.name));
    out.insert("type".into(), json!(rec.resource_type));
    out.insert("engine".into(), json!(rec.engine.as_str()));
    out.insert("default_port".into(), json!(rec.engine.default_port()));
    out.insert("hostname".into(), json!(text("hostname")));
    out.insert("ip_address".into(), json!(text("ip_address")));
    out.insert("database_name".into(), json!(text("database_name")));
    out.insert("enforcement".into(), json!(rec.settings.enforcement.as_str()));
    out.insert("profiles".into(), Value::Array(profiles));
    out.insert("invalid_profiles".into(), Value::Array(invalid));
    out
}

/// Read one `sql` profile's credential (§5.4 rules 3 and 5's inputs). The
/// profile must exist, be `sql` and parse strictly; a `dynamic` source is
/// refused until Phase 9; the secret must carry a login. The values never
/// reach a log line or an error.
#[maybe_async::maybe_async]
pub async fn read_release(
    view: &dyn Storage,
    rec: &SqlResourceRecord,
    profile_id: &str,
) -> Result<SqlRelease, RvError> {
    let Some(stored) = find_profile(&rec.meta, profile_id) else {
        return Err(refusal(
            404,
            reason::PROFILE_NOT_FOUND,
            format!("profile `{profile_id}` not found on resource `{}`", rec.name),
        ));
    };
    let profile = parse_sql_profile(&stored, rec.engine)?;
    let endpoint = resolve_endpoint(&profile, &rec.meta, rec.engine)?;
    let secret_id = match &profile.credential_source {
        SqlCredentialSource::Secret { secret_id } => secret_id.clone(),
        SqlCredentialSource::Dynamic { .. } => {
            return Err(refusal(
                403,
                reason::DYNAMIC_NOT_AVAILABLE,
                "dynamic database credentials are reserved for a later phase (T130) and are not released by this \
                 server",
            ))
        }
    };
    let Some(entry) = view.get(&format!("secret/{}/{secret_id}", rec.name)).await? else {
        return Err(refusal(
            403,
            reason::CREDENTIAL_MISSING,
            format!("the profile's secret `{secret_id}` does not exist on resource `{}`", rec.name),
        ));
    };
    let raw = zeroize::Zeroizing::new(entry.value);
    let login = parse_secret_login(&raw)?;
    Ok(SqlRelease { profile, endpoint, secret_id, login })
}

// ── `v2/sql/privileges/<resource>` ──────────────────────────────────────

/// An object target that addresses no single object: checked on the objects
/// root, where only a grant covering every object (`…/sql/*`,
/// `…/sql/objects/*`) applies. That is the resource-wide answer.
fn resource_wide() -> SqlTarget {
    SqlTarget::Object { catalog: String::new(), schema: String::new(), object: String::new() }
}

fn granted(verdicts: &[SqlVerdict]) -> Vec<&'static str> {
    verdicts.iter().filter(|v| v.allowed).map(|v| v.capability.as_str()).collect()
}

/// `objects` off a read: absent is none; anything but a string refuses.
fn objects_field(req: &Request) -> Result<Vec<(String, String, String)>, RvError> {
    match req.get_data("objects") {
        Ok(Value::String(s)) => parse_objects_param(&s).map_err(|m| bv_error_response_status!(400, m)),
        Ok(Value::Null) | Err(RvError::ErrRequestFieldNotFound | RvError::ErrRequestNoData) => Ok(Vec::new()),
        Ok(_) | Err(RvError::ErrRequestFieldInvalid) => {
            Err(bv_error_response_status!(400, "`objects` must be a string"))
        }
        Err(e) => Err(e),
    }
}

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    /// Does the caller hold any SQL capability on `resource`'s `sql/server`?
    /// A display probe: it decides only which grant a connect pre-flight
    /// checks, and records nothing.
    pub(crate) async fn caller_holds_sql_privilege(&self, req: &Request, resource: &str) -> Result<bool, RvError> {
        let policy = self.core.policy().ok_or_else(|| crate::bv_error_string!("policy module not registered"))?;
        let checks: Vec<SqlCheck> =
            SqlCapability::ALL.iter().map(|c| SqlCheck { capability: *c, target: SqlTarget::Server }).collect();
        let verdicts = policy.sql_privileges(req, SqlPurpose::Display, resource, &checks).await?;
        Ok(verdicts.iter().any(|v| v.allowed))
    }

    /// `GET resources/v2/sql/privileges/<resource>[?objects=c/s/o,…]`: the
    /// caller's own effective SQL capabilities on `sql/server`,
    /// resource-wide and per named object, for the GUI's chips. A display
    /// read (`SqlPurpose::Display`): no denial is recorded and nothing is
    /// enforced from it. The record is not read, so it answers the same
    /// for a resource that does not exist.
    pub async fn handle_sql_privileges(
        &self,
        _backend: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        if req.auth.is_none() {
            return Err(bv_error_response_status!(401, "no authenticated caller"));
        }
        let raw = req.get_data("resource")?.as_str().unwrap_or_default().to_string();
        let resource = canonical_resource(&raw)?;
        let objects = objects_field(req)?;

        let caps = SqlCapability::ALL;
        let mut checks: Vec<SqlCheck> = Vec::with_capacity(caps.len() * (2 + objects.len()));
        let mut push_all = |target: SqlTarget| {
            checks.extend(caps.iter().map(|c| SqlCheck { capability: *c, target: target.clone() }));
        };
        push_all(SqlTarget::Server);
        push_all(resource_wide());
        for (catalog, schema, object) in &objects {
            push_all(SqlTarget::Object { catalog: catalog.clone(), schema: schema.clone(), object: object.clone() });
        }

        let policy = self.core.policy().ok_or_else(|| crate::bv_error_string!("policy module not registered"))?;
        let verdicts = policy.sql_privileges(req, SqlPurpose::Display, &resource, &checks).await?;
        let mut chunks = verdicts.chunks(caps.len());
        let server = granted(chunks.next().unwrap_or_default());
        let wide = granted(chunks.next().unwrap_or_default());
        let per_object: Vec<Value> = objects
            .iter()
            .zip(chunks)
            .map(|((catalog, schema, object), verdicts)| {
                let target =
                    SqlTarget::Object { catalog: catalog.clone(), schema: schema.clone(), object: object.clone() };
                json!({
                    "catalog": catalog,
                    "schema": schema,
                    "object": object,
                    "addressable": target.is_addressable(),
                    "capabilities": granted(verdicts),
                })
            })
            .collect();

        let mut data = Map::new();
        data.insert("resource".into(), json!(resource));
        data.insert("server".into(), json!(server));
        data.insert("resource_wide".into(), json!(wide));
        data.insert("objects".into(), Value::Array(per_object));
        Ok(Some(Response::data_response(Some(data))))
    }
}
