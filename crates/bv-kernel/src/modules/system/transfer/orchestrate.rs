//! Copy or move one resource or KV secret to another namespace (T494).
//!
//! Every step is an ordinary request made with the caller's own token in the
//! namespace it touches, so each one gets the ACL, token binding, owner stamp
//! and audit entry a direct request would. Nothing here touches storage.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::shares::ShareWarning;
use crate::{
    errors::RvError,
    kernel_api::{namespace::normalize_path, VaultCtx},
    logical::{Operation, Request, Response},
    modules::{
        namespace::router::{is_header_scoped_path, NAMESPACE_HEADER},
        policy::TRANSFER_IMPORT_MAX_SECRETS,
    },
};

/// A soft-deleted KV version arrives destroyed: its value is not readable.
pub const CODE_DELETED_VERSION_NOT_RECOVERABLE: &str = "deleted-version-not-recoverable";
/// A resource secret with no version index arrives as version 1.
pub const CODE_UNVERSIONED_SECRET: &str = "unversioned-secret";
/// The caller may not read the source's owner; the history does not name it.
pub const CODE_ORIGIN_OWNER_UNREADABLE: &str = "origin-owner-unreadable";
/// A dry run could not read the destination to look for a collision.
pub const CODE_COLLISION_NOT_CHECKED: &str = "collision-not-checked";
/// `on_conflict = overwrite` deleted (or, on a dry run, would delete) an item.
pub const CODE_DESTINATION_REPLACED: &str = "destination-replaced";
/// `on_conflict = rename` wrote the item under another name.
pub const CODE_RENAMED: &str = "renamed";
/// Policies naming the source path are not rewritten for the destination.
pub const CODE_POLICIES_NOT_CARRIED: &str = "policies-not-carried";
/// KV environment overrides are rebuilt from per-environment reads, so an
/// override equal to its base value is not carried (there is no raw read).
pub const CODE_KV_ENV_OVERRIDES_NORMALIZED: &str = "kv-environment-overrides-normalized";

/// `on_conflict = rename` tries the name, then `<name>-2` up to this suffix.
const RENAME_MAX_SUFFIX: usize = 100;

/// The resource import's 409 for a destination-side content gate, not a name
/// collision (`check_import_write_gates` in bv-engine-resource; pinned by the
/// facade test `a_gate_refusal_is_never_read_as_a_collision`).
const BROKERED_GATE_CODE: &str = "brokered_resource_no_static_credential";

/// `copy` keeps the source; `move` deletes it after a verified copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOp {
    Copy,
    Move,
}

impl TransferOp {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "copy" => Some(Self::Copy),
            "move" => Some(Self::Move),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Copy => "copy",
            Self::Move => "move",
        }
    }
}

/// One side of a transfer: `namespace` (`""` = root), `mount`, and the
/// resource name or KV secret path inside it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    #[serde(default)]
    pub namespace: String,
    pub mount: String,
    pub path: String,
}

/// The body of `sys/namespace-transfer/{copy|move}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    /// `resource` or `kv-secret`.
    pub kind: String,
    pub source: Location,
    pub destination: Location,
    /// `refuse` (default), `rename` or `overwrite`.
    #[serde(default)]
    pub on_conflict: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// What arrived (or, on a dry run, would arrive) in the destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Transferred {
    pub secrets: usize,
    pub versions: usize,
    pub history: usize,
    pub shares: usize,
}

/// A part of the item that was dropped or altered: `{code, subject, message}`,
/// never a value. The share planner's warnings have the same shape.
pub type TransferWarning = ShareWarning;

#[derive(Debug, Clone, Serialize)]
pub struct TransferResult {
    pub transferred: Transferred,
    pub warnings: Vec<TransferWarning>,
    pub dry_run: bool,
    pub destination: Location,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Resource,
    KvSecret,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::KvSecret => "kv-secret",
        }
    }

    /// The engine type a mount of this kind has.
    fn mount_type(self) -> &'static str {
        match self {
            Self::Resource => "resource",
            Self::KvSecret => "kv-v2",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Conflict {
    Refuse,
    Rename,
    Overwrite,
}

/// A validated [`Location`]: canonical namespace, `mount/`, and the path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Place {
    ns: String,
    mount: String,
    path: String,
}

impl Place {
    fn named(&self, path: String) -> Self {
        Self { path, ..self.clone() }
    }

    /// The item's record: what is read, deleted and checked for a collision.
    fn item(&self, kind: Kind) -> String {
        match kind {
            Kind::Resource => format!("{}resources/{}", self.mount, self.path),
            Kind::KvSecret => format!("{}metadata/{}", self.mount, self.path),
        }
    }

    fn import(&self) -> String {
        format!("{}v2/transfer/import/{}", self.mount, self.path)
    }

    /// `<ns>/<mount>` as the router sees it: a namespace written into the mount
    /// (`{ns: "", mount: "a/secret"}`) reaches the same mount as `{ns: "a"}`.
    fn scope(&self) -> String {
        let mount = self.mount.trim_end_matches('/');
        match self.ns.is_empty() {
            true => mount.to_string(),
            false => format!("{}/{mount}", self.ns),
        }
    }

    /// `<ns>/<mount><path>`, the form logs, messages and `origin` use.
    fn display(&self) -> String {
        match self.ns.is_empty() {
            true => format!("{}{}", self.mount, self.path),
            false => format!("{}/{}{}", self.ns, self.mount, self.path),
        }
    }

    fn location(&self) -> Location {
        Location {
            namespace: self.ns.clone(),
            mount: self.mount.trim_end_matches('/').to_string(),
            path: self.path.clone(),
        }
    }
}

fn namespace_label(ns: &str) -> String {
    match ns.is_empty() {
        true => "the root namespace".to_string(),
        false => format!("namespace '{ns}'"),
    }
}

/// A validated request.
#[derive(Debug)]
struct Plan {
    op: TransferOp,
    kind: Kind,
    conflict: Conflict,
    dry_run: bool,
    source: Place,
    destination: Place,
}

impl Plan {
    fn new(op: TransferOp, t: TransferRequest) -> Result<Self, RvError> {
        let kind = match t.kind.trim() {
            "resource" => Kind::Resource,
            "kv-secret" => Kind::KvSecret,
            other => return Err(invalid(format!("kind must be resource or kv-secret, not '{other}'"))),
        };
        let conflict = match t.on_conflict.trim() {
            "" | "refuse" => Conflict::Refuse,
            "rename" => Conflict::Rename,
            "overwrite" => Conflict::Overwrite,
            other => return Err(invalid(format!("on_conflict must be refuse, rename or overwrite, not '{other}'"))),
        };
        let source = place(kind, "source", &t.source)?;
        let destination = place(kind, "destination", &t.destination)?;
        let same_name = match kind {
            Kind::Resource => source.path.eq_ignore_ascii_case(&destination.path),
            Kind::KvSecret => source.path == destination.path,
        };
        // Compared on the effective scope, so no aliased spelling of one item
        // passes (an overwrite or move onto itself would delete it).
        if source.scope() == destination.scope() && same_name {
            return Err(invalid("source and destination are the same item"));
        }
        Ok(Self { op, kind, conflict, dry_run: t.dry_run, source, destination })
    }
}

fn invalid(message: impl Into<String>) -> RvError {
    RvError::ErrResponseStatus(400, format!("invalid namespace transfer: {}", message.into()))
}

/// Non-empty `/`-separated segments, none of them `.`, no `..` anywhere (the
/// barrier refuses it in any key) and no control characters.
fn clean_segments(path: &str) -> bool {
    !path.contains("..") && !path.chars().any(char::is_control) && path.split('/').all(|s| !s.is_empty() && s != ".")
}

fn place(kind: Kind, field: &str, loc: &Location) -> Result<Place, RvError> {
    let ns =
        normalize_path(&loc.namespace).map_err(|_| invalid(format!("{field}.namespace is not a namespace path")))?;
    let mount = loc.mount.trim().trim_matches('/');
    if mount.is_empty() || !clean_segments(mount) {
        return Err(invalid(format!("{field}.mount must be a mount path")));
    }
    let mount = format!("{mount}/");
    // These mounts live in the root table only and ignore the namespace.
    if is_header_scoped_path(&mount) {
        return Err(invalid(format!("{field}.mount '{mount}' is not a mount inside a namespace")));
    }
    let path = match kind {
        Kind::Resource => {
            let name = loc.path.trim();
            if name.is_empty() || name.contains('/') || !clean_segments(name) {
                return Err(invalid(format!("{field}.path must be one resource name, without '/' or '..'")));
            }
            name.to_string()
        }
        // KV names are exact keys: no trimming.
        Kind::KvSecret => {
            if loc.path.is_empty() || !clean_segments(&loc.path) {
                return Err(invalid(format!("{field}.path must be a secret path without '..', '.' or empty segments")));
            }
            loc.path.clone()
        }
    };
    Ok(Place { ns, mount, path })
}

fn warning(code: &str, subject: impl Into<String>, message: impl Into<String>) -> TransferWarning {
    TransferWarning { code: code.to_string(), subject: subject.into(), message: message.into() }
}

fn status_of(e: &RvError) -> u16 {
    match e {
        RvError::ErrResponseStatus(status, _) => *status,
        other => other.response_status(),
    }
}

/// The status and text of an error, for a message that adds context to it.
fn split(e: RvError) -> (u16, String) {
    match e {
        RvError::ErrResponseStatus(status, message) => (status, message),
        other => (other.response_status(), other.to_string()),
    }
}

/// An import 409 that means "the name is taken" (an item or leftover data),
/// not a destination content gate, whose refusal must reach the caller as is.
fn is_name_conflict(e: &RvError) -> bool {
    matches!(e, RvError::ErrResponseStatus(409, message) if !message.starts_with(BROKERED_GATE_CODE))
}

/// A denied sub-request as a 403 that says which step was refused.
fn refused(e: RvError, what: &str) -> RvError {
    match e {
        RvError::ErrPermissionDenied => RvError::ErrResponseStatus(403, format!("permission denied: {what}")),
        other => other,
    }
}

/// One request as the caller, in namespace `ns`. API version 1: the KV
/// import route exists only there (at 2 the router reads it as a secret).
#[maybe_async::maybe_async]
async fn call(
    core: &dyn VaultCtx,
    caller: &Request,
    ns: &str,
    operation: Operation,
    path: String,
    body: Option<Map<String, Value>>,
) -> Result<Option<Response>, RvError> {
    let mut req = Request::new(path);
    req.operation = operation;
    req.client_token = caller.client_token.clone();
    req.body = body;
    if !ns.is_empty() {
        req.headers = Some(HashMap::from([(NAMESPACE_HEADER.to_string(), ns.to_string())]));
    }
    // An MCP tool call keeps its dispatcher marking and audit block.
    req.mcp_dispatch = caller.mcp_dispatch;
    req.mcp_audit = caller.mcp_audit.clone();
    core.handle_request(&mut req).await
}

/// Read `path` in `ns` as the caller: the response data, `None` if absent.
#[maybe_async::maybe_async]
async fn read(
    core: &dyn VaultCtx,
    caller: &Request,
    ns: &str,
    path: String,
    body: Option<Value>,
) -> Result<Option<Map<String, Value>>, RvError> {
    let what = format!("the caller may not read {path} in {}", namespace_label(ns));
    let body = body.and_then(|b| b.as_object().cloned());
    let resp = call(core, caller, ns, Operation::Read, path, body).await.map_err(|e| refused(e, &what))?;
    Ok(resp.and_then(|r| r.data))
}

#[maybe_async::maybe_async]
async fn list(core: &dyn VaultCtx, caller: &Request, ns: &str, path: String) -> Result<Vec<String>, RvError> {
    let what = format!("the caller may not list {path} in {}", namespace_label(ns));
    let resp = call(core, caller, ns, Operation::List, path, None).await.map_err(|e| refused(e, &what))?;
    let keys = resp.and_then(|r| r.data).and_then(|d| d.get("keys").and_then(Value::as_array).cloned());
    Ok(keys.unwrap_or_default().iter().filter_map(Value::as_str).map(String::from).collect())
}

/// Refuse, before anything is read, a location whose namespace does not
/// exist, whose mount starts with a namespace path (an alias of a mount in
/// that namespace), or whose mount is not one of the caller-visible mounts of
/// the kind's engine in its namespace (`sys/internal/ui/mounts`).
#[maybe_async::maybe_async]
async fn check_place(
    core: &dyn VaultCtx,
    caller: &Request,
    kind: Kind,
    place: &Place,
    field: &str,
) -> Result<(), RvError> {
    if let Some(namespaces) = core.namespaces() {
        if !place.ns.is_empty() && namespaces.resolve(&place.ns).await?.is_none() {
            let message = format!("{field}.namespace: no such namespace '{}'", place.ns);
            return Err(RvError::ErrResponseStatus(404, message));
        }
        let segments: Vec<&str> = place.mount.trim_end_matches('/').split('/').collect();
        for end in 1..=segments.len() {
            let prefix = segments[..end].join("/");
            let candidate = if place.ns.is_empty() { prefix.clone() } else { format!("{}/{prefix}", place.ns) };
            // A segment no namespace may have (`*`, padding) names none.
            if normalize_path(&candidate).is_ok() && namespaces.resolve(&candidate).await?.is_some() {
                let message = format!(
                    "{field}.mount '{}' starts with namespace '{candidate}'; name it in {field}.namespace",
                    place.mount
                );
                return Err(invalid(message));
            }
        }
    }
    let listing = read(core, caller, &place.ns, "sys/internal/ui/mounts".to_string(), None).await?.unwrap_or_default();
    let mounts = listing.get("secret").and_then(Value::as_object);
    let entry =
        mounts.and_then(|m| m.iter().find(|(path, _)| path.trim_end_matches('/') == place.mount.trim_end_matches('/')));
    let found = entry.and_then(|(_, info)| info.get("type").and_then(Value::as_str));
    match found {
        Some(engine) if engine == kind.mount_type() => Ok(()),
        Some(engine) => Err(invalid(format!(
            "{field}.mount '{}' is a {engine} mount, not the {} mount a {} transfer needs",
            place.mount,
            kind.mount_type(),
            kind.as_str()
        ))),
        None => Err(invalid(format!(
            "{field}.mount '{}' is not a mount the caller can see in {}",
            place.mount,
            namespace_label(&place.ns)
        ))),
    }
}

fn text(map: &Map<String, Value>, field: &str) -> String {
    map.get(field).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn not_found(src: &Place) -> RvError {
    RvError::ErrResponseStatus(404, format!("nothing to transfer: {} does not exist", src.display()))
}

/// What was read from the source: the import body without the destination
/// fields, compared again before a move deletes the source. Holds secret
/// values, hence no `Debug`.
struct Snapshot {
    content: Map<String, Value>,
    /// Resource secret keys, for the destination write probes.
    keys: Vec<String>,
    counts: Transferred,
    warnings: Vec<TransferWarning>,
}

#[maybe_async::maybe_async]
async fn read_source(core: &dyn VaultCtx, caller: &Request, kind: Kind, src: &Place) -> Result<Snapshot, RvError> {
    match kind {
        Kind::Resource => read_resource(core, caller, src).await,
        Kind::KvSecret => read_kv(core, caller, src).await,
    }
}

/// The record, the change history, every secret and every version of each,
/// through the resource engine's own read endpoints.
#[maybe_async::maybe_async]
async fn read_resource(core: &dyn VaultCtx, caller: &Request, src: &Place) -> Result<Snapshot, RvError> {
    let (ns, name) = (src.ns.as_str(), src.path.as_str());
    let meta = read(core, caller, ns, src.item(Kind::Resource), None).await?.ok_or_else(|| not_found(src))?;
    let history_path = format!("{}resources/{name}/history", src.mount);
    let history = read(core, caller, ns, history_path, None).await?.unwrap_or_default();
    let history = history.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();

    let keys = list(core, caller, ns, format!("{}secrets/{name}", src.mount)).await?;
    if keys.len() > TRANSFER_IMPORT_MAX_SECRETS {
        return Err(invalid(format!(
            "{} carries {} secrets; one transfer carries at most {TRANSFER_IMPORT_MAX_SECRETS}",
            src.display(),
            keys.len()
        )));
    }

    let (mut secrets, mut versions_total, mut warnings) = (Vec::with_capacity(keys.len()), 0, Vec::new());
    for key in &keys {
        let base = format!("{}secrets/{name}/{key}", src.mount);
        let index = read(core, caller, ns, format!("{base}/history"), None).await?.unwrap_or_default();
        let mut numbers: Vec<u64> = index
            .get("versions")
            .and_then(Value::as_array)
            .map(|all| all.iter().filter_map(|v| v.get("version").and_then(Value::as_u64)).collect())
            .unwrap_or_default();
        numbers.sort_unstable();

        let mut versions = Vec::with_capacity(numbers.len().max(1));
        if numbers.is_empty() {
            // Written before secrets were versioned: only the live value exists,
            // with no creation time (an empty one keeps a move's re-read equal).
            let live = read(core, caller, ns, base.clone(), None).await?.ok_or_else(|| changed(src))?;
            versions.push(json!({ "version": 1, "created_time": "", "data": live }));
            let message = format!("secret {key} had no version history; it arrives as version 1 with no creation time");
            warnings.push(warning(CODE_UNVERSIONED_SECRET, key.clone(), message));
        }
        for n in &numbers {
            let v = read(core, caller, ns, format!("{base}/version/{n}"), None).await?.ok_or_else(|| {
                let message = format!("secret {key} version {n} of {} is listed but not stored", src.display());
                RvError::ErrResponseStatus(409, format!("{message}; it cannot be carried faithfully"))
            })?;
            versions.push(json!({
                "version": n,
                "created_time": text(&v, "created_time"),
                "username": text(&v, "username"),
                "operation": text(&v, "operation"),
                "data": v.get("data").cloned().unwrap_or_else(|| json!({})),
            }));
        }
        versions_total += versions.len();
        let current = numbers.last().copied().unwrap_or(1);
        secrets.push(json!({ "key": key, "current": current, "versions": versions }));
    }

    let counts = Transferred { secrets: keys.len(), versions: versions_total, history: history.len(), shares: 0 };
    let mut content = Map::new();
    content.insert("meta".into(), Value::Object(meta));
    content.insert("secrets".into(), Value::Array(secrets));
    content.insert("history".into(), Value::Array(history));
    Ok(Snapshot { content, keys, counts, warnings })
}

/// The overrides `merged` adds to `base`: the keys an environment read
/// returns with a value the base read does not have.
fn env_overrides(base: &Map<String, Value>, merged: &Map<String, Value>) -> Map<String, Value> {
    merged.iter().filter(|(k, v)| base.get(*k) != Some(*v)).map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// The secret's settings and every version, through `metadata/` and
/// `data/` (one read per version and per environment).
#[maybe_async::maybe_async]
async fn read_kv(core: &dyn VaultCtx, caller: &Request, src: &Place) -> Result<Snapshot, RvError> {
    let ns = src.ns.as_str();
    let meta = read(core, caller, ns, src.item(Kind::KvSecret), None).await?.ok_or_else(|| not_found(src))?;
    let mut numbered: Vec<(u64, Map<String, Value>)> = meta
        .get("versions")
        .and_then(Value::as_object)
        .map(|all| all.iter().filter_map(|(k, v)| Some((k.parse().ok()?, v.as_object()?.clone()))).collect())
        .unwrap_or_default();
    numbered.sort_by_key(|(n, _)| *n);

    let data_path = format!("{}data/{}", src.mount, src.path);
    let (mut versions, mut warnings) = (Vec::with_capacity(numbered.len()), Vec::new());
    let mut env_names = std::collections::BTreeSet::new();
    for (n, vm) in &numbered {
        let mut entry = json!({
            "version": n,
            "created_time": text(vm, "created_time"),
            "username": text(vm, "username"),
            "operation": text(vm, "operation"),
        });
        let destroyed = vm.get("destroyed").and_then(Value::as_bool).unwrap_or(false);
        let deletion_time = text(vm, "deletion_time");
        if destroyed || !deletion_time.is_empty() {
            if !destroyed {
                let message =
                    format!("version {n} is deleted at the source; its value cannot be read, so it arrives destroyed");
                warnings.push(warning(CODE_DELETED_VERSION_NOT_RECOVERABLE, format!("version {n}"), message));
            }
            entry["destroyed"] = json!(true);
            entry["deletion_time"] = json!(deletion_time);
            versions.push(entry);
            continue;
        }
        let at = |env: Option<&str>| match env {
            Some(env) => json!({ "version": n, "env": env }),
            None => json!({ "version": n }),
        };
        let live = read(core, caller, ns, data_path.clone(), Some(at(None))).await?.ok_or_else(|| changed(src))?;
        let base = live.get("data").and_then(Value::as_object).cloned().ok_or_else(|| changed(src))?;
        let names = live.get("metadata").and_then(|m| m.get("available_envs")).and_then(Value::as_array).cloned();
        let mut envs = Map::new();
        for env in names.unwrap_or_default().iter().filter_map(Value::as_str) {
            let resolved = read(core, caller, ns, data_path.clone(), Some(at(Some(env)))).await?;
            let merged = resolved.and_then(|d| d.get("data").and_then(Value::as_object).cloned());
            envs.insert(env.to_string(), Value::Object(env_overrides(&base, &merged.ok_or_else(|| changed(src))?)));
            env_names.insert(env.to_string());
        }
        entry["data"] = Value::Object(base);
        if !envs.is_empty() {
            entry["envs"] = Value::Object(envs);
        }
        versions.push(entry);
    }
    if !env_names.is_empty() {
        let names = env_names.into_iter().collect::<Vec<_>>().join(", ");
        let message = format!(
            "environments {names} of {} are rebuilt from per-environment reads: every environment reads the same, but \
             an override equal to its base value is not carried and follows the base after the next write",
            src.display()
        );
        warnings.push(warning(CODE_KV_ENV_OVERRIDES_NORMALIZED, src.display(), message));
    }

    let settings = json!({
        "max_versions": meta.get("max_versions").and_then(Value::as_u64).unwrap_or(0),
        "cas_required": meta.get("cas_required").and_then(Value::as_bool).unwrap_or(false),
        "delete_version_after": text(&meta, "delete_version_after"),
        "created_time": text(&meta, "created_time"),
        "updated_time": text(&meta, "updated_time"),
    });
    let counts = Transferred { secrets: 1, versions: versions.len(), history: 0, shares: 0 };
    let mut content = Map::new();
    content.insert("current".into(), json!(meta.get("current_version").and_then(Value::as_u64).unwrap_or(0)));
    content.insert("versions".into(), Value::Array(versions));
    content.insert("metadata".into(), settings);
    Ok(Snapshot { content, keys: Vec::new(), counts, warnings })
}

/// The source changed between two reads of one transfer.
fn changed(src: &Place) -> RvError {
    RvError::ErrResponseStatus(409, format!("{} changed while it was being read; retry the transfer", src.display()))
}

/// The resource owner's entity id, through `identity/owner/`. A caller who may
/// not read it gets a warning and an empty owner, not a refusal.
#[maybe_async::maybe_async]
async fn read_origin_owner(
    core: &dyn VaultCtx,
    caller: &Request,
    src: &Place,
    warnings: &mut Vec<TransferWarning>,
) -> Result<String, RvError> {
    let path = format!("identity/owner/resource/{}", src.path);
    match call(core, caller, &src.ns, Operation::Read, path, None).await {
        Ok(resp) => Ok(resp.and_then(|r| r.data).map(|d| text(&d, "entity_id")).unwrap_or_default()),
        Err(RvError::ErrPermissionDenied) => {
            let message = "the caller may not read the source's owner, so the destination history does not name it";
            warnings.push(warning(CODE_ORIGIN_OWNER_UNREADABLE, src.display(), message));
            Ok(String::new())
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, Copy)]
enum Right {
    Write,
    Delete,
}

impl Right {
    fn name(self) -> &'static str {
        match self {
            Self::Write => "write (create or update)",
            Self::Delete => "delete",
        }
    }

    fn held_in(self, caps: &[&str]) -> bool {
        if caps.contains(&"deny") {
            return false;
        }
        caps.contains(&"root")
            || match self {
                Self::Write => caps.contains(&"create") || caps.contains(&"update"),
                Self::Delete => caps.contains(&"delete"),
            }
    }
}

/// Refuse with a 403 unless the caller holds every `(path, right)` in `ns`, as
/// `sys/capabilities-self` reports it for the caller's token (namespace
/// binding included). `step` names what needs the rights.
#[maybe_async::maybe_async]
async fn require(
    core: &dyn VaultCtx,
    caller: &Request,
    ns: &str,
    checks: &[(String, Right)],
    step: &str,
) -> Result<(), RvError> {
    let paths: Vec<&str> = checks.iter().map(|(p, _)| p.as_str()).collect();
    let body = json!({ "paths": paths }).as_object().cloned();
    let what = format!("sys/capabilities-self is needed to check the rights {step} needs");
    let resp = call(core, caller, ns, Operation::Write, "sys/capabilities-self".to_string(), body).await;
    let data = resp.map_err(|e| refused(e, &what))?.and_then(|r| r.data).unwrap_or_default();
    if data.get("namespace_operable").and_then(Value::as_bool) == Some(false) {
        let message = format!("permission denied: the token may not operate in {}", namespace_label(ns));
        return Err(RvError::ErrResponseStatus(403, message));
    }
    let caps = data.get("capabilities").and_then(Value::as_object);
    for (path, right) in checks {
        let held = caps.and_then(|c| c.get(path)).and_then(Value::as_array).cloned().unwrap_or_default();
        let held: Vec<&str> = held.iter().filter_map(Value::as_str).collect();
        if !right.held_in(&held) {
            let label = namespace_label(ns);
            let message = format!(
                "permission denied: the caller lacks {} on {path} in {label}, which {step} needs",
                right.name()
            );
            return Err(RvError::ErrResponseStatus(403, message));
        }
    }
    Ok(())
}

/// Writing `dest` is authorized on the item and, for a resource, on each
/// secret it carries (as the import's policy layer does).
fn write_checks(kind: Kind, dest: &Place, snapshot: &Snapshot) -> Vec<(String, Right)> {
    let mut checks = vec![(dest.import(), Right::Write)];
    if kind == Kind::Resource {
        let name = dest.path.trim().to_ascii_lowercase();
        checks.extend(snapshot.keys.iter().map(|key| (format!("{}secrets/{name}/{key}", dest.mount), Right::Write)));
    }
    checks
}

/// The name, then `<name>-2` to `<name>-RENAME_MAX_SUFFIX`.
fn candidates(path: &str) -> impl Iterator<Item = String> + '_ {
    std::iter::once(path.to_string()).chain((2..=RENAME_MAX_SUFFIX).map(move |n| format!("{path}-{n}")))
}

fn no_free_name(dest: &Place) -> RvError {
    let message =
        format!("no free name for {}: it and every suffix -2 to -{RENAME_MAX_SUFFIX} are taken", dest.display());
    RvError::ErrResponseStatus(409, message)
}

/// Whether the item at `place` exists, read as the caller; `None` when the
/// caller may not read it.
#[maybe_async::maybe_async]
async fn exists(core: &dyn VaultCtx, caller: &Request, kind: Kind, place: &Place) -> Result<Option<bool>, RvError> {
    match call(core, caller, &place.ns, Operation::Read, place.item(kind), None).await {
        Ok(resp) => Ok(Some(resp.is_some_and(|r| r.data.is_some()))),
        Err(RvError::ErrPermissionDenied) => Ok(None),
        Err(e) => Err(e),
    }
}

fn not_checked(place: &Place) -> TransferWarning {
    let message = "the caller may not read the destination, so a name collision is only found when the transfer runs";
    warning(CODE_COLLISION_NOT_CHECKED, place.display(), message)
}

fn renamed(kind: Kind, wanted: &Place, written: &Place) -> Option<TransferWarning> {
    let same = match kind {
        Kind::Resource => written.path.eq_ignore_ascii_case(&wanted.path),
        Kind::KvSecret => written.path == wanted.path,
    };
    let message = format!("{} was taken; the item was written as {}", wanted.display(), written.display());
    (!same).then(|| warning(CODE_RENAMED, written.display(), message))
}

fn replaced(dest: &Place, dry_run: bool) -> TransferWarning {
    let message = match dry_run {
        true => format!("{} exists and would be deleted before the import", dest.display()),
        false => format!("the overwrite deleted what was at {} and wrote the transferred item", dest.display()),
    };
    warning(CODE_DESTINATION_REPLACED, dest.display(), message)
}

/// Dry run: settle the destination name with reads and capability probes,
/// exactly as a run would, and write nothing.
#[maybe_async::maybe_async]
async fn plan_destination(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
    snapshot: &Snapshot,
    warnings: &mut Vec<TransferWarning>,
) -> Result<Place, RvError> {
    let dest = &plan.destination;
    let chosen = match plan.conflict {
        Conflict::Refuse => {
            match exists(core, caller, plan.kind, dest).await? {
                Some(true) => return Err(collision(dest, "it already exists; choose on_conflict rename or overwrite")),
                Some(false) => {}
                None => warnings.push(not_checked(dest)),
            }
            dest.clone()
        }
        Conflict::Overwrite => {
            let mut checks = write_checks(plan.kind, dest, snapshot);
            checks.push((dest.item(plan.kind), Right::Delete));
            require(core, caller, &dest.ns, &checks, "an overwrite").await?;
            match exists(core, caller, plan.kind, dest).await? {
                Some(true) => warnings.push(replaced(dest, true)),
                Some(false) => {}
                None => warnings.push(not_checked(dest)),
            }
            return Ok(dest.clone());
        }
        Conflict::Rename => {
            let mut free = None;
            for name in candidates(&dest.path) {
                let candidate = dest.named(name);
                match exists(core, caller, plan.kind, &candidate).await? {
                    Some(true) => continue,
                    Some(false) => {}
                    None => warnings.push(not_checked(&candidate)),
                }
                free = Some(candidate);
                break;
            }
            let free = free.ok_or_else(|| no_free_name(dest))?;
            warnings.extend(renamed(plan.kind, dest, &free));
            free
        }
    };
    require(core, caller, &chosen.ns, &write_checks(plan.kind, &chosen, snapshot), "the import").await?;
    Ok(chosen)
}

/// A 409 that names the destination path.
fn collision(dest: &Place, detail: &str) -> RvError {
    RvError::ErrResponseStatus(409, format!("{}: {detail}", dest.display()))
}

/// The import of `body` at `dest`; answers the place the engine wrote.
#[maybe_async::maybe_async]
async fn import(
    core: &dyn VaultCtx,
    caller: &Request,
    kind: Kind,
    dest: &Place,
    body: &Map<String, Value>,
) -> Result<Place, RvError> {
    let what = format!("the caller may not write {} in {}", dest.display(), namespace_label(&dest.ns));
    let resp = call(core, caller, &dest.ns, Operation::Write, dest.import(), Some(body.clone())).await;
    let data = resp.map_err(|e| refused(e, &what))?.and_then(|r| r.data).unwrap_or_default();
    let field = match kind {
        Kind::Resource => "name",
        Kind::KvSecret => "path",
    };
    match data.get(field).and_then(Value::as_str) {
        Some(written) => Ok(dest.named(written.to_string())),
        None => Err(crate::bv_error_string!(format!("the import into {} did not say what it wrote", dest.display()))),
    }
}

fn import_body(kind: Kind, snapshot: &Snapshot, origin: String, origin_owner: &str) -> Map<String, Value> {
    let mut body = snapshot.content.clone();
    body.insert("on_conflict".into(), json!("refuse"));
    if kind == Kind::Resource {
        body.insert("origin".into(), json!(origin));
        body.insert("origin_owner".into(), json!(origin_owner));
    }
    body
}

/// Write the item into the destination per `on_conflict`. `rename` tries
/// `refuse` imports name by name, so the ACL sees each name; `overwrite` is an
/// ordinary DELETE (owner, shares and groups cleaned up) and then an import.
#[maybe_async::maybe_async]
async fn write_destination(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
    body: &Map<String, Value>,
    snapshot: &Snapshot,
    warnings: &mut Vec<TransferWarning>,
) -> Result<Place, RvError> {
    let (dest, kind) = (&plan.destination, plan.kind);
    match plan.conflict {
        Conflict::Refuse => import(core, caller, kind, dest, body).await.map_err(|e| match e {
            RvError::ErrResponseStatus(409, detail) => collision(dest, &detail),
            other => other,
        }),
        Conflict::Rename => {
            for name in candidates(&dest.path) {
                match import(core, caller, kind, &dest.named(name), body).await {
                    Ok(written) => {
                        warnings.extend(renamed(kind, dest, &written));
                        return Ok(written);
                    }
                    Err(e) if is_name_conflict(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
            Err(no_free_name(dest))
        }
        Conflict::Overwrite => {
            let mut checks = write_checks(kind, dest, snapshot);
            checks.push((dest.item(kind), Right::Delete));
            require(core, caller, &dest.ns, &checks, "an overwrite").await?;
            match import(core, caller, kind, dest, body).await {
                Ok(written) => return Ok(written),
                Err(e) if is_name_conflict(&e) => {
                    // Delete only what a read shows is there (or cannot show): a
                    // 409 on a name the caller sees free is leftover data.
                    if exists(core, caller, kind, dest).await? == Some(false) {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
            // The destination gates (brokered credential, agent access) depend on
            // the replaced item's asset groups, which this delete prunes, so they
            // cannot be checked before it: a failure below reports the deletion.
            let what = format!("the caller may not delete {} in {}", dest.display(), namespace_label(&dest.ns));
            call(core, caller, &dest.ns, Operation::Delete, dest.item(kind), None)
                .await
                .map_err(|e| refused(e, &what))?;
            match import(core, caller, kind, dest, body).await {
                Ok(written) => {
                    warnings.push(replaced(dest, false));
                    Ok(written)
                }
                Err(e) => {
                    log::warn!(
                        target: "security",
                        "namespace-transfer: overwrite deleted {} but the import failed (status {})",
                        dest.display(),
                        status_of(&e)
                    );
                    let (status, detail) = split(e);
                    let hint = match status == 409 && !detail.starts_with(BROKERED_GATE_CODE) {
                        true => "; leftover data from an interrupted import cannot be cleared through the API, use on_conflict rename",
                        false => "",
                    };
                    let message = format!(
                        "the overwrite ran an ordinary DELETE of {}, which removed what was there, but the import then \
                         failed: {detail}{hint}; the source is untouched",
                        dest.display()
                    );
                    Err(RvError::ErrResponseStatus(status, message))
                }
            }
        }
    }
}

/// Seam for Task 4b: re-create the shares, asset-group membership and
/// attached files of the item at `destination`. Called after the import (on a
/// dry run, after the probes) and before a move deletes the source; it reports
/// how many shares it wrote and what it dropped. Carries nothing yet.
#[maybe_async::maybe_async]
async fn carry_relations(
    _core: &dyn VaultCtx,
    _caller: &Request,
    _kind: Kind,
    _source: &Place,
    _destination: &Place,
    _dry_run: bool,
) -> Result<(usize, Vec<TransferWarning>), RvError> {
    Ok((0, Vec::new()))
}

/// Re-read the source and delete it only if it still matches what was copied.
/// Any failure leaves the complete copy and says so.
#[maybe_async::maybe_async]
async fn finish_move(
    core: &dyn VaultCtx,
    caller: &Request,
    plan: &Plan,
    snapshot: &Snapshot,
    written: &Place,
) -> Result<(), RvError> {
    let src = &plan.source;
    let (counts, copy) = (snapshot.counts, written.display());
    let copied = format!("the copy at {copy} ({} secrets, {} versions) is complete", counts.secrets, counts.versions);
    let partial = |e: RvError, what: &str| {
        log::warn!(target: "security", "namespace-transfer: move left the source {} and a copy at {copy}", src.display());
        let (status, detail) = split(e);
        let message = format!("{copied}, but the source {} {what}: {detail}; review both", src.display());
        RvError::ErrResponseStatus(status, message)
    };

    let again = match read_source(core, caller, plan.kind, src).await {
        Ok(again) => again,
        Err(e) => return Err(partial(e, "could not be read again to verify the copy, so it was not deleted")),
    };
    if again.content != snapshot.content {
        log::warn!(target: "security", "namespace-transfer: source {} changed during a move to {copy}", src.display());
        let message = format!(
            "the source {} changed while it was being moved, so it was not deleted; {copied}. Compare the two and delete one",
            src.display()
        );
        return Err(RvError::ErrResponseStatus(409, message));
    }
    let what = format!("the caller may not delete {} in {}", src.display(), namespace_label(&src.ns));
    match call(core, caller, &src.ns, Operation::Delete, src.item(plan.kind), None).await {
        Ok(_) => Ok(()),
        Err(e) => Err(partial(refused(e, &what), "could not be deleted")),
    }
}

/// Copy or move one item with `caller`'s token: read the source, probe the
/// rights, settle the destination name, import, then (move) verify and delete
/// the source. A failure before the import writes nothing; one after it keeps
/// the copy and says so. Never returns or logs a secret value.
#[maybe_async::maybe_async]
pub async fn run_transfer(
    core: &dyn VaultCtx,
    caller: &Request,
    op: TransferOp,
    t: TransferRequest,
) -> Result<TransferResult, RvError> {
    let plan = Plan::new(op, t)?;
    check_place(core, caller, plan.kind, &plan.source, "source").await?;
    check_place(core, caller, plan.kind, &plan.destination, "destination").await?;
    let snapshot = read_source(core, caller, plan.kind, &plan.source).await?;
    let mut warnings = snapshot.warnings.clone();
    let origin_owner = match plan.kind {
        Kind::Resource => read_origin_owner(core, caller, &plan.source, &mut warnings).await?,
        Kind::KvSecret => String::new(),
    };
    if plan.op == TransferOp::Move {
        let origin = [(plan.source.item(plan.kind), Right::Delete)];
        require(core, caller, &plan.source.ns, &origin, "a move").await?;
    }

    let written = match plan.dry_run {
        true => plan_destination(core, caller, &plan, &snapshot, &mut warnings).await?,
        false => {
            let body = import_body(plan.kind, &snapshot, plan.source.display(), &origin_owner);
            write_destination(core, caller, &plan, &body, &snapshot, &mut warnings).await?
        }
    };
    let (shares, dropped) = carry_relations(core, caller, plan.kind, &plan.source, &written, plan.dry_run).await?;
    warnings.extend(dropped);
    if plan.op == TransferOp::Move && !plan.dry_run {
        finish_move(core, caller, &plan, &snapshot, &written).await?;
    }

    let message = "policies that name the source path are not rewritten; review the destination namespace's policies";
    warnings.push(warning(CODE_POLICIES_NOT_CARRIED, plan.source.display(), message));
    let transferred = Transferred { shares, ..snapshot.counts };
    log::info!(
        target: "security",
        "namespace-transfer: op={} kind={} user={} source={} destination={} dry_run={} secrets={} versions={} history={} shares={} warnings={}",
        plan.op.as_str(),
        plan.kind.as_str(),
        caller.auth.as_ref().map(|a| a.display_name.as_str()).unwrap_or_default(),
        plan.source.display(),
        written.display(),
        plan.dry_run,
        transferred.secrets,
        transferred.versions,
        transferred.history,
        transferred.shares,
        warnings.len()
    );
    Ok(TransferResult { transferred, warnings, dry_run: plan.dry_run, destination: written.location() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(namespace: &str, mount: &str, path: &str) -> Location {
        Location { namespace: namespace.into(), mount: mount.into(), path: path.into() }
    }

    fn request(kind: &str, source: Location, destination: Location, on_conflict: &str) -> TransferRequest {
        TransferRequest { kind: kind.into(), source, destination, on_conflict: on_conflict.into(), dry_run: false }
    }

    fn status(r: Result<Plan, RvError>) -> u16 {
        r.err().map(|e| status_of(&e)).unwrap_or(200)
    }

    #[test]
    fn a_request_is_validated_before_anything_is_read() {
        let ok = |kind, src, dst| Plan::new(TransferOp::Copy, request(kind, src, dst, ""));
        let plan = ok("resource", loc("/src/", " resources/ ", " Srv1 "), loc("dst", "resources", "srv1")).unwrap();
        assert_eq!(plan.source, Place { ns: "src".into(), mount: "resources/".into(), path: "Srv1".into() });
        assert_eq!(plan.conflict, Conflict::Refuse);
        assert_eq!(plan.source.display(), "src/resources/Srv1");
        assert_eq!(plan.destination.location(), loc("dst", "resources", "srv1"));
        assert_eq!(plan.destination.import(), "resources/v2/transfer/import/srv1");
        let kv = ok("kv-secret", loc("", "secret", "team/db"), loc("dst", "secret", "team/db")).unwrap();
        assert_eq!(kv.source.display(), "secret/team/db");
        assert_eq!(kv.source.item(Kind::KvSecret), "secret/metadata/team/db");

        for (kind, src, dst) in [
            ("secret", loc("a", "secret", "x"), loc("b", "secret", "x")),
            ("resource", loc("a", "resources", "x/y"), loc("b", "resources", "x")),
            ("resource", loc("a", "resources", "x"), loc("b", "resources", "..")),
            ("resource", loc("a", "", "x"), loc("b", "resources", "x")),
            ("resource", loc("a", "sys", "x"), loc("b", "resources", "x")),
            ("resource", loc("a", "identity/", "x"), loc("b", "resources", "x")),
            ("kv-secret", loc("a", "secret", "a/../b"), loc("b", "secret", "x")),
            ("kv-secret", loc("a", "secret", "a//b"), loc("b", "secret", "x")),
            ("kv-secret", loc("a", "secret", "x\n"), loc("b", "secret", "x")),
            ("kv-secret", loc("a/../b", "secret", "x"), loc("b", "secret", "x")),
            ("resource", loc("a", "resources", "srv1"), loc("a/", "resources/", "SRV1")),
            ("kv-secret", loc("", "secret", "x"), loc("", "secret", "x")),
        ] {
            assert_eq!(status(ok(kind, src.clone(), dst.clone())), 400, "{kind} {src:?} -> {dst:?}");
        }
        let modes =
            |mode: &str| Plan::new(TransferOp::Move, request("resource", loc("a", "r", "x"), loc("b", "r", "x"), mode));
        assert_eq!(modes("rename").unwrap().conflict, Conflict::Rename);
        assert_eq!(modes(" overwrite ").unwrap().conflict, Conflict::Overwrite);
        assert_eq!(status(modes("merge")), 400);
        let kv_case = Plan::new(TransferOp::Copy, request("kv-secret", loc("", "s", "X"), loc("", "s", "x"), ""));
        assert!(kv_case.is_ok(), "KV names are exact keys");
    }

    /// Regression: a namespace written into the mount reaches the same mount
    /// as the namespace field, so an aliased pair is one item, refused in
    /// either direction and whatever the conflict mode.
    #[test]
    fn an_aliased_spelling_of_the_same_item_is_refused() {
        let aliases = [
            ("kv-secret", loc("src", "secret", "team/db"), loc("", "src/secret", "team/db")),
            ("kv-secret", loc("src", "sub/secret", "team/db"), loc("src/sub", "secret/", "team/db")),
            ("resource", loc("src", "resources", "srv1"), loc("", "/src/resources/", "SRV1")),
            ("resource", loc("src", "sub/resources", "srv1"), loc("src/sub/", "resources", "srv1")),
        ];
        for (kind, a, b) in aliases {
            for (from, to) in [(a.clone(), b.clone()), (b, a)] {
                for (op, mode) in [(TransferOp::Copy, ""), (TransferOp::Move, ""), (TransferOp::Move, "overwrite")] {
                    let r = Plan::new(op, request(kind, from.clone(), to.clone(), mode));
                    assert_eq!(status(r), 400, "{kind} {op:?} {mode} {from:?} -> {to:?}");
                }
            }
        }
        let other_root =
            Plan::new(TransferOp::Move, request("kv-secret", loc("", "secret", "x"), loc("src", "secret", "x"), ""));
        assert!(other_root.is_ok(), "the same path in another namespace is another item");
    }

    #[test]
    fn only_a_taken_name_is_a_name_conflict() {
        assert!(is_name_conflict(&RvError::ErrResponseStatus(409, "a resource named 'srv1' already exists".into())));
        let gate = format!("{BROKERED_GATE_CODE}: resource `srv1` is brokered in this namespace");
        assert!(!is_name_conflict(&RvError::ErrResponseStatus(409, gate)));
        assert!(!is_name_conflict(&RvError::ErrResponseStatus(403, "permission denied".into())));
        assert!(!is_name_conflict(&RvError::ErrPermissionDenied));
    }

    #[test]
    fn env_overrides_are_what_the_environment_adds_to_the_base() {
        let base = json!({ "v": "two", "host": "db" }).as_object().cloned().unwrap();
        let merged = json!({ "v": "two", "host": "db.prod", "tls": true }).as_object().cloned().unwrap();
        assert_eq!(Value::Object(env_overrides(&base, &merged)), json!({ "host": "db.prod", "tls": true }));
        assert!(env_overrides(&base, &base).is_empty());
    }

    #[test]
    fn rename_tries_the_name_then_bounded_suffixes() {
        let names: Vec<String> = candidates("team/db").collect();
        assert_eq!(names.len(), RENAME_MAX_SUFFIX);
        assert_eq!(names[..3], ["team/db", "team/db-2", "team/db-3"]);
        assert_eq!(names.last().unwrap(), &format!("team/db-{RENAME_MAX_SUFFIX}"));
    }

    #[test]
    fn a_right_is_held_only_without_deny() {
        assert!(Right::Write.held_in(&["create"]) && Right::Write.held_in(&["update"]));
        assert!(Right::Delete.held_in(&["delete"]) && Right::Delete.held_in(&["root"]));
        assert!(!Right::Delete.held_in(&["create", "update", "read"]));
        assert!(!Right::Write.held_in(&["deny", "create"]) && !Right::Delete.held_in(&["deny", "root"]));
        assert!(!Right::Write.held_in(&[]));
    }

    #[test]
    fn a_denied_step_says_which_one_and_keeps_other_errors() {
        let e = refused(RvError::ErrPermissionDenied, "the caller may not read x");
        assert_eq!(status_of(&e), 403);
        assert!(matches!(e, RvError::ErrResponseStatus(403, ref m) if m.contains("may not read x")));
        assert!(matches!(
            refused(RvError::ErrResponseStatus(409, "taken".into()), "x"),
            RvError::ErrResponseStatus(409, _)
        ));
    }
}
