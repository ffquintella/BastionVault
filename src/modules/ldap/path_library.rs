//! `/v1/openldap/library` CRUD + `/check-out` + `/check-in` + `/status`.
//!
//! A `library` is a *pool* of pre-provisioned accounts that share a
//! purpose (e.g. four `svc_etl_*` accounts that all have the same
//! grants). On check-out the engine atomically picks an available
//! account, rotates its password, hands the password to the caller,
//! and persists a checked-out marker. On check-in (or lease expiry
//! via the future scheduler) the engine rotates again and removes
//! the marker.
//!
//! Concurrency: a per-mount `tokio::sync::Mutex` over the
//! library-set storage entry serialises check-out attempts on the
//! same set, so two callers can't race for the same account.

use std::{collections::HashMap, sync::Arc, time::SystemTime};

use dashmap::DashMap;
#[allow(unused_imports)]
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{
    client,
    policy::{CheckOutRecord, LibrarySet, LIBRARY_PREFIX},
    LdapBackend, LdapBackendInner,
};
use crate::{
    context::Context,
    errors::RvError,
    logical::{Backend, Field, FieldType, Operation, Path, PathOperation, Request, Response},
    new_fields, new_fields_internal, new_path, new_path_internal,
    storage::StorageEntry,
};

const SET_HELP: &str =
    "Library set CRUD. POST creates / updates a pool of `service_account_names`; DELETE removes the set + all check-out records.";
const CHECK_OUT_HELP: &str = "Check out an available account from the pool. Generates a fresh password, writes it to the directory, and returns the credential + lease metadata.";
const CHECK_IN_HELP: &str = "Release a checked-out account. Rotates the password and marks the account available.";
const STATUS_HELP: &str = "Show which accounts in the pool are currently checked out and which are available.";
const LIST_HELP: &str = "List configured library set names.";

/// Per-mount serialisation gate for check-out / check-in. Keyed by
/// `(mount-uuid, set-name)` — the mount-uuid component is implicit
/// in the storage prefix the request operates on, but we use the
/// set-name alone here because every request flows through a
/// distinct `Request` whose storage view is already mount-scoped.
fn library_locks() -> &'static DashMap<String, Arc<Mutex<()>>> {
    use std::sync::OnceLock;
    static M: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

fn lock_for(set: &str) -> Arc<Mutex<()>> {
    library_locks()
        .entry(set.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

impl LdapBackend {
    pub fn library_set_path(&self) -> Path {
        let read = self.inner.clone();
        let write = self.inner.clone();
        let delete = self.inner.clone();
        new_path!({
            pattern: r"library/(?P<set>\w[\w-]*\w)",
            fields: {
                "set":                          { field_type: FieldType::Str,  required: true, description: "Library set name." },
                "service_account_names":        { field_type: FieldType::Str,  default: "", description: "Comma-separated list of DNs / short names." },
                "ttl":                          { field_type: FieldType::Int,  default: 3600, description: "Default check-out duration in seconds." },
                "max_ttl":                      { field_type: FieldType::Int,  default: 86400, description: "Hard cap in seconds." },
                "disable_check_in_enforcement": { field_type: FieldType::Bool, default: false, description: "When true, any caller can check in (default refuses cross-entity check-in)." }
            },
            operations: [
                {op: Operation::Read,   handler: read.handle_set_read},
                {op: Operation::Write,  handler: write.handle_set_write},
                {op: Operation::Delete, handler: delete.handle_set_delete}
            ],
            help: SET_HELP
        })
    }

    pub fn library_list_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"library/?$",
            operations: [{op: Operation::List, handler: h.handle_set_list}],
            help: LIST_HELP
        })
    }

    pub fn library_check_out_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"library/(?P<set>\w[\w-]*\w)/check-out",
            fields: {
                "set": { field_type: FieldType::Str, required: true, description: "Library set name." },
                "ttl": { field_type: FieldType::Int, default: 0, description: "Per-call TTL override (capped at the set's max_ttl). 0 = use set default." }
            },
            operations: [{op: Operation::Write, handler: h.handle_check_out}],
            help: CHECK_OUT_HELP
        })
    }

    pub fn library_check_in_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"library/(?P<set>\w[\w-]*\w)/check-in",
            fields: {
                "set":     { field_type: FieldType::Str, required: true, description: "Library set name." },
                "account": { field_type: FieldType::Str, default: "", description: "Account to release. Empty releases the caller's only checked-out account." }
            },
            operations: [{op: Operation::Write, handler: h.handle_check_in}],
            help: CHECK_IN_HELP
        })
    }

    pub fn library_status_path(&self) -> Path {
        let h = self.inner.clone();
        new_path!({
            pattern: r"library/(?P<set>\w[\w-]*\w)/status",
            fields: {
                "set": { field_type: FieldType::Str, required: true, description: "Library set name." }
            },
            operations: [{op: Operation::Read, handler: h.handle_status}],
            help: STATUS_HELP
        })
    }
}

#[maybe_async::maybe_async]
impl LdapBackendInner {
    pub async fn get_set(
        &self,
        req: &Request,
        set: &str,
    ) -> Result<Option<LibrarySet>, RvError> {
        match req.storage_get(&format!("{LIBRARY_PREFIX}{set}")).await? {
            Some(e) => Ok(Some(serde_json::from_slice(&e.value)?)),
            None => Ok(None),
        }
    }

    pub async fn put_set(
        &self,
        req: &mut Request,
        set: &str,
        s: &LibrarySet,
    ) -> Result<(), RvError> {
        let bytes = serde_json::to_vec(s)?;
        req.storage_put(&StorageEntry {
            key: format!("{LIBRARY_PREFIX}{set}"),
            value: bytes,
        })
        .await
    }

    pub async fn handle_set_read(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let set = take_str(req, "set");
        match self.get_set(req, &set).await? {
            None => Ok(None),
            Some(s) => {
                let mut data = Map::new();
                data.insert(
                    "service_account_names".into(),
                    Value::Array(
                        s.service_account_names
                            .iter()
                            .map(|n| Value::String(n.clone()))
                            .collect(),
                    ),
                );
                data.insert("ttl".into(), Value::Number(s.ttl.as_secs().into()));
                data.insert("max_ttl".into(), Value::Number(s.max_ttl.as_secs().into()));
                data.insert(
                    "disable_check_in_enforcement".into(),
                    Value::Bool(s.disable_check_in_enforcement),
                );
                Ok(Some(Response::data_response(Some(data))))
            }
        }
    }

    pub async fn handle_set_write(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let set = take_str(req, "set");
        if set.is_empty() {
            return Err(RvError::ErrString("set name is required".into()));
        }
        let raw = take_str(req, "service_account_names");
        let names: Vec<String> = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let ttl = req.get_data("ttl").ok().and_then(|v| v.as_u64()).unwrap_or(3600);
        let max_ttl = req.get_data("max_ttl").ok().and_then(|v| v.as_u64()).unwrap_or(86400);
        let s = LibrarySet {
            service_account_names: names,
            ttl: std::time::Duration::from_secs(ttl),
            max_ttl: std::time::Duration::from_secs(max_ttl),
            disable_check_in_enforcement: req
                .get_data("disable_check_in_enforcement")
                .ok()
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        };
        s.validate().map_err(RvError::ErrString)?;
        self.put_set(req, &set, &s).await?;
        Ok(None)
    }

    pub async fn handle_set_delete(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let set = take_str(req, "set");
        // Drop check-out records under the set first, then the set itself.
        let prefix = format!("{LIBRARY_PREFIX}{set}/checked-out/");
        if let Ok(children) = req.storage_list(&prefix).await {
            for child in children {
                let _ = req.storage_delete(&format!("{prefix}{child}")).await;
            }
        }
        let _ = req.storage_delete(&format!("{LIBRARY_PREFIX}{set}")).await;
        Ok(None)
    }

    pub async fn handle_set_list(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let names = req.storage_list(LIBRARY_PREFIX).await?;
        // The storage layout has both `library/<set>` and
        // `library/<set>/checked-out/...`; filter the children so
        // the LIST returns only set names.
        let names: Vec<String> = names
            .into_iter()
            .filter(|n| !n.contains('/'))
            .collect();
        Ok(Some(Response::list_response(&names)))
    }

    pub async fn handle_check_out(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let set_name = take_str(req, "set");
        let _gate = lock_for(&set_name).lock_owned().await;

        let set = self
            .get_set(req, &set_name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown library set `{set_name}`")))?;

        // Determine effective TTL.
        let mut ttl = req
            .get_data("ttl")
            .ok()
            .and_then(|v| v.as_u64())
            .map(std::time::Duration::from_secs)
            .unwrap_or(set.ttl);
        if !set.max_ttl.is_zero() && ttl > set.max_ttl {
            ttl = set.max_ttl;
        }

        // Find the first available account.
        let prefix = format!("{LIBRARY_PREFIX}{set_name}/checked-out/");
        let in_flight = req.storage_list(&prefix).await.unwrap_or_default();
        let in_flight_set: std::collections::BTreeSet<String> = in_flight
            .into_iter()
            .map(|n| n.trim_end_matches('/').to_string())
            .collect();
        let chosen = set
            .service_account_names
            .iter()
            .find(|n| !in_flight_set.contains(*n))
            .ok_or_else(|| {
                RvError::ErrString(format!(
                    "library `{set_name}` is exhausted; every account is checked out"
                ))
            })?
            .clone();

        let cfg = self
            .load_config(req)
            .await?
            .ok_or_else(|| RvError::ErrString("ldap engine not configured".into()))?;

        let new_password = super::password::generate(super::password::DEFAULT_LENGTH);
        let mut ldap = client::bind(&cfg)
            .await
            .map_err(|e| RvError::ErrString(format!("check-out: bind: {e}")))?;
        client::set_password(&mut ldap, &cfg, &chosen, &new_password)
            .await
            .map_err(|e| RvError::ErrString(format!("check-out: write: {e}")))?;
        let _ = ldap.unbind().await;

        let now = unix_now();
        let lease_id = format!("ldap-library-{}", Uuid::new_v4());
        let entity = req.client_token.clone(); // best-effort identity carrier
        let record = CheckOutRecord {
            set: set_name.clone(),
            account: chosen.clone(),
            lease_id: lease_id.clone(),
            checked_out_by: entity,
            checked_out_at_unix: now,
            expires_at_unix: now.saturating_add(ttl.as_secs()),
        };
        let bytes = serde_json::to_vec(&record)?;
        req.storage_put(&StorageEntry {
            key: format!("{prefix}{chosen}"),
            value: bytes,
        })
        .await?;

        let mut data = Map::new();
        data.insert("service_account_name".into(), Value::String(chosen));
        data.insert("password".into(), Value::String(new_password));
        data.insert("lease_id".into(), Value::String(lease_id));
        data.insert("ttl_secs".into(), Value::Number(ttl.as_secs().into()));
        Ok(Some(Response::data_response(Some(data))))
    }

    pub async fn handle_check_in(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let set_name = take_str(req, "set");
        let account_in = take_str(req, "account");
        let _gate = lock_for(&set_name).lock_owned().await;

        let set = self
            .get_set(req, &set_name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown library set `{set_name}`")))?;

        let prefix = format!("{LIBRARY_PREFIX}{set_name}/checked-out/");
        // If `account` was supplied, target it directly; otherwise
        // pick the caller's only checked-out account (and refuse if
        // there isn't exactly one).
        let entity = req.client_token.clone();
        let to_release = if !account_in.is_empty() {
            account_in.clone()
        } else {
            let in_flight = req.storage_list(&prefix).await.unwrap_or_default();
            let mut owned: Vec<String> = Vec::new();
            for child in in_flight {
                let key = format!("{prefix}{}", child.trim_end_matches('/'));
                if let Ok(Some(entry)) = req.storage_get(&key).await {
                    if let Ok(rec) = serde_json::from_slice::<CheckOutRecord>(&entry.value) {
                        if rec.checked_out_by == entity {
                            owned.push(rec.account);
                        }
                    }
                }
            }
            if owned.len() != 1 {
                return Err(RvError::ErrString(format!(
                    "supply `account` explicitly: caller has {} checked-out account(s) in `{set_name}`",
                    owned.len()
                )));
            }
            owned.into_iter().next().unwrap()
        };

        let key = format!("{prefix}{to_release}");
        let entry = req
            .storage_get(&key)
            .await?
            .ok_or_else(|| {
                RvError::ErrString(format!(
                    "account `{to_release}` is not checked out in `{set_name}`"
                ))
            })?;
        let record: CheckOutRecord = serde_json::from_slice(&entry.value)?;

        if !set.disable_check_in_enforcement && record.checked_out_by != entity {
            // Constant-time compare to avoid timing oracles on entity ids.
            use subtle::ConstantTimeEq;
            let owner = record.checked_out_by.as_bytes();
            let caller = entity.as_bytes();
            let same = owner.len() == caller.len()
                && bool::from(owner.ct_eq(caller));
            if !same {
                return Err(RvError::ErrString(
                    "check-in refused: caller is not the owner of this check-out".into(),
                ));
            }
        }

        // Rotate again to invalidate the password the caller still holds.
        let cfg = self
            .load_config(req)
            .await?
            .ok_or_else(|| RvError::ErrString("ldap engine not configured".into()))?;
        let new_password = super::password::generate(super::password::DEFAULT_LENGTH);
        let mut ldap = client::bind(&cfg)
            .await
            .map_err(|e| RvError::ErrString(format!("check-in: bind: {e}")))?;
        client::set_password(&mut ldap, &cfg, &to_release, &new_password)
            .await
            .map_err(|e| RvError::ErrString(format!("check-in: write: {e}")))?;
        let _ = ldap.unbind().await;

        req.storage_delete(&key).await?;
        Ok(None)
    }

    pub async fn handle_status(
        &self,
        _b: &dyn Backend,
        req: &mut Request,
    ) -> Result<Option<Response>, RvError> {
        let set_name = take_str(req, "set");
        let set = self
            .get_set(req, &set_name)
            .await?
            .ok_or_else(|| RvError::ErrString(format!("unknown library set `{set_name}`")))?;

        let prefix = format!("{LIBRARY_PREFIX}{set_name}/checked-out/");
        let in_flight = req.storage_list(&prefix).await.unwrap_or_default();
        let mut checked_out = Map::new();
        for child in in_flight {
            let key = format!("{prefix}{}", child.trim_end_matches('/'));
            if let Ok(Some(entry)) = req.storage_get(&key).await {
                if let Ok(rec) = serde_json::from_slice::<CheckOutRecord>(&entry.value) {
                    let mut entry_data = Map::new();
                    entry_data.insert("lease_id".into(), Value::String(rec.lease_id));
                    entry_data.insert(
                        "expires_at_unix".into(),
                        Value::Number(rec.expires_at_unix.into()),
                    );
                    checked_out.insert(rec.account, Value::Object(entry_data));
                }
            }
        }
        let available: Vec<Value> = set
            .service_account_names
            .iter()
            .filter(|n| !checked_out.contains_key(*n))
            .map(|n| Value::String(n.clone()))
            .collect();

        let mut data = Map::new();
        data.insert("checked_out".into(), Value::Object(checked_out));
        data.insert("available".into(), Value::Array(available));
        Ok(Some(Response::data_response(Some(data))))
    }
}

fn take_str(req: &Request, key: &str) -> String {
    req.get_data(key)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
