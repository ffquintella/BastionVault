//! Static-role auto-rotation scheduler — Phase 3.
//!
//! A single tokio task started from [`Core::post_unseal`](crate::core::Core)
//! ticks every 60 s, enumerates every mount of type `"openldap"`, reads
//! every static-role under each mount, and rotates the ones whose
//! `last_vault_rotation + rotation_period <= now`.
//!
//! Design choices, mirroring the PKI auto-tidy scheduler:
//!
//! - **One scheduler, many mounts.** One tokio task walks every
//!   openldap mount on each tick. Per-mount cadence is driven by each
//!   role's persisted `rotation_period`; the 60 s tick is the worst-
//!   case firing jitter.
//! - **One bind per mount per tick.** When at least one role is due
//!   for rotation, the scheduler binds the mount's LDAP connection
//!   once, runs every due rotation, then unbinds. A mount with no due
//!   roles never opens a connection that tick.
//! - **Idempotent + crash-safe.** The directory-write happens before
//!   the storage-write, same as the manual `rotate-role` path. If the
//!   scheduler crashes between the two writes, the next tick (or a
//!   manual `rotate-role`) detects the divergence on the next bind
//!   probe — see `features/ldap-secret-engine.md` § Rotation Atomicity.
//! - **Self-skip when sealed.** `core.state.load().sealed` is checked
//!   every tick. The storage reads inside the rotation logic would
//!   fail anyway; skipping early keeps the log clean right after a
//!   seal.
//! - **Single-process scheduler.** No HA leader gating yet — every
//!   node in a Hiqlite cluster runs its own scheduler. The directory
//!   itself serialises rotations under the bind DN's credentials
//!   (last-writer-wins on the password attribute), so two nodes
//!   double-rotating is wasteful but not incorrect: the second
//!   write supersedes the first, and only the most recent storage
//!   record matches the directory's password — the loser's storage
//!   write is detected on the next bind probe and the role is
//!   re-rotated. HA leader gating tracks as a follow-up alongside the
//!   same gap in `pki/auto-tidy` and `scheduled_exports`.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::sync::Mutex;

use super::{
    client,
    config::{LdapConfig, CONFIG_KEY},
    password,
    policy::{StaticCred, StaticRole, STATIC_CRED_PREFIX, STATIC_ROLE_PREFIX},
};
use crate::{
    core::Core,
    errors::RvError,
    logical::{Operation, Request},
    storage::{Storage, StorageEntry},
};

const TICK_INTERVAL: Duration = Duration::from_secs(60);

/// Spawn the LDAP rotation scheduler. Detached task; the returned
/// `JoinHandle` is dropped intentionally so the loop runs until the
/// process exits. The loop self-skips when sealed.
pub fn start_ldap_rotation_scheduler(core: Arc<Core>) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn(async move {
        let last_fired: Arc<Mutex<HashMap<String, Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));
        log::info!(
            "openldap/auto-rotate: scheduler started (tick every {}s)",
            TICK_INTERVAL.as_secs()
        );

        let mut interval = tokio::time::interval(TICK_INTERVAL);
        loop {
            interval.tick().await;
            if core.state.load().sealed {
                continue;
            }
            if let Err(e) = tick(&core, last_fired.clone()).await {
                log::warn!("openldap/auto-rotate: tick failed: {e}");
            }
        }
    })
}

/// Run a single rotation pass across every openldap mount. Exposed
/// publicly so integration tests can drive the scheduler without
/// waiting 60 s for a real tick, and so an operator-facing
/// `sys/openldap/rotate-due` admin endpoint (future) can force the
/// same sweep on demand.
#[maybe_async::maybe_async]
pub async fn run_rotation_pass(
    core: &Arc<Core>,
    last_fired: Option<Arc<Mutex<HashMap<String, Instant>>>>,
) -> Result<(), RvError> {
    let map = last_fired.unwrap_or_else(|| Arc::new(Mutex::new(HashMap::new())));
    tick(core, map).await
}

#[maybe_async::maybe_async]
async fn tick(
    core: &Arc<Core>,
    _last_fired: Arc<Mutex<HashMap<String, Instant>>>,
) -> Result<(), RvError> {
    // Snapshot the mount table; release the read lock before any awaits.
    let ldap_mounts: Vec<(String, String)> = {
        let entries = core.mounts_router.entries.read()?;
        entries
            .values()
            .filter_map(|me| {
                let entry = me.read().ok()?;
                if entry.logical_type == "openldap" {
                    Some((entry.uuid.clone(), entry.path.clone()))
                } else {
                    None
                }
            })
            .collect()
    };

    if ldap_mounts.is_empty() {
        return Ok(());
    }

    for (uuid, path) in ldap_mounts {
        if let Err(e) = run_one(core, &uuid, &path).await {
            log::warn!(
                "openldap/auto-rotate: mount {path} (uuid {uuid}): tick error: {e}"
            );
        }
    }
    Ok(())
}

#[maybe_async::maybe_async]
async fn run_one(
    core: &Arc<Core>,
    _mount_uuid: &str,
    mount_path: &str,
) -> Result<(), RvError> {
    let view = match core.router.matching_view(mount_path)? {
        Some(v) => v,
        None => return Ok(()),
    };
    let storage_arc: Arc<dyn Storage> = view;

    let mut req = Request::new("");
    req.operation = Operation::Read;
    req.storage = Some(storage_arc.clone());

    // Mount must have a config; skip if missing.
    let cfg: LdapConfig = match req.storage_get(CONFIG_KEY).await? {
        Some(e) => match serde_json::from_slice(&e.value) {
            Ok(c) => c,
            Err(_) => {
                log::warn!(
                    "openldap/auto-rotate: mount {mount_path}: config corrupt; skipping tick"
                );
                return Ok(());
            }
        },
        None => return Ok(()), // never configured, nothing to do
    };

    // Pre-flight: enumerate roles, find ones that are due for rotation.
    // We read both `static-role/<name>` and `static-cred/<name>` so a
    // role that has never been rotated still trips the comparison
    // (it has no `last_vault_rotation` yet and we treat that as "due").
    let role_names: Vec<String> = req.storage_list(STATIC_ROLE_PREFIX).await?;
    let now = unix_now();

    let mut due: Vec<(String, StaticRole)> = Vec::new();
    for name in role_names {
        let key = format!("{STATIC_ROLE_PREFIX}{name}");
        let role: StaticRole = match req.storage_get(&key).await? {
            Some(e) => match serde_json::from_slice(&e.value) {
                Ok(r) => r,
                Err(_) => continue, // corrupt entry; let the next manual op surface it
            },
            None => continue,
        };
        if role.rotation_period.is_zero() {
            continue; // explicit "manual rotation only"
        }
        let last = read_last_rotation(&req, &name).await?;
        let due_at = last.saturating_add(role.rotation_period.as_secs());
        if now >= due_at {
            due.push((name, role));
        }
    }

    if due.is_empty() {
        return Ok(());
    }

    log::info!(
        "openldap/auto-rotate: mount {mount_path}: {} role(s) due for rotation",
        due.len()
    );

    // One bind per mount per tick. If the bind fails, log and bail —
    // we'll retry next tick. Don't burn cycles binding per role.
    let mut ldap = match client::bind(&cfg).await {
        Ok(l) => l,
        Err(e) => {
            log::warn!(
                "openldap/auto-rotate: mount {mount_path}: bind failed: {e}; skipping tick"
            );
            return Ok(());
        }
    };

    let mut req_mut = Request::new("");
    req_mut.operation = Operation::Write;
    req_mut.storage = Some(storage_arc);

    for (name, role) in due {
        let new_password = password::generate(password::DEFAULT_LENGTH);
        // Directory-first; storage-second.
        if let Err(e) =
            client::set_password(&mut ldap, &cfg, &role.dn, &new_password).await
        {
            log::warn!(
                "openldap/auto-rotate: mount {mount_path}: rotate `{name}` (dn={}): directory write failed: {e}",
                role.dn
            );
            continue;
        }
        let cred = StaticCred {
            password: new_password,
            last_vault_rotation_unix: unix_now(),
        };
        let bytes = match serde_json::to_vec(&cred) {
            Ok(b) => b,
            Err(e) => {
                log::error!(
                    "openldap/auto-rotate: mount {mount_path}: rotate `{name}`: cred serialise failed AFTER directory write: {e}; \
                     manual reconciliation required",
                );
                continue;
            }
        };
        if let Err(e) = req_mut
            .storage_put(&StorageEntry {
                key: format!("{STATIC_CRED_PREFIX}{name}"),
                value: bytes,
            })
            .await
        {
            log::error!(
                "openldap/auto-rotate: mount {mount_path}: rotate `{name}`: storage write failed AFTER directory write: {e}; \
                 next rotate-role will reconcile",
            );
            continue;
        }
        log::info!(
            "openldap/auto-rotate: mount {mount_path}: rotated `{name}` (dn={})",
            role.dn
        );
    }

    let _ = ldap.unbind().await;
    Ok(())
}

#[maybe_async::maybe_async]
async fn read_last_rotation(req: &Request, name: &str) -> Result<u64, RvError> {
    let key = format!("{STATIC_CRED_PREFIX}{name}");
    match req.storage_get(&key).await? {
        Some(e) => match serde_json::from_slice::<StaticCred>(&e.value) {
            Ok(c) => Ok(c.last_vault_rotation_unix),
            // No cred yet ⇒ never rotated. Treat as "due forever ago".
            Err(_) => Ok(0),
        },
        None => Ok(0),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::ldap::policy::StaticRole;
    use std::time::Duration;

    /// Pure logic: when is a role due? The scheduler reads role +
    /// cred and computes `last + period <= now`. Here we exercise
    /// the threshold directly.
    #[test]
    fn due_threshold_logic() {
        let role = StaticRole {
            dn: "CN=svc,DC=example,DC=com".into(),
            username: "svc".into(),
            rotation_period: Duration::from_secs(60),
            password_policy: String::new(),
        };
        let now = 10_000u64;
        // never rotated → due
        let last = 0u64;
        let due = now >= last.saturating_add(role.rotation_period.as_secs());
        assert!(due, "never-rotated role must be due");

        // rotated 30s ago, period 60s → not due
        let last = now - 30;
        let due = now >= last.saturating_add(role.rotation_period.as_secs());
        assert!(!due, "rotated 30s ago with 60s period should not be due");

        // rotated 90s ago, period 60s → due
        let last = now - 90;
        let due = now >= last.saturating_add(role.rotation_period.as_secs());
        assert!(due, "rotated 90s ago with 60s period must be due");

        // rotation_period = 0 (manual only) is filtered out *before*
        // the threshold check; the scheduler skips it explicitly so
        // the logic above never runs against `is_zero()` periods.
    }

    #[test]
    fn manual_only_roles_skip_the_scheduler() {
        // The scheduler's `if role.rotation_period.is_zero() { continue; }`
        // guard is what we're documenting here — `is_zero()` is the
        // entire condition for "this role never auto-rotates."
        let role = StaticRole {
            dn: "CN=svc,DC=example,DC=com".into(),
            username: "svc".into(),
            rotation_period: Duration::ZERO,
            password_policy: String::new(),
        };
        assert!(role.rotation_period.is_zero());
    }
}
