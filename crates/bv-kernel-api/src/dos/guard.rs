//! In-memory IP request-abuse guard.
//!
//! [`DosGuard`] is the hot-path enforcement primitive. It is process-local by
//! design (the request path must never touch storage): each node counts the
//! traffic it directly sees and bans abusive IPs locally. Configuration and
//! *manual* bans are persisted separately (see [`super::store`]) so they
//! survive restart and converge across an HA cluster; automatic bans and the
//! live per-IP counters are ephemeral per node.
//!
//! Locking discipline: the `windows` and `bans` maps are guarded by separate
//! `Mutex`es that are only ever locked one at a time (never nested), so there
//! is no lock-ordering hazard.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

use super::config::DosConfig;

/// Wall-clock seconds since the Unix epoch, saturating to `0` on the
/// (impossible in practice) pre-epoch clock.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Why an IP is banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BanKind {
    /// Applied automatically because the IP crossed a configured threshold.
    Auto,
    /// Applied manually by an operator through the API.
    Manual,
}

/// A persisted manual ban. Serialized into the barrier as part of
/// [`super::store::PersistedDosState`]. `IpAddr` serializes as its canonical
/// string form under serde_json.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualBan {
    pub ip: IpAddr,
    /// Absolute expiry, Unix seconds. A record with `until_unix <= now` is
    /// treated as expired and skipped on load.
    pub until_unix: u64,
    pub reason: String,
}

/// Live in-memory ban record.
struct BanState {
    /// Monotonic expiry used for enforcement.
    until: Instant,
    kind: BanKind,
    reason: String,
    /// Absolute expiry (Unix seconds) — present for manual bans so they can be
    /// re-persisted and displayed; `None` for ephemeral auto-bans.
    until_unix: Option<u64>,
}

/// Fixed-window request counters for one IP.
struct Window {
    count_total: u64,
    count_auth: u64,
    start: Instant,
}

/// Outcome of a denied [`DosGuard::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanInfo {
    /// Seconds until the ban expires (for a `Retry-After` header).
    pub retry_after_secs: u64,
    pub reason: String,
    pub kind: BanKind,
    /// `true` only on the request that first triggered an automatic ban, so
    /// the caller can emit exactly one audit event per ban instead of one per
    /// blocked request.
    pub newly_banned: bool,
}

/// A tracked IP's current-window activity, for the stats panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpUsage {
    pub ip: IpAddr,
    pub requests: u64,
    pub auth_requests: u64,
    pub window_secs: u64,
}

/// An active ban, for the stats panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    pub ip: IpAddr,
    pub kind: BanKind,
    pub reason: String,
    pub expires_in_secs: u64,
    /// Absolute expiry (Unix seconds) for manual bans; `None` for auto-bans.
    pub until_unix: Option<u64>,
}

/// Snapshot returned by [`DosGuard::stats`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DosStats {
    pub config: DosConfig,
    pub tracked: Vec<IpUsage>,
    pub bans: Vec<BanRecord>,
}

/// Maximum number of tracked IPs returned in a stats snapshot, to bound the
/// response size under a broad flood. The busiest IPs are reported first.
const STATS_TRACKED_CAP: usize = 200;

pub struct DosGuard {
    config: ArcSwap<DosConfig>,
    windows: Mutex<HashMap<IpAddr, Window>>,
    bans: Mutex<HashMap<IpAddr, BanState>>,
}

impl DosGuard {
    pub fn new(config: DosConfig) -> Self {
        Self {
            config: ArcSwap::from_pointee(config.sanitized()),
            windows: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
        }
    }

    /// Replace the active configuration. Values are sanitized first.
    pub fn set_config(&self, config: DosConfig) {
        self.config.store(std::sync::Arc::new(config.sanitized()));
    }

    /// Current configuration (cloned).
    pub fn config(&self) -> DosConfig {
        (**self.config.load()).clone()
    }

    /// Admit or reject one request from `ip` to `path`.
    ///
    /// Returns `Err(BanInfo)` when the IP is currently banned (either a still
    /// live prior ban, or a new auto-ban triggered by this very request).
    /// Otherwise records the request against the IP's window and returns `Ok`.
    ///
    /// Fails open on `enabled == false`: no counting, no bans.
    pub fn check(&self, ip: IpAddr, path: &str) -> Result<(), BanInfo> {
        let cfg = self.config.load();
        if !cfg.enabled {
            return Ok(());
        }
        let now = Instant::now();

        // 1. Reject if a live ban exists; drop it if it has expired.
        {
            let mut bans = self.bans.lock().unwrap();
            if let Some(b) = bans.get(&ip) {
                if b.until > now {
                    let retry = b.until.saturating_duration_since(now).as_secs().max(1);
                    return Err(BanInfo {
                        retry_after_secs: retry,
                        reason: b.reason.clone(),
                        kind: b.kind,
                        newly_banned: false,
                    });
                }
                bans.remove(&ip);
            }
        }

        // 2. Count this request in the IP's fixed window.
        let is_auth = is_auth_path(path);
        let (over_general, over_auth) = {
            let mut windows = self.windows.lock().unwrap();
            let w = windows
                .entry(ip)
                .or_insert_with(|| Window { count_total: 0, count_auth: 0, start: now });
            if now.duration_since(w.start) >= Duration::from_secs(cfg.window_secs) {
                w.count_total = 0;
                w.count_auth = 0;
                w.start = now;
            }
            w.count_total += 1;
            if is_auth {
                w.count_auth += 1;
            }
            let over_general = cfg.max_requests > 0 && w.count_total > cfg.max_requests;
            let over_auth = cfg.auth_max_requests > 0 && is_auth && w.count_auth > cfg.auth_max_requests;
            (over_general, over_auth)
        };

        // 3. Apply an automatic ban if a threshold was crossed and banning is
        //    enabled (ban_secs > 0).
        if (over_general || over_auth) && cfg.ban_secs > 0 {
            let reason = if over_auth {
                format!(
                    "authentication request rate exceeded: >{} req/{}s to auth paths",
                    cfg.auth_max_requests, cfg.window_secs
                )
            } else {
                format!(
                    "request rate exceeded: >{} req/{}s",
                    cfg.max_requests, cfg.window_secs
                )
            };
            let mut bans = self.bans.lock().unwrap();
            // Don't clobber a still-live ban (e.g. a manual one) with a fresh
            // auto-ban; only the transition into a ban is "newly banned".
            let newly_banned = bans.get(&ip).is_none_or(|b| b.until <= now);
            if newly_banned {
                bans.insert(
                    ip,
                    BanState {
                        until: now + Duration::from_secs(cfg.ban_secs),
                        kind: BanKind::Auto,
                        reason: reason.clone(),
                        until_unix: None,
                    },
                );
            }
            let existing_retry = bans
                .get(&ip)
                .map(|b| b.until.saturating_duration_since(now).as_secs().max(1))
                .unwrap_or(cfg.ban_secs);
            return Err(BanInfo {
                retry_after_secs: existing_retry,
                reason,
                kind: BanKind::Auto,
                newly_banned,
            });
        }

        Ok(())
    }

    /// Ban `ip` manually for `ttl_secs`. Returns the absolute expiry (Unix
    /// seconds) so the caller can persist it. Overwrites any existing ban for
    /// the IP.
    pub fn manual_ban(&self, ip: IpAddr, ttl_secs: u64, reason: &str) -> u64 {
        let now = Instant::now();
        let until_unix = now_unix() + ttl_secs;
        self.bans.lock().unwrap().insert(
            ip,
            BanState {
                until: now + Duration::from_secs(ttl_secs),
                kind: BanKind::Manual,
                reason: reason.to_string(),
                until_unix: Some(until_unix),
            },
        );
        until_unix
    }

    /// Lift any ban (manual or automatic) on `ip`. Returns whether one existed.
    pub fn unban(&self, ip: IpAddr) -> bool {
        self.windows.lock().unwrap().remove(&ip);
        self.bans.lock().unwrap().remove(&ip).is_some()
    }

    /// Replace the in-memory set of *manual* bans with `records` (auto-bans are
    /// left untouched). Expired records are skipped. Called at unseal and on
    /// each periodic refresh so persisted manual bans converge across nodes.
    pub fn load_manual_bans(&self, records: &[ManualBan]) {
        let now = Instant::now();
        let now_u = now_unix();
        let mut bans = self.bans.lock().unwrap();
        bans.retain(|_, b| b.kind != BanKind::Manual);
        for r in records {
            if r.until_unix <= now_u {
                continue;
            }
            let remaining = r.until_unix - now_u;
            bans.insert(
                r.ip,
                BanState {
                    until: now + Duration::from_secs(remaining),
                    kind: BanKind::Manual,
                    reason: r.reason.clone(),
                    until_unix: Some(r.until_unix),
                },
            );
        }
    }

    /// Drop expired bans and stale windows. Cheap; called on a timer.
    pub fn sweep(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.load().window_secs.max(1));
        self.windows.lock().unwrap().retain(|_, w| now.duration_since(w.start) < window);
        self.bans.lock().unwrap().retain(|_, b| b.until > now);
    }

    /// Build a snapshot for the stats panel: the current configuration, the
    /// busiest tracked IPs (capped), and every active ban.
    pub fn stats(&self) -> DosStats {
        let now = Instant::now();
        let cfg = (**self.config.load()).clone();
        let window = Duration::from_secs(cfg.window_secs.max(1));

        let mut tracked: Vec<IpUsage> = {
            let windows = self.windows.lock().unwrap();
            windows
                .iter()
                .filter(|(_, w)| now.duration_since(w.start) < window)
                .map(|(ip, w)| IpUsage {
                    ip: *ip,
                    requests: w.count_total,
                    auth_requests: w.count_auth,
                    window_secs: cfg.window_secs,
                })
                .collect()
        };
        tracked.sort_by_key(|u| std::cmp::Reverse(u.requests)); // busiest first
        tracked.truncate(STATS_TRACKED_CAP);

        let mut bans: Vec<BanRecord> = {
            let bans = self.bans.lock().unwrap();
            bans.iter()
                .filter(|(_, b)| b.until > now)
                .map(|(ip, b)| BanRecord {
                    ip: *ip,
                    kind: b.kind,
                    reason: b.reason.clone(),
                    expires_in_secs: b.until.saturating_duration_since(now).as_secs(),
                    until_unix: b.until_unix,
                })
                .collect()
        };
        bans.sort_by_key(|b| b.expires_in_secs); // soonest to expire first

        DosStats { config: cfg, tracked, bans }
    }
}

/// Whether `path` targets an authentication/login endpoint. Used to apply the
/// stricter `auth_max_requests` ceiling. Matches the login sub-paths of the
/// auth mounts (userpass, approle, ferrogate, fido2, …), which all contain a
/// `login` segment.
pub fn is_auth_path(path: &str) -> bool {
    path.contains("login")
}

/// Whether `path` is exempt from all DoS enforcement. Health, seal-status, and
/// metrics endpoints must always answer so that load balancers and monitoring
/// are never banned.
pub fn is_exempt_path(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    p.ends_with("/health")
        || p.ends_with("/seal-status")
        || p.ends_with("/metrics")
        || p == "/metrics"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg(max: u64, auth_max: u64, ban: u64) -> DosConfig {
        DosConfig {
            enabled: true,
            window_secs: 60,
            max_requests: max,
            auth_max_requests: auth_max,
            ban_secs: ban,
            refresh_secs: 30,
        }
    }

    #[test]
    fn general_threshold_triggers_auto_ban() {
        let g = DosGuard::new(cfg(3, 0, 300));
        let a = ip("203.0.113.7");
        assert!(g.check(a, "/v1/secret/data/x").is_ok());
        assert!(g.check(a, "/v1/secret/data/x").is_ok());
        assert!(g.check(a, "/v1/secret/data/x").is_ok());
        // 4th request in the window crosses max_requests = 3 → banned.
        let err = g.check(a, "/v1/secret/data/x").unwrap_err();
        assert_eq!(err.kind, BanKind::Auto);
        assert!(err.newly_banned);
        assert!(err.retry_after_secs > 0);
        // Subsequent blocked requests are not "newly banned".
        let err2 = g.check(a, "/v1/secret/data/x").unwrap_err();
        assert!(!err2.newly_banned);
    }

    #[test]
    fn auth_sub_limit_is_stricter() {
        // General limit high (100), auth limit low (2).
        let g = DosGuard::new(cfg(100, 2, 300));
        let a = ip("203.0.113.8");
        assert!(g.check(a, "/v1/auth/userpass/login/alice").is_ok());
        assert!(g.check(a, "/v1/auth/userpass/login/alice").is_ok());
        // 3rd login crosses auth_max_requests = 2.
        let err = g.check(a, "/v1/auth/userpass/login/alice").unwrap_err();
        assert_eq!(err.kind, BanKind::Auto);
        assert!(err.reason.contains("authentication"));
    }

    #[test]
    fn non_auth_traffic_ignores_auth_limit() {
        let g = DosGuard::new(cfg(0, 2, 300)); // general disabled, auth=2
        let a = ip("203.0.113.9");
        // Non-login requests never count against the auth ceiling.
        for _ in 0..10 {
            assert!(g.check(a, "/v1/secret/data/x").is_ok());
        }
    }

    #[test]
    fn disabled_guard_admits_everything() {
        let mut c = cfg(1, 1, 300);
        c.enabled = false;
        let g = DosGuard::new(c);
        let a = ip("203.0.113.10");
        for _ in 0..100 {
            assert!(g.check(a, "/v1/auth/userpass/login/x").is_ok());
        }
    }

    #[test]
    fn zero_ban_secs_counts_but_never_bans() {
        let g = DosGuard::new(cfg(2, 0, 0));
        let a = ip("203.0.113.11");
        for _ in 0..50 {
            assert!(g.check(a, "/v1/secret/data/x").is_ok());
        }
    }

    #[test]
    fn manual_ban_and_unban() {
        let g = DosGuard::new(cfg(1000, 0, 300));
        let a = ip("198.51.100.5");
        assert!(g.check(a, "/v1/secret/data/x").is_ok());
        g.manual_ban(a, 300, "operator block");
        let err = g.check(a, "/v1/secret/data/x").unwrap_err();
        assert_eq!(err.kind, BanKind::Manual);
        assert!(g.unban(a));
        assert!(g.check(a, "/v1/secret/data/x").is_ok());
        // A second unban reports "nothing to remove".
        assert!(!g.unban(a));
    }

    #[test]
    fn load_manual_bans_replaces_manual_set_only() {
        let g = DosGuard::new(cfg(1, 0, 300));
        let auto = ip("203.0.113.20");
        // Trigger an auto-ban.
        assert!(g.check(auto, "/v1/x").is_ok());
        let _ = g.check(auto, "/v1/x");
        let manual = ip("198.51.100.9");
        let future = now_unix() + 600;
        g.load_manual_bans(&[ManualBan { ip: manual, until_unix: future, reason: "persisted".into() }]);
        // The persisted manual ban is now enforced.
        assert_eq!(g.check(manual, "/v1/x").unwrap_err().kind, BanKind::Manual);
        // The pre-existing auto-ban is untouched by a manual-ban reload.
        assert_eq!(g.check(auto, "/v1/x").unwrap_err().kind, BanKind::Auto);
        // An expired persisted record is skipped on load.
        g.load_manual_bans(&[ManualBan { ip: manual, until_unix: 1, reason: "old".into() }]);
        assert!(g.check(manual, "/v1/x").is_ok());
    }

    #[test]
    fn config_change_reflected_in_stats() {
        let g = DosGuard::new(cfg(10, 0, 300));
        g.set_config(cfg(5, 3, 120));
        let s = g.stats();
        assert_eq!(s.config.max_requests, 5);
        assert_eq!(s.config.auth_max_requests, 3);
    }

    #[test]
    fn exempt_and_auth_classifiers() {
        assert!(is_exempt_path("/v1/sys/health"));
        assert!(is_exempt_path("/v1/sys/seal-status"));
        assert!(is_exempt_path("/v1/metrics"));
        assert!(!is_exempt_path("/v1/secret/data/x"));
        assert!(is_auth_path("/v1/auth/userpass/login/alice"));
        assert!(!is_auth_path("/v1/secret/data/x"));
    }
}
