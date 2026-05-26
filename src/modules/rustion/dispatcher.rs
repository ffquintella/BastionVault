//! Bastion-target dispatcher for the Rustion integration.
//!
//! Given a connection profile and the registry's health cache,
//! returns the ordered list of Rustion target candidates the
//! session-open flow walks through. Two modes:
//!
//!   - **Pinned-list (`Mode::OrderedFallback`)** — the profile names
//!     an explicit ordered list of target ids. We try them in
//!     declared order, skipping any whose health is not `up`.
//!     Falls through on transport / 5xx failures to the next entry;
//!     halts on a hard auth refusal (4xx) so the operator sees a
//!     real "access denied" instead of every bastion bouncing them.
//!
//!   - **Random-pool (`Mode::RandomPool`)** — the profile carries an
//!     empty / unset bastion list. We draw uniformly at random from
//!     every globally-enabled target whose health is `up`. Random
//!     spreads load across BastionVault HA replicas without shared
//!     state; the operator's session isn't a hot path that benefits
//!     from stickiness.
//!
//! Both modes are deterministic given the (profile, health cache,
//! seed) triple — the random-pool mode draws from a caller-supplied
//! RNG so tests can pin the choice. The dispatcher is pure: it
//! reads the registry / health cache but performs no I/O of its own.
//! The session-open flow's actual network attempts (POST envelope,
//! parse response, surface 4xx vs 5xx) live in the Tauri command
//! layer; the dispatcher just supplies the ordering.

#![deny(unsafe_code)]

use rand::seq::SliceRandom;

use super::config::{HealthStatus, RustionTarget, RustionTargetHealth};

/// Why this target ended up in the candidate list. Surfaced on the
/// session.open audit event so a debugger can reconstruct what the
/// dispatcher saw without rerunning it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Profile pinned a specific ordered list — the candidates are
    /// the survivors of that list after health filtering, in
    /// declared order.
    OrderedFallback,
    /// Profile left the list empty — candidates are the global pool
    /// of healthy enabled targets, in random order.
    RandomPool,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::OrderedFallback => "ordered-fallback",
            Mode::RandomPool => "random-pool",
        }
    }
}

/// Outcome of one dispatcher pass.
#[derive(Debug, Clone)]
pub struct DispatchPlan {
    pub mode: Mode,
    pub candidates: Vec<RustionTarget>,
    /// Targets the dispatcher considered but dropped. Surfaced on
    /// audit so an operator can see, e.g., "rustion-eu-west-1 was
    /// pinned but its health is `down`" without re-running.
    pub dropped: Vec<DroppedTarget>,
}

#[derive(Debug, Clone)]
pub struct DroppedTarget {
    pub id: String,
    pub name: String,
    pub reason: DropReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Target was disabled in the registry (`enabled = false`).
    Disabled,
    /// Health verdict is not `up`. The dispatcher refuses `Degraded`
    /// equally to `Down` because a yellow chip still means "don't
    /// route to it"; the operator just sees the wobble in the GUI
    /// before the verdict flips fully.
    NotUp(HealthStatus),
    /// Target id pinned in the profile but not present in the
    /// registry (operator deleted the bastion after writing the
    /// profile). Distinct from `NotUp` so the GUI can flag a stale
    /// profile reference.
    NotRegistered,
}

/// Resolve a candidate list given the inputs.
///
/// `pinned` is the profile's `bastions` field — `None` or an empty
/// vec means random-pool. The registry passes the full target table
/// + the latest cached health per target id.
pub fn plan<R: rand::Rng>(
    pinned: Option<&[String]>,
    targets: &[RustionTarget],
    health: &dyn Fn(&str) -> Option<RustionTargetHealth>,
    rng: &mut R,
) -> DispatchPlan {
    match pinned {
        Some(list) if !list.is_empty() => plan_pinned(list, targets, health),
        _ => plan_random_pool(targets, health, rng),
    }
}

fn plan_pinned(
    pinned: &[String],
    targets: &[RustionTarget],
    health: &dyn Fn(&str) -> Option<RustionTargetHealth>,
) -> DispatchPlan {
    let mut candidates = Vec::new();
    let mut dropped = Vec::new();
    for id in pinned {
        let Some(target) = targets.iter().find(|t| &t.id == id) else {
            dropped.push(DroppedTarget {
                id: id.clone(),
                name: id.clone(),
                reason: DropReason::NotRegistered,
            });
            continue;
        };
        if !target.enabled {
            dropped.push(DroppedTarget {
                id: target.id.clone(),
                name: target.name.clone(),
                reason: DropReason::Disabled,
            });
            continue;
        }
        let h = health(&target.id).unwrap_or_default();
        if !h.status.is_routable() {
            dropped.push(DroppedTarget {
                id: target.id.clone(),
                name: target.name.clone(),
                reason: DropReason::NotUp(h.status),
            });
            continue;
        }
        candidates.push(target.clone());
    }
    DispatchPlan {
        mode: Mode::OrderedFallback,
        candidates,
        dropped,
    }
}

fn plan_random_pool<R: rand::Rng>(
    targets: &[RustionTarget],
    health: &dyn Fn(&str) -> Option<RustionTargetHealth>,
    rng: &mut R,
) -> DispatchPlan {
    let mut candidates: Vec<RustionTarget> = Vec::new();
    let mut dropped: Vec<DroppedTarget> = Vec::new();
    for target in targets {
        if !target.enabled {
            dropped.push(DroppedTarget {
                id: target.id.clone(),
                name: target.name.clone(),
                reason: DropReason::Disabled,
            });
            continue;
        }
        let h = health(&target.id).unwrap_or_default();
        if !h.status.is_routable() {
            dropped.push(DroppedTarget {
                id: target.id.clone(),
                name: target.name.clone(),
                reason: DropReason::NotUp(h.status),
            });
            continue;
        }
        candidates.push(target.clone());
    }
    candidates.shuffle(rng);
    DispatchPlan {
        mode: Mode::RandomPool,
        candidates,
        dropped,
    }
}

/// Decide whether to advance to the next candidate after a session-open
/// attempt failed.
///
/// The rule: **transport / 5xx → advance**, **4xx → halt**. A 403 from a
/// reachable Rustion is a final answer — re-trying on the next bastion
/// would just lock the operator's account on every host in the pool.
/// Network-layer failures (DNS, TCP, TLS, body parse) are transient by
/// nature and fall through to the next candidate.
pub fn should_advance(outcome: &OpenAttemptOutcome) -> bool {
    match outcome {
        OpenAttemptOutcome::Success => false,
        OpenAttemptOutcome::Transport(_) => true,
        OpenAttemptOutcome::Http(status, _) => *status >= 500,
        // Inside this taxonomy, an envelope_replay / envelope_expired
        // would surface as 409 / 410 — fall through to the next host
        // since the attacker (or clock skew) is per-bastion.
    }
}

/// Outcome of one POST /v1/sessions attempt — fed to `should_advance`.
#[derive(Debug, Clone)]
pub enum OpenAttemptOutcome {
    Success,
    /// Network-layer failure: DNS, TCP, TLS handshake, body parse, …
    Transport(String),
    /// HTTP-status failure with the Rustion-side error body. 5xx → advance,
    /// 4xx → halt (per `should_advance`).
    Http(u16, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rand::SeedableRng;

    use crate::modules::rustion::config::HybridPubKey;

    fn target(id: &str, name: &str, enabled: bool) -> RustionTarget {
        RustionTarget {
            id: id.into(),
            name: name.into(),
            endpoint: format!("{name}.test:9443"),
            public_key: HybridPubKey::default(),
            kem_public_key: String::new(),
            fingerprint: String::new(),
            description: String::new(),
            tags: vec![],
            enabled,
            default_recording_dir: String::new(),
            tls_pinned_cert_pem: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn health_map(rows: &[(&str, HealthStatus)]) -> impl Fn(&str) -> Option<RustionTargetHealth> {
        let owned: Vec<(String, RustionTargetHealth)> = rows
            .iter()
            .map(|(id, status)| {
                (
                    (*id).to_string(),
                    RustionTargetHealth {
                        status: *status,
                        ..Default::default()
                    },
                )
            })
            .collect();
        move |id: &str| {
            owned
                .iter()
                .find(|(k, _)| k == id)
                .map(|(_, v)| v.clone())
        }
    }

    fn rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0x9b1deadbeef)
    }

    #[test]
    fn pinned_list_filters_and_preserves_order() {
        let targets = vec![
            target("rt_a", "eu-1", true),
            target("rt_b", "eu-2", true),
            target("rt_c", "us-1", true),
        ];
        let pinned = ["rt_a".to_string(), "rt_b".to_string(), "rt_c".to_string()];
        let health = health_map(&[
            ("rt_a", HealthStatus::Up),
            ("rt_b", HealthStatus::Down),
            ("rt_c", HealthStatus::Up),
        ]);

        let plan = plan(Some(&pinned), &targets, &health, &mut rng());
        assert_eq!(plan.mode, Mode::OrderedFallback);
        assert_eq!(plan.candidates.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(),
                   vec!["rt_a", "rt_c"]);
        assert_eq!(plan.dropped.len(), 1);
        assert_eq!(plan.dropped[0].id, "rt_b");
        assert!(matches!(plan.dropped[0].reason, DropReason::NotUp(HealthStatus::Down)));
    }

    #[test]
    fn pinned_list_drops_disabled_and_unknown_ids() {
        let targets = vec![
            target("rt_a", "eu-1", true),
            target("rt_b", "eu-2", false), // disabled
        ];
        let pinned = ["rt_a".to_string(), "rt_b".to_string(), "rt_missing".to_string()];
        let health = health_map(&[
            ("rt_a", HealthStatus::Up),
            ("rt_b", HealthStatus::Up),
        ]);

        let plan = plan(Some(&pinned), &targets, &health, &mut rng());
        assert_eq!(plan.candidates.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(),
                   vec!["rt_a"]);
        let dropped_ids: Vec<&str> = plan.dropped.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(dropped_ids, vec!["rt_b", "rt_missing"]);
        assert!(matches!(plan.dropped[0].reason, DropReason::Disabled));
        assert!(matches!(plan.dropped[1].reason, DropReason::NotRegistered));
    }

    #[test]
    fn empty_pin_falls_into_random_pool() {
        let targets = vec![
            target("rt_a", "eu-1", true),
            target("rt_b", "eu-2", true),
            target("rt_c", "us-1", true),
        ];
        let health = health_map(&[
            ("rt_a", HealthStatus::Up),
            ("rt_b", HealthStatus::Up),
            ("rt_c", HealthStatus::Down),
        ]);

        // No pinned list → random pool, healthy targets only.
        let plan = plan(None, &targets, &health, &mut rng());
        assert_eq!(plan.mode, Mode::RandomPool);
        let ids: Vec<&str> = plan.candidates.iter().map(|t| t.id.as_str()).collect();
        // Pool size = 2 (rt_a + rt_b, rt_c is down)
        assert_eq!(plan.candidates.len(), 2);
        assert!(ids.contains(&"rt_a"));
        assert!(ids.contains(&"rt_b"));
        assert!(!ids.contains(&"rt_c"));
        // rt_c surfaces in `dropped` as NotUp(Down).
        let dropped: Vec<&str> = plan.dropped.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(dropped, vec!["rt_c"]);
    }

    #[test]
    fn random_pool_uses_supplied_rng_for_deterministic_tests() {
        let targets = vec![
            target("rt_a", "eu-1", true),
            target("rt_b", "eu-2", true),
            target("rt_c", "us-1", true),
        ];
        let health = health_map(&[
            ("rt_a", HealthStatus::Up),
            ("rt_b", HealthStatus::Up),
            ("rt_c", HealthStatus::Up),
        ]);
        // Different seeds produce different orderings.
        let mut rng_a = rand::rngs::StdRng::seed_from_u64(1);
        let mut rng_b = rand::rngs::StdRng::seed_from_u64(2);
        let plan_a = plan(None, &targets, &health, &mut rng_a);
        let plan_b = plan(None, &targets, &health, &mut rng_b);
        let ids_a: Vec<&str> = plan_a.candidates.iter().map(|t| t.id.as_str()).collect();
        let ids_b: Vec<&str> = plan_b.candidates.iter().map(|t| t.id.as_str()).collect();
        // Both contain the same three targets — just possibly different order.
        assert_eq!(ids_a.len(), 3);
        assert_eq!(ids_b.len(), 3);
        for id in ["rt_a", "rt_b", "rt_c"] {
            assert!(ids_a.contains(&id));
            assert!(ids_b.contains(&id));
        }
    }

    #[test]
    fn should_advance_falls_through_on_transport_and_5xx() {
        assert!(should_advance(&OpenAttemptOutcome::Transport(
            "tcp connect timeout".into()
        )));
        assert!(should_advance(&OpenAttemptOutcome::Http(503, "capacity".into())));
        assert!(should_advance(&OpenAttemptOutcome::Http(502, "bad gateway".into())));
    }

    #[test]
    fn should_advance_halts_on_4xx() {
        assert!(!should_advance(&OpenAttemptOutcome::Http(401, "signature_invalid".into())));
        assert!(!should_advance(&OpenAttemptOutcome::Http(403, "authority_revoked".into())));
        assert!(!should_advance(&OpenAttemptOutcome::Http(409, "envelope_replay".into())));
        assert!(!should_advance(&OpenAttemptOutcome::Http(410, "envelope_expired".into())));
    }

    #[test]
    fn should_advance_halts_on_success() {
        assert!(!should_advance(&OpenAttemptOutcome::Success));
    }
}
