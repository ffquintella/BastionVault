//! Memory-protection guardrails applied once at process start.
//!
//! Honors two `CacheConfig` flags whose whole job is to harden the
//! invariant that cached material never leaks out of process memory:
//!
//! * `memlock` — call `mlockall(MCL_CURRENT | MCL_FUTURE)` on Unix so
//!   all process pages (including current and future cache allocations)
//!   are pinned against swap. Startup aborts if the syscall fails rather
//!   than silently running unprotected.
//! * `allow_core_dumps` — when `false` (the default) and any cache layer
//!   is enabled with a non-zero TTL, call `prctl(PR_SET_DUMPABLE, 0)` on
//!   Linux so a crash does not write cache contents into a core file.
//!
//! Windows is not yet supported. `memlock = true` on Windows returns an
//! explicit error from [`apply`] so operators don't silently run with a
//! weaker protection model than they asked for.

use crate::{cache::CacheConfig, errors::RvError};

/// Apply every memory-protection flag the operator has turned on. Called
/// exactly once, from `BastionVault::new`, before any cache allocations
/// are made.
///
/// Returns `Err` when a protection was requested but cannot be granted
/// (e.g. `mlockall` fails for lack of privilege, or `memlock = true` on
/// an unsupported platform). Callers should treat that as a fatal
/// startup condition — the operator asked for a guarantee the process
/// cannot provide.
pub fn apply(cache_config: &CacheConfig) -> Result<(), RvError> {
    if cache_config.memlock {
        apply_memlock()?;
    }

    let any_cache_enabled = cache_config.token_cache_ttl_secs > 0
        || cache_config.secret_cache_ttl_secs > 0
        // Policy cache is unconditionally on. Treat as "enabled" only when
        // the operator also asked for memlock; otherwise PR_SET_DUMPABLE is
        // opt-in, not forced on every BastionVault process.
        || (cache_config.memlock && cache_config.policy_cache_size > 0);
    if any_cache_enabled && !cache_config.allow_core_dumps {
        disable_core_dumps()?;
    }

    Ok(())
}

/// `true` if any of the memory protections from this module are active
/// in the current process. Used by the startup log line and by a test
/// that verifies the invariant is documented in telemetry.
pub fn protections_status(cache_config: &CacheConfig) -> ProtectionsStatus {
    ProtectionsStatus {
        memlock_requested: cache_config.memlock,
        core_dumps_allowed: cache_config.allow_core_dumps,
        any_cache_enabled: cache_config.token_cache_ttl_secs > 0
            || cache_config.secret_cache_ttl_secs > 0,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProtectionsStatus {
    pub memlock_requested: bool,
    pub core_dumps_allowed: bool,
    pub any_cache_enabled: bool,
}

// ---------------------------------------------------------------------
// Platform-specific implementations.
// ---------------------------------------------------------------------

#[cfg(unix)]
fn apply_memlock() -> Result<(), RvError> {
    // SAFETY: `mlockall` is a standard Unix syscall. We pass only the
    // documented flag combination and inspect the return value.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(RvError::ErrString(format!(
            "cache.memlock: mlockall failed: {err}. \
             The operator asked for swap-proof cache allocations but the \
             kernel refused (typically RLIMIT_MEMLOCK too low or the \
             process lacks CAP_IPC_LOCK). Startup is aborted rather than \
             silently running with a weaker protection than requested."
        )));
    }
    log::info!("cache.memlock: mlockall(MCL_CURRENT|MCL_FUTURE) succeeded; cache allocations pinned against swap");
    Ok(())
}

#[cfg(not(unix))]
fn apply_memlock() -> Result<(), RvError> {
    Err(RvError::ErrString(
        "cache.memlock = true is not yet implemented on this platform. \
         Set memlock = false in the cache block or run on a Unix host."
            .into(),
    ))
}

#[cfg(target_os = "linux")]
fn disable_core_dumps() -> Result<(), RvError> {
    // SAFETY: `prctl` with `PR_SET_DUMPABLE = 0` is a standard Linux
    // syscall. Third argument must be zero for SET_DUMPABLE; the
    // remaining two are unused.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(RvError::ErrString(format!(
            "cache: prctl(PR_SET_DUMPABLE, 0) failed: {err}. \
             Caches are enabled but core dumps could still include cache \
             contents. Set cache.allow_core_dumps = true to opt out, or \
             investigate why the prctl syscall is denied."
        )));
    }
    log::info!("cache: PR_SET_DUMPABLE set to 0; process will not produce core dumps");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn disable_core_dumps() -> Result<(), RvError> {
    // On non-Linux hosts we have no portable way to disable core dumps.
    // We log once and keep running — the operator has not asked for an
    // abort here (unlike `memlock`), so abandoning startup would be
    // more surprising than continuing. The startup log makes the
    // residual risk visible.
    log::warn!(
        "cache: PR_SET_DUMPABLE equivalent not available on this platform; \
         core dumps are not suppressed. Set cache.allow_core_dumps = true \
         to silence this warning once you have ensured dumps are disabled \
         at the OS level."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_cleanly() {
        // Default CacheConfig: memlock off, all TTLs at defaults.
        // `apply` should be a no-op on any platform.
        let cfg = CacheConfig::default();
        apply(&cfg).expect("default config must not apply any protections");
    }

    #[test]
    fn protections_status_reflects_config() {
        let mut cfg = CacheConfig::default();
        let s = protections_status(&cfg);
        assert!(!s.memlock_requested);
        assert!(!s.core_dumps_allowed);
        // token cache default TTL is 30s (> 0), so any_cache_enabled = true.
        assert!(s.any_cache_enabled);

        cfg.token_cache_ttl_secs = 0;
        cfg.secret_cache_ttl_secs = 0;
        let s = protections_status(&cfg);
        assert!(!s.any_cache_enabled);
    }
}
