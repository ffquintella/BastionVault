//! Monotonic time for the HSM pool's breaker, backoff and session expiry.
//!
//! Injected rather than read from `Instant` directly, so the pool and the mock
//! device can be tested with a [`ManualClock`] and no real sleeping.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Monotonic time since an arbitrary origin.
pub trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

/// The real clock: time elapsed since this value was created.
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

pub fn monotonic() -> Arc<dyn Clock> {
    Arc::new(MonotonicClock::new())
}

/// A clock that moves only when told to. Tests and the mock device only.
#[cfg(any(test, feature = "hsm_mock"))]
#[derive(Default)]
pub struct ManualClock {
    millis: std::sync::atomic::AtomicU64,
}

#[cfg(any(test, feature = "hsm_mock"))]
impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.millis.fetch_add(ms, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "hsm_mock"))]
impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.millis.load(std::sync::atomic::Ordering::SeqCst))
    }
}
