//! The shared retry policy (`bv_errors::retry`) plus a sleep that also works
//! in the `sync_handler` build, for the HSM pool init probe.

pub use bv_errors::retry::{backoff, is_transient_hsm, MAX_ATTEMPTS};

#[cfg(not(feature = "sync_handler"))]
pub async fn pause(d: std::time::Duration) {
    tokio::time::sleep(d).await;
}

#[cfg(feature = "sync_handler")]
pub fn pause(d: std::time::Duration) {
    std::thread::sleep(d);
}
