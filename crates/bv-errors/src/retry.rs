//! Bounded retry policy for transient cluster and HSM-transport failures:
//! 5 attempts, doubling backoff (0.5, 1, 2, 4 s).

use std::{future::Future, time::Duration};

use crate::RvError;

/// Total attempts, the first one included.
pub const MAX_ATTEMPTS: u32 = 5;

/// Delay after the first failure; doubles each time up to [`MAX_DELAY`].
pub const BASE_DELAY: Duration = Duration::from_millis(500);
pub const MAX_DELAY: Duration = Duration::from_secs(4);

/// Delay to wait after failed attempt number `failed_attempt` (1-based).
pub fn backoff(failed_attempt: u32) -> Duration {
    let shift = failed_attempt.saturating_sub(1).min(16);
    BASE_DELAY.saturating_mul(1u32 << shift).min(MAX_DELAY)
}

/// No leader, quorum not confirmed in time, or node unhealthy: state unchanged.
pub fn is_transient_cluster(e: &RvError) -> bool {
    matches!(e, RvError::ErrClusterQuorumLost | RvError::ErrClusterNoLeader | RvError::ErrClusterUnhealthy)
}

/// Connector connection or session closed; the next request reconnects.
pub fn is_transient_hsm(e: &RvError) -> bool {
    matches!(e, RvError::ErrHsmTransport(_))
}

/// Run `op` up to [`MAX_ATTEMPTS`] times, sleeping [`backoff`] between
/// attempts, retrying only errors `is_transient` accepts. `op` must be safe
/// to repeat (a read). `what` names the operation in the warning.
pub async fn retry_transient<T, F, Fut>(what: &str, is_transient: fn(&RvError) -> bool, mut op: F) -> Result<T, RvError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, RvError>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Err(e) if is_transient(&e) && attempt < MAX_ATTEMPTS => {
                let wait = backoff(attempt);
                log::warn!("{what}: transient error ({e}); attempt {attempt}/{MAX_ATTEMPTS}, retrying in {wait:?}");
                tokio::time::sleep(wait).await;
                attempt += 1;
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let waits: Vec<_> = (1..=6).map(backoff).collect();
        assert_eq!(
            waits,
            vec![
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(4),
                Duration::from_secs(4),
            ]
        );
        assert_eq!(backoff(u32::MAX), MAX_DELAY);
    }

    #[test]
    fn only_transient_classes_are_retried() {
        assert!(is_transient_cluster(&RvError::ErrClusterQuorumLost));
        assert!(is_transient_cluster(&RvError::ErrClusterNoLeader));
        assert!(is_transient_cluster(&RvError::ErrClusterUnhealthy));
        assert!(!is_transient_cluster(&RvError::ErrPermissionDenied));
        assert!(!is_transient_cluster(&RvError::ErrCluster("x".into())));
        assert!(is_transient_hsm(&RvError::ErrHsmTransport("x".into())));
        assert!(!is_transient_hsm(&RvError::ErrHsmContextMismatch));
    }

    async fn run_failing(failures: u32, err: fn() -> RvError) -> (Result<u32, RvError>, u32) {
        let calls = AtomicU32::new(0);
        let result = retry_transient("test", is_transient_cluster, || async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n < failures {
                Err(err())
            } else {
                Ok(n)
            }
        })
        .await;
        (result, calls.load(Ordering::SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn retries_until_success_within_the_budget() {
        let (result, calls) = run_failing(MAX_ATTEMPTS - 1, || RvError::ErrClusterQuorumLost).await;
        assert_eq!(result.unwrap(), MAX_ATTEMPTS - 1);
        assert_eq!(calls, MAX_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_the_budget_with_the_last_error() {
        let (result, calls) = run_failing(MAX_ATTEMPTS, || RvError::ErrClusterNoLeader).await;
        assert!(matches!(result, Err(RvError::ErrClusterNoLeader)));
        assert_eq!(calls, MAX_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn a_non_transient_error_is_never_retried() {
        let (result, calls) = run_failing(1, || RvError::ErrPermissionDenied).await;
        assert!(matches!(result, Err(RvError::ErrPermissionDenied)));
        assert_eq!(calls, 1);
    }
}
