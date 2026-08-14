//! Replay-cache sweeper (Phase 3).
//!
//! Drops `used/<name>/<step>` rows older than `(skew + 1) * period`.
//! Outside the validator's acceptance window a row contributes
//! nothing — it can never legitimately match a future code, since a
//! step that old is already rejected by the validator on freshness
//! grounds.
//!
//! Today this is invoked opportunistically from the validate path:
//! every successful validation triggers a single-pass sweep over the
//! current key's `used/` prefix. A future operator-facing tidy
//! endpoint would call `sweep_all` from a route handler.

use super::{
    backend::UsedEntry,
    policy::{KeyPolicy, USED_PREFIX},
    TotpBackendInner,
};
use crate::{errors::RvError, logical::Request};

#[maybe_async::maybe_async]
impl TotpBackendInner {
    /// Sweep replay rows for one key. `now_secs` is supplied by the
    /// caller so the validator can pass its captured `now` and stay
    /// consistent with the validation it just performed.
    pub async fn sweep_key_replay(
        &self,
        req: &mut Request,
        name: &str,
        policy: &KeyPolicy,
        now_secs: u64,
    ) -> Result<(), RvError> {
        let prefix = format!("{USED_PREFIX}{name}/");
        let children = match req.storage_list(&prefix).await {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let max_age = policy.period.saturating_mul((policy.skew as u64).saturating_add(1));
        for child in children {
            let key = format!("{prefix}{child}");
            let entry: UsedEntry = match req.storage_get(&key).await {
                Ok(Some(e)) => match serde_json::from_slice(&e.value) {
                    Ok(v) => v,
                    Err(_) => {
                        // Garbage row — drop it rather than panic.
                        let _ = req.storage_delete(&key).await;
                        continue;
                    }
                },
                _ => continue,
            };
            if now_secs.saturating_sub(entry.written_at) > max_age {
                let _ = req.storage_delete(&key).await;
            }
        }
        Ok(())
    }
}
