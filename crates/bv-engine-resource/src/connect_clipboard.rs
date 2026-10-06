//! `POST resources/v2/connect/clipboard/audit` — the vault-side audit row for
//! RDP clipboard transfers (T35 Phase 4, features/rdp-clipboard-redirection.md
//! §8).
//!
//! A direct RDP session's clipboard moves between the operator's machine and
//! the target without touching the vault, so only the desktop host knows a
//! transfer happened. The host batches what it saw and posts it here; the
//! request pipeline then writes the batch to every audit device exactly like
//! any other request, which is what puts it in the tamper-evident chain an
//! auditor reads.
//!
//! ## What a batch may carry — and what it cannot
//!
//! Metadata only: direction, kind, outcome, byte counts. Never content and
//! never file names. The shape enforces that rather than trusting the caller:
//!
//! ```json
//! {
//!   "resource": "srv1", "profile_id": "p_1", "session": "rdp_…", "seq": 3, "final": false,
//!   "transfers": { "session-to-host.text.ok": [120, 33], "host-to-session.file.oversize": [0] },
//!   "overflow":  { "session-to-host.image.ok": { "count": 40, "bytes": 9000000 } }
//! }
//! ```
//!
//! Every metadata word is a map **key** from a closed vocabulary and every
//! value is a **number**. There is no free-text slot a file name could ride
//! in, and the audit device's redaction — which HMACs strings but passes keys
//! and numbers through — leaves the row readable without the HMAC key.
//!
//! `overflow` is the host's rate limiter at work: transfers it could not
//! afford a row each for, folded into a count and a byte total rather than
//! dropped. Nothing about a transfer is silently lost.

use serde_json::{Map, Value};

use crate::{bv_error_response_status, errors::RvError, logical::Request};

/// Directions, in the profile key's own words (`rdp_clipboard`).
pub const DIRECTIONS: [&str; 2] = ["host-to-session", "session-to-host"];
/// What moved. `text` is `CF_UNICODETEXT`, `image` `CF_DIB`/`CF_DIBV5`,
/// `file` one file of a `FileGroupDescriptorW` list.
pub const KINDS: [&str; 3] = ["text", "image", "file"];
/// How it ended. `refused` covers both the direction switch and the policy
/// ceiling; `malformed` is a payload that failed validation; `error` a local
/// failure (host clipboard, disk, a remote error response, a timeout).
pub const OUTCOMES: [&str; 5] = ["ok", "oversize", "refused", "malformed", "error"];

/// Most per-transfer entries one batch may carry. The host rate-limits well
/// below this; the bound is what keeps a misbehaving client from turning one
/// audited request into an arbitrarily large audit record.
pub const MAX_BATCH_ENTRIES: usize = 256;
/// Largest byte count accepted for one entry, or one overflow total: 2^53,
/// the largest integer every JSON consumer reads exactly.
pub const MAX_BYTES: u64 = 1 << 53;
/// Session token shape: the host's `rdp_<32 hex>` token, bounded generously.
const MAX_SESSION_LEN: usize = 64;

/// What a validated batch adds up to, for the log line and the response.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BatchSummary {
    pub transfers: u64,
    pub bytes: u64,
    pub overflow_transfers: u64,
    pub overflow_bytes: u64,
    /// `key=count` pairs in key order — metadata words only.
    pub by_key: Vec<(String, u64)>,
}

fn is_known_key(key: &str) -> bool {
    let mut parts = key.split('.');
    let (Some(d), Some(k), Some(o), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    DIRECTIONS.contains(&d) && KINDS.contains(&k) && OUTCOMES.contains(&o)
}

fn byte_count(v: &Value, what: &str) -> Result<u64, String> {
    let n = v.as_u64().ok_or_else(|| format!("{what} must be a non-negative integer"))?;
    if n > MAX_BYTES {
        return Err(format!("{what} exceeds {MAX_BYTES}"));
    }
    Ok(n)
}

/// Validate a batch body strictly. Any unknown key, non-numeric value,
/// negative or oversized count, or an over-long batch refuses the whole
/// batch — a partially accepted audit record is worse than a refused one,
/// because the host fails closed on a refusal and would otherwise not know.
pub fn validate_batch(
    transfers: &Map<String, Value>,
    overflow: &Map<String, Value>,
    is_final: bool,
) -> Result<BatchSummary, String> {
    let mut summary = BatchSummary::default();
    let mut entries = 0usize;
    let mut by_key: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();

    for (key, value) in transfers {
        if !is_known_key(key) {
            return Err(format!("unknown transfer key `{key}` (expected <direction>.<kind>.<outcome>)"));
        }
        let arr = value.as_array().ok_or_else(|| format!("`transfers.{key}` must be an array of byte counts"))?;
        if arr.is_empty() {
            return Err(format!("`transfers.{key}` is empty"));
        }
        entries += arr.len();
        if entries > MAX_BATCH_ENTRIES {
            return Err(format!("batch carries more than {MAX_BATCH_ENTRIES} transfers"));
        }
        for v in arr {
            let n = byte_count(v, &format!("`transfers.{key}` entry"))?;
            summary.bytes = summary.bytes.saturating_add(n);
        }
        summary.transfers += arr.len() as u64;
        *by_key.entry(key.clone()).or_default() += arr.len() as u64;
    }

    for (key, value) in overflow {
        if !is_known_key(key) {
            return Err(format!("unknown overflow key `{key}` (expected <direction>.<kind>.<outcome>)"));
        }
        let obj = value.as_object().ok_or_else(|| format!("`overflow.{key}` must be {{count, bytes}}"))?;
        if obj.len() != 2 || !obj.contains_key("count") || !obj.contains_key("bytes") {
            return Err(format!("`overflow.{key}` must carry exactly `count` and `bytes`"));
        }
        let count = obj["count"]
            .as_u64()
            .filter(|c| *c > 0)
            .ok_or_else(|| format!("`overflow.{key}.count` must be a positive integer"))?;
        let bytes = byte_count(&obj["bytes"], &format!("`overflow.{key}.bytes`"))?;
        summary.overflow_transfers = summary.overflow_transfers.saturating_add(count);
        summary.overflow_bytes = summary.overflow_bytes.saturating_add(bytes);
        let slot = by_key.entry(key.clone()).or_default();
        *slot = slot.saturating_add(count);
    }

    if summary.transfers == 0 && summary.overflow_transfers == 0 && !is_final {
        // Only the session's closing batch may be empty: it is the
        // "nothing more is coming" marker an auditor can rely on.
        return Err("empty batch (only the final batch of a session may carry no transfers)".into());
    }
    summary.by_key = by_key.into_iter().collect();
    Ok(summary)
}

/// The session token is an opaque correlation id, but it is still caller
/// text that lands in a log line: bound it and keep it to `[A-Za-z0-9_-]`.
pub fn validate_session_token(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_SESSION_LEN {
        return Err(format!("`session` must be 1..={MAX_SESSION_LEN} characters"));
    }
    if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err("`session` may contain only [A-Za-z0-9_-]".into());
    }
    Ok(())
}

fn map_field(req: &Request, key: &str) -> Result<Map<String, Value>, RvError> {
    match req.get_data(key) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(Value::Null) | Err(RvError::ErrRequestFieldNotFound) | Err(RvError::ErrRequestNoData) => Ok(Map::new()),
        _ => Err(bv_error_response_status!(400, &format!("`{key}` must be an object"))),
    }
}

#[maybe_async::maybe_async]
impl super::ResourceBackendInner {
    /// `POST resources/v2/connect/clipboard/audit`.
    ///
    /// Gated like every other connect endpoint: the caller must be able to
    /// connect to the named resource (`connect`, `read` or `root` on its
    /// secret path, ownership, or a share), and the profile must exist and be
    /// an RDP profile. A caller who cannot open the session cannot write its
    /// audit trail either.
    pub async fn handle_connect_clipboard_audit(
        &self,
        _backend: &dyn crate::logical::Backend,
        req: &mut Request,
    ) -> Result<Option<crate::logical::Response>, RvError> {
        let (resource, profile_id, meta) = self.connect_target_record(req).await?;
        let profile =
            meta.as_ref().and_then(|m| crate::connect_mfa::find_profile(m, &profile_id)).ok_or_else(|| {
                bv_error_response_status!(404, &format!("profile `{profile_id}` not found on resource `{resource}`"))
            })?;
        if profile.get("protocol").and_then(|v| v.as_str()) != Some("rdp") {
            return Err(bv_error_response_status!(400, "clipboard audit applies to RDP profiles only"));
        }

        let session = req
            .get_data("session")
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or_else(|| bv_error_response_status!(400, "`session` is required"))?;
        validate_session_token(&session).map_err(|e| bv_error_response_status!(400, &e))?;
        let seq = req
            .get_data("seq")
            .ok()
            .and_then(|v| v.as_u64())
            .ok_or_else(|| bv_error_response_status!(400, "`seq` must be a non-negative integer"))?;
        let is_final = match req.get_data("final") {
            Ok(Value::Bool(b)) => b,
            Err(RvError::ErrRequestFieldNotFound) | Err(RvError::ErrRequestNoData) => false,
            _ => return Err(bv_error_response_status!(400, "`final` must be a boolean")),
        };
        let transfers = map_field(req, "transfers")?;
        let overflow = map_field(req, "overflow")?;
        let summary =
            validate_batch(&transfers, &overflow, is_final).map_err(|e| bv_error_response_status!(400, &e))?;

        let actor = crate::kernel_api::identity::caller_audit_actor(req);
        let keys: Vec<String> = summary.by_key.iter().map(|(k, n)| format!("{k}={n}")).collect();
        // Counts and outcomes only — the shape admits nothing else.
        log::info!(
            "connect.clipboard.transfers resource={resource} profile={profile_id} actor={actor} session={session} \
             seq={seq} final={is_final} transfers={} bytes={} overflow_transfers={} overflow_bytes={} [{}]",
            summary.transfers,
            summary.bytes,
            summary.overflow_transfers,
            summary.overflow_bytes,
            keys.join(","),
        );

        let mut data = Map::new();
        data.insert("accepted".into(), Value::from(summary.transfers + summary.overflow_transfers));
        data.insert("seq".into(), Value::from(seq));
        Ok(Some(crate::logical::Response::data_response(Some(data))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn a_well_formed_batch_is_summarised() {
        let s = validate_batch(
            &obj(json!({ "session-to-host.text.ok": [120, 33], "host-to-session.file.oversize": [0] })),
            &obj(json!({ "session-to-host.image.ok": { "count": 40, "bytes": 9000000 } })),
            false,
        )
        .unwrap();
        assert_eq!(s.transfers, 3);
        assert_eq!(s.bytes, 153);
        assert_eq!(s.overflow_transfers, 40);
        assert_eq!(s.overflow_bytes, 9_000_000);
        assert_eq!(
            s.by_key,
            vec![
                ("host-to-session.file.oversize".to_string(), 1),
                ("session-to-host.image.ok".to_string(), 40),
                ("session-to-host.text.ok".to_string(), 2),
            ]
        );
    }

    #[test]
    fn there_is_no_slot_for_a_file_name() {
        // A name smuggled as a key, or as a string value, is refused — the
        // vocabulary is closed and every value is a number.
        for (t, o) in [
            (json!({ "session-to-host.file.ok.secret.docx": [1] }), json!({})),
            (json!({ "secret.docx": [1] }), json!({})),
            (json!({ "session-to-host.file.ok": ["secret.docx"] }), json!({})),
            (json!({ "session-to-host.file.ok": [{ "name": "secret.docx", "bytes": 1 }] }), json!({})),
            (json!({}), json!({ "session-to-host.file.ok": { "count": 1, "bytes": 1, "name": "secret.docx" } })),
        ] {
            assert!(validate_batch(&obj(t.clone()), &obj(o.clone()), false).is_err(), "{t} / {o} must be refused");
        }
    }

    #[test]
    fn malformed_values_refuse_the_whole_batch() {
        let bad = [
            json!({ "session-to-host.text.ok": [-1] }),
            json!({ "session-to-host.text.ok": [1.5] }),
            json!({ "session-to-host.text.ok": [MAX_BYTES + 1] }),
            json!({ "session-to-host.text.ok": [] }),
            json!({ "session-to-host.text.ok": 5 }),
            json!({ "sideways.text.ok": [1] }),
            json!({ "session-to-host.video.ok": [1] }),
            json!({ "session-to-host.text.maybe": [1] }),
            json!({ "session-to-host.text": [1] }),
        ];
        for t in bad {
            assert!(validate_batch(&obj(t.clone()), &Map::new(), false).is_err(), "{t} must be refused");
        }
        // Overflow must be exactly {count>0, bytes}.
        for o in [
            json!({ "session-to-host.text.ok": { "count": 0, "bytes": 0 } }),
            json!({ "session-to-host.text.ok": { "count": 1 } }),
            json!({ "session-to-host.text.ok": [1] }),
        ] {
            assert!(validate_batch(&Map::new(), &obj(o.clone()), false).is_err(), "{o} must be refused");
        }
    }

    #[test]
    fn a_batch_cannot_exceed_the_entry_cap() {
        let many: Vec<u64> = vec![1; MAX_BATCH_ENTRIES + 1];
        let t = obj(json!({ "session-to-host.text.ok": many }));
        assert!(validate_batch(&t, &Map::new(), false).is_err());
        let exactly: Vec<u64> = vec![1; MAX_BATCH_ENTRIES];
        let t = obj(json!({ "session-to-host.text.ok": exactly }));
        assert!(validate_batch(&t, &Map::new(), false).is_ok());
    }

    #[test]
    fn only_the_final_batch_may_be_empty() {
        assert!(validate_batch(&Map::new(), &Map::new(), false).is_err());
        let s = validate_batch(&Map::new(), &Map::new(), true).unwrap();
        assert_eq!(s.transfers + s.overflow_transfers, 0);
    }

    #[test]
    fn the_session_token_is_bounded_and_plain() {
        assert!(validate_session_token("rdp_0123abcd").is_ok());
        assert!(validate_session_token("").is_err());
        assert!(validate_session_token(&"a".repeat(65)).is_err());
        for bad in ["rdp 1", "rdp\n1", "../x", "rdp=1", "ünï"] {
            assert!(validate_session_token(bad).is_err(), "{bad:?}");
        }
    }
}
