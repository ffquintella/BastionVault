//! Cursor pagination for bulk-metadata (`<list>/info`) endpoints.
//!
//! Several list-heavy views need one summary per listed object. Read
//! individually that is `1 + N` requests per page load, which on a mount
//! holding a few hundred objects is indistinguishable from a flood and trips
//! the server's own per-IP abuse guard — the operator gets banned from their
//! own vault for five minutes. The fix is an endpoint that returns a *page*
//! of summaries; see `features/client-request-efficiency.md`.
//!
//! This module holds the parts every such endpoint shares, so the cursor
//! semantics are identical across engines rather than reimplemented (and
//! subtly diverging) seven times.
//!
//! **The cursor is a key, not an offset.** `after` names the last key of the
//! previous page and the next page starts strictly after it in lexicographic
//! storage order. An offset would be wrong here: objects are created and
//! deleted while an operator pages through, and an insert before the boundary
//! makes an offset either re-serve a row already shown or skip one entirely.
//! A key cursor cannot do either, and it stays valid even if the object it
//! names is deleted between requests.
//!
//! **These endpoints are reads.** Paging through a listing has to remain
//! available to a read-only policy, so `after` / `limit` travel as query
//! parameters (a GET body does not survive the HTTP boundary) and are lifted
//! into `Request::data` by [`crate::util::parse_query_allowlist`].

use serde_json::{json, Map, Value};

use bv_errors::RvError;

use crate::{Request, Response};

/// Longest cursor accepted. Cursors are storage key names echoed back from a
/// previous page, so anything longer is not a key this vault produced.
const MAX_CURSOR_LEN: usize = 512;

/// Page size bounds for one endpoint.
#[derive(Debug, Clone, Copy)]
pub struct PageLimits {
    /// Page size when the caller does not ask for one.
    pub default_limit: usize,
    /// Hard ceiling, so one request cannot ask the server to load and
    /// serialize an unbounded number of objects.
    pub max_limit: usize,
}

impl PageLimits {
    pub const fn new(default_limit: usize, max_limit: usize) -> Self {
        Self { default_limit, max_limit }
    }
}

impl Default for PageLimits {
    fn default() -> Self {
        Self { default_limit: 100, max_limit: 500 }
    }
}

/// One page of keys, resolved from a full key listing plus the caller's
/// cursor.
#[derive(Debug, Clone)]
pub struct Page {
    /// The keys on this page, in storage order.
    pub keys: Vec<String>,
    /// Total keys in the listing, across every page, so a client can show
    /// progress (or a "showing the first N of M" notice) without walking it.
    pub total: usize,
    /// Cursor to pass back as `after`. Empty when this was the last page.
    pub next: String,
}

impl Page {
    /// Whether more pages follow.
    pub fn truncated(&self) -> bool {
        !self.next.is_empty()
    }
}

/// Read an all-optional request field.
///
/// [`Request::get_data_or_default`] reports `ErrRequestNoData` when a request
/// carries neither a `data` map nor a body — which is precisely what a GET
/// with no query string looks like. For an endpoint whose every parameter is
/// optional that is a request for the first page, not an error, so the
/// absent-data case collapses to `Null` and each caller applies its own
/// default.
pub fn optional_param(req: &Request, key: &str) -> Value {
    req.get_data_or_default(key).unwrap_or(Value::Null)
}

/// Resolve the caller's `after` / `limit` against a full key listing.
///
/// `keys` is sorted in place: storage backends are not required to list in
/// any particular order, and the cursor is only meaningful against a stable
/// one.
///
/// Fails with a 400 when `after` is not a plausible key. A cursor is echoed
/// back from a page this server produced, so a malformed one is a client bug
/// worth reporting — silently rewinding to the first page instead would turn
/// a paging loop into an infinite one, which is far harder to diagnose.
/// Callers whose keys have a known shape (a hex serial, a UUID) should check
/// that themselves before calling; this can only enforce what is true of
/// every key.
pub fn paginate(
    req: &Request,
    mut keys: Vec<String>,
    limits: PageLimits,
) -> Result<Page, RvError> {
    let after = optional_param(req, "after").as_str().unwrap_or("").trim().to_string();
    if after.len() > MAX_CURSOR_LEN {
        return Err(bv_errors::bv_error_response_status!(
            400,
            "`after` is not a valid cursor: too long"
        ));
    }
    let limit = match optional_param(req, "limit").as_u64().unwrap_or(0) {
        0 => limits.default_limit,
        n => (n as usize).min(limits.max_limit),
    };

    keys.sort();
    let total = keys.len();
    let start = match after.is_empty() {
        true => 0,
        // The first index strictly greater than the cursor, so a cursor
        // naming a since-deleted key still resumes in the right place
        // instead of erroring or restarting.
        false => keys.partition_point(|k| k.as_str() <= after.as_str()),
    };
    let page: Vec<String> = keys.into_iter().skip(start).take(limit).collect();
    let next = match start + page.len() < total {
        true => page.last().cloned().unwrap_or_default(),
        false => String::new(),
    };
    Ok(Page { keys: page, total, next })
}

/// Build the response body every `<list>/info` endpoint returns.
///
/// `records` must be parallel to [`Page::keys`] — one summary per key, in the
/// same order — so a client can correlate them positionally. An object that
/// fails to load should still contribute a record carrying its key and no
/// metadata: a listing that silently omits an object is worse than one that
/// shows a row the operator can drill into to find out why.
pub fn page_response(page: &Page, records: Vec<Value>) -> Response {
    debug_assert_eq!(
        page.keys.len(),
        records.len(),
        "page_response: one record per key, in key order"
    );
    let mut data: Map<String, Value> = Map::new();
    data.insert("keys".into(), json!(page.keys));
    data.insert("records".into(), Value::Array(records));
    data.insert("total".into(), json!(page.total));
    data.insert("next".into(), json!(page.next));
    data.insert("truncated".into(), json!(page.truncated()));
    Response::data_response(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        field::{Field, FieldType},
        path::Path,
    };
    use std::sync::Arc;

    /// A request carrying the given query parameters, matched against a path
    /// that declares the pagination fields.
    ///
    /// Declaring them matters: `Request`'s field accessors refuse a key the
    /// matched path does not know, so a test against a field-less path would
    /// read every parameter as absent and pass no matter what `paginate`
    /// did with them.
    fn req_with(params: Option<Value>) -> Request {
        let mut path = Path::new("test/info");
        path.fields.insert(
            "after".into(),
            Arc::new(Field {
                required: false,
                field_type: FieldType::Str,
                default: json!(""),
                description: String::new(),
            }),
        );
        path.fields.insert(
            "limit".into(),
            Arc::new(Field {
                required: false,
                field_type: FieldType::Int,
                default: json!(0),
                description: String::new(),
            }),
        );
        let mut req = Request::new("test/info");
        req.match_path = Some(Arc::new(path));
        req.data = params.and_then(|v| v.as_object().cloned());
        req
    }

    fn keys(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("key-{i:03}")).collect()
    }

    #[test]
    fn no_parameters_yields_the_first_page() {
        // A GET with no query string carries no `data` at all; that is the
        // first page, not an error.
        let req = req_with(None);
        let page = paginate(&req, keys(250), PageLimits::new(100, 500)).unwrap();
        assert_eq!(page.keys.len(), 100);
        assert_eq!(page.keys[0], "key-000");
        assert_eq!(page.total, 250);
        assert_eq!(page.next, "key-099");
        assert!(page.truncated());
    }

    #[test]
    fn cursor_resumes_strictly_after_the_previous_page() {
        let req = req_with(Some(json!({"after": "key-099", "limit": 5})));
        let page = paginate(&req, keys(250), PageLimits::default()).unwrap();
        assert_eq!(page.keys, vec!["key-100", "key-101", "key-102", "key-103", "key-104"]);
        assert_eq!(page.next, "key-104");
    }

    #[test]
    fn walking_every_page_sees_each_key_exactly_once() {
        let all = keys(23);
        let mut seen: Vec<String> = Vec::new();
        let mut cursor = String::new();
        for _ in 0..20 {
            let params = match cursor.is_empty() {
                true => json!({"limit": 5}),
                false => json!({"limit": 5, "after": cursor}),
            };
            let page = paginate(&req_with(Some(params)), all.clone(), PageLimits::default())
                .unwrap();
            seen.extend(page.keys.iter().cloned());
            cursor = page.next.clone();
            if cursor.is_empty() {
                break;
            }
        }
        assert!(cursor.is_empty(), "paging failed to terminate");
        assert_eq!(seen, all);
    }

    #[test]
    fn a_key_inserted_before_the_cursor_does_not_shift_the_boundary() {
        // The reason the cursor is a key and not an offset: with an offset,
        // this insert makes the next page re-serve `key-002`.
        let mut all = keys(6);
        let first = paginate(&req_with(Some(json!({"limit": 3}))), all.clone(), PageLimits::default())
            .unwrap();
        assert_eq!(first.next, "key-002");

        all.push("key-000a".to_string());
        let second = paginate(
            &req_with(Some(json!({"limit": 3, "after": first.next}))),
            all,
            PageLimits::default(),
        )
        .unwrap();
        assert_eq!(second.total, 7, "the new key is counted");
        for k in &second.keys {
            assert!(!first.keys.contains(k), "`{k}` served twice across the insert");
        }
    }

    #[test]
    fn a_cursor_naming_a_deleted_key_still_resumes_in_place() {
        // `key-002` was the previous page's last key and has since been
        // deleted. Resuming must continue at `key-003`, not restart.
        let mut all = keys(6);
        all.retain(|k| k != "key-002");
        let page = paginate(
            &req_with(Some(json!({"after": "key-002", "limit": 2}))),
            all,
            PageLimits::default(),
        )
        .unwrap();
        assert_eq!(page.keys, vec!["key-003", "key-004"]);
    }

    #[test]
    fn limit_is_clamped_to_the_endpoint_ceiling() {
        let req = req_with(Some(json!({"limit": 100_000})));
        let page = paginate(&req, keys(1000), PageLimits::new(100, 500)).unwrap();
        assert_eq!(page.keys.len(), 500, "one request cannot ask for everything");
    }

    #[test]
    fn an_over_long_cursor_is_refused() {
        let req = req_with(Some(json!({"after": "x".repeat(MAX_CURSOR_LEN + 1)})));
        assert!(paginate(&req, keys(3), PageLimits::default()).is_err());
    }

    #[test]
    fn a_cursor_past_the_end_yields_an_empty_final_page() {
        let req = req_with(Some(json!({"after": "zzz"})));
        let page = paginate(&req, keys(5), PageLimits::default()).unwrap();
        assert!(page.keys.is_empty());
        assert_eq!(page.total, 5);
        assert!(!page.truncated(), "an empty page is never truncated");
    }

    #[test]
    fn keys_are_sorted_before_paging() {
        // Storage backends are not required to list in order, and the
        // cursor is only meaningful against a stable one.
        let unsorted = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        let page = paginate(&req_with(None), unsorted, PageLimits::default()).unwrap();
        assert_eq!(page.keys, vec!["a", "b", "c"]);
    }

    #[test]
    fn response_carries_the_page_envelope() {
        let page = Page {
            keys: vec!["a".into(), "b".into()],
            total: 7,
            next: "b".into(),
        };
        let resp = page_response(&page, vec![json!({"name": "a"}), json!({"name": "b"})]);
        let data = resp.data.unwrap();
        assert_eq!(data["total"], json!(7));
        assert_eq!(data["next"], json!("b"));
        assert_eq!(data["truncated"], json!(true));
        assert_eq!(data["keys"], json!(["a", "b"]));
        assert_eq!(data["records"][1]["name"], json!("b"));
    }
}
