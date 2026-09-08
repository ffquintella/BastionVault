//! `sys/audit/events` filters over the real HTTP boundary.
//!
//! Written to pin down a suspected repeat of the kv-v2 `version` /
//! PKI-export defect, where a `GET` filter was silently dropped on the way
//! in and the caller got an unparameterised answer with no error. It is
//! *not* that: unlike those paths, `sys/audit/events` has its own HTTP shim
//! (`bv-server::sys::sys_audit_events_request_handler`) which parses the
//! query string unfiltered and parses a request body regardless of method,
//! and `ureq::Agent::run` does attach a body to a `GET` (it inserts
//! `ForceSendBody` whenever one is present). So both forms reach the
//! handler, and both are asserted below — the body form because the
//! embedded Tauri backend and the in-process API depend on it, the query
//! form because the GUI now also sends it there and a GET body is
//! something intermediaries may strip.
//!
//! What *was* silently dropped is a filter the caller supplied but that
//! could not be used: an unparseable bound, or a non-numeric limit. Both
//! became the unfiltered default (the 500 newest events), which is
//! indistinguishable from a working filter at the call site and is what
//! makes the Admin → Audit date pickers look inert when an operator types
//! `2026-01-01` into a free-text RFC3339 box. Those are now 400s.
//!
//! Driven through `TestHttpServer` on purpose: an in-process
//! `core.handle_request` test cannot see this class of bug at all, because
//! the embedded backend sets `Request::body` for reads and the HTTP one
//! does not. Same reasoning as `src/engine_tests/kv_version_read.rs` and
//! `src/engine_tests/pki_export.rs`.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// Stand up a vault and write four ACL policies, each of which appends to
/// the policy change-history the aggregator reads. Four is enough to be
/// distinguishable from any `limit` we ask for and far below the 500
/// default.
async fn boot_with_events(name: &str) -> TestHttpServer {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();

    for i in 1..=4 {
        let (status, got) = server
            .write(
                &format!("sys/policies/acl/window{i}"),
                obj(json!({"policy": format!("path \"secret/w{i}/*\" {{ capabilities = [\"read\"] }}")})),
                None,
            )
            .unwrap();
        assert!(
            status == 200 || status == 204,
            "policy write {i} failed ({status}): {got}"
        );
    }

    server
}

/// Read `sys/audit/events` at `path` and return the event array.
fn events_at(server: &TestHttpServer, path: &str) -> Vec<Value> {
    let (status, got) = server.read(path, None).unwrap();
    assert_eq!(status, 200, "read {path} failed: {got}");
    got.get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_else(|| panic!("no events array in response to {path}: {got}"))
}

/// `limit` on the query string really caps the response.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn audit_events_limit_query_param_caps_the_response() {
    let server = boot_with_events("audit_events_limit_query").await;

    let all = events_at(&server, "sys/audit/events");
    assert!(
        all.len() >= 4,
        "expected the four policy writes in the trail, got {}: {all:?}",
        all.len()
    );

    let capped = events_at(&server, "sys/audit/events?limit=2");
    assert_eq!(
        capped.len(),
        2,
        "?limit=2 must return exactly two events, not the unfiltered {}: {capped:?}",
        all.len()
    );

    // Newest-first ordering is what makes a small limit useful — the cap
    // must take the head of the list, not an arbitrary slice.
    assert_eq!(
        capped[0]["ts"], all[0]["ts"],
        "?limit=2 must return the newest events: {capped:?}"
    );
}

/// `from` / `to` on the query string really bound the window. Both bounds
/// are exercised in the direction that must return nothing, so a filter
/// that is ignored fails the assertion instead of passing by accident.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn audit_events_from_and_to_query_params_bound_the_window() {
    let server = boot_with_events("audit_events_window_query").await;

    let all = events_at(&server, "sys/audit/events");
    assert!(!all.is_empty(), "no events to filter");

    let future = events_at(&server, "sys/audit/events?from=2099-01-01T00:00:00Z");
    assert!(
        future.is_empty(),
        "?from in the far future must return nothing, got {} events — the \
         bound was dropped on the way in: {future:?}",
        future.len()
    );

    let past = events_at(&server, "sys/audit/events?to=2000-01-01T00:00:00Z");
    assert!(
        past.is_empty(),
        "?to in the far past must return nothing, got {} events — the bound \
         was dropped on the way in: {past:?}",
        past.len()
    );

    // A window that spans now keeps everything, so the bounds are not
    // simply refusing all rows.
    let spanning = events_at(
        &server,
        "sys/audit/events?from=2000-01-01T00:00:00Z&to=2099-01-01T00:00:00Z",
    );
    assert_eq!(
        spanning.len(),
        all.len(),
        "a window spanning now must keep every event: {spanning:?}"
    );
}

/// The body form of the same filters also reaches the handler. This is
/// the endpoint's own shim doing something `logical_routes` does not
/// (parse a body on a read), and the embedded Tauri backend plus the
/// in-process API rely on it — the GUI's query string is belt to this
/// braces, not a replacement.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn audit_events_filters_in_a_get_body_are_honoured_too() {
    let server = boot_with_events("audit_events_body_form").await;

    let all = events_at(&server, "sys/audit/events");
    assert!(all.len() >= 4, "no events to filter: {all:?}");

    let (status, got) = server
        .request(
            "GET",
            "sys/audit/events",
            obj(json!({"limit": 2})),
            None,
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "GET-with-body read failed: {got}");
    let via_body = got
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        via_body.len(),
        2,
        "a body-borne limit must be honoured — the embedded backend has no \
         other way to filter: {via_body:?}"
    );

    // Body wins over query when the two disagree, which is what lets the
    // GUI send both without the forms fighting.
    let (status, got) = server
        .request(
            "GET",
            "sys/audit/events?limit=1",
            obj(json!({"limit": 3})),
            None,
            None,
        )
        .unwrap();
    assert_eq!(status, 200, "GET-with-body-and-query read failed: {got}");
    let merged = got
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        merged.len(),
        3,
        "the body must take precedence over the query string: {merged:?}"
    );
}

/// The regression: a filter the caller did supply but that cannot be used
/// is refused, not silently downgraded to an unfiltered read.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn audit_events_unusable_filters_are_refused_not_ignored() {
    let server = boot_with_events("audit_events_unusable").await;

    for path in [
        // Free-text RFC3339 boxes: these are what an operator types.
        "sys/audit/events?from=yesterday",
        "sys/audit/events?to=2026-13-45",
        "sys/audit/events?from=2026-01-01",
        "sys/audit/events?limit=all",
        "sys/audit/events?limit=0",
    ] {
        let (status, got) = server.read(path, None).unwrap();
        assert_eq!(
            status, 400,
            "{path} must be refused, not answered with an unfiltered read: {got}"
        );
    }

    // An empty value is "no bound", not a malformed one — the GUI sends
    // each box's contents verbatim and an untouched field is empty.
    let (status, got) = server.read("sys/audit/events?from=&to=", None).unwrap();
    assert_eq!(status, 200, "empty bounds must mean unfiltered: {got}");

    // Same rule on the body path, so the embedded backend cannot end up
    // with the lenient behaviour the HTTP one just lost.
    let (status, got) = server
        .request(
            "GET",
            "sys/audit/events",
            obj(json!({"from": "yesterday"})),
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        status, 400,
        "a body-borne malformed bound must be refused too: {got}"
    );
}

/// An RFC3339 offset survives the query string. `bv-client`'s
/// `encode_query` percent-encodes `+`, so an operator-typed `+02:00`
/// arrives as `%2B02:00`; before the shim decoded it, the bound was
/// stored verbatim, failed to parse, and was dropped without a word.
#[maybe_async::test(
    feature = "sync_handler",
    async(all(not(feature = "sync_handler")), tokio::test)
)]
async fn audit_events_percent_encoded_offset_is_decoded() {
    let server = boot_with_events("audit_events_encoded_offset").await;

    // Far-future bound with an encoded `+00:00` offset: accepted (not a
    // 400) and actually applied (empty result), which together prove it
    // was decoded rather than passed through verbatim.
    let encoded = events_at(
        &server,
        "sys/audit/events?from=2099-01-01T00%3A00%3A00%2B00%3A00",
    );
    assert!(
        encoded.is_empty(),
        "a percent-encoded future bound must filter everything out: {encoded:?}"
    );

    // The same bound with a raw `+` decodes identically — this endpoint
    // does not use form-urlencoded semantics, where `+` would become a
    // space and break the timestamp.
    let raw = events_at(&server, "sys/audit/events?from=2099-01-01T00:00:00+00:00");
    assert!(
        raw.is_empty(),
        "a raw `+` offset must be treated as an offset, not a space: {raw:?}"
    );
}
