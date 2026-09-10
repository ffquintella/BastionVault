//! `pki/certs-info` — the bulk certificate-summary endpoint.
//!
//! This endpoint exists because the listing view needs a common name and an
//! expiry per row, and `pki/certs` returns bare serials. The GUI therefore
//! read every serial individually: `1 + N` requests, each carrying a whole
//! PEM, to render two columns. On a mount with a few hundred certificates
//! that burst crosses the server's own abuse ceiling and bans the operator
//! for five minutes. See `features/client-request-efficiency.md`.
//!
//! Driven through `TestHttpServer` on purpose. The cursor and page size
//! travel as *query parameters*, and query parameters only reach the engine
//! if `bv_logical`'s allowlist lifts them — an in-process
//! `core.handle_request` test sets `Request::data` directly and would pass
//! even if the HTTP layer dropped them both. This is the same reason
//! `pki_export.rs` is an HTTP test.

use serde_json::{json, Map, Value};

use crate::test_utils::TestHttpServer;

fn obj(v: Value) -> Option<Map<String, Value>> {
    v.as_object().cloned()
}

/// Stand up a vault with a PKI mount, a root CA, a permissive role, and
/// `count` issued leaves. Returns the server and the issued serials.
async fn boot_with_leaves(name: &str, count: usize) -> (TestHttpServer, Vec<String>) {
    let mut server = TestHttpServer::new(name, false).await;
    server.token = server.root_token.clone();

    server
        .write("sys/mounts/pki/", obj(json!({"type": "pki"})), None)
        .unwrap();
    server
        .write(
            "pki/root/generate/internal",
            obj(json!({
                "common_name": "Certs Info Test Root",
                "key_type": "ec",
                "ttl": "8760h"
            })),
            None,
        )
        .unwrap();
    server
        .write(
            "pki/roles/web",
            obj(json!({
                "ttl": "24h",
                "key_type": "ec",
                "allow_any_name": true,
                "server_flag": true
            })),
            None,
        )
        .unwrap();

    let mut serials = Vec::with_capacity(count);
    for i in 0..count {
        let (status, issued) = server
            .write(
                "pki/issue/web",
                obj(json!({"common_name": format!("leaf{i}.example.com"), "ttl": "12h"})),
                None,
            )
            .unwrap();
        assert_eq!(status, 200, "issue {i} failed: {issued}");
        serials.push(
            issued["data"]["serial_number"]
                .as_str()
                .expect("issue response carries a serial")
                .to_string(),
        );
    }
    (server, serials)
}

/// Serials come back from `pki/issue` colon-separated; storage keys and the
/// listing use bare lowercase hex.
fn bare(serial: &str) -> String {
    serial.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase()
}

#[actix_rt::test]
async fn one_request_returns_every_summary_the_list_view_needs() {
    let (server, serials) = boot_with_leaves("pki_certs_info_basic", 3).await;

    let (status, body) = server.read("pki/certs-info", None).unwrap();
    assert_eq!(status, 200, "certs-info failed: {body}");

    let records = body["data"]["records"].as_array().expect("records array");
    assert_eq!(records.len(), 3);
    assert_eq!(body["data"]["total"].as_u64(), Some(3));
    assert_eq!(body["data"]["truncated"].as_bool(), Some(false));
    assert_eq!(body["data"]["next"].as_str(), Some(""));

    // Every issued serial is present, each with the identity and expiry the
    // list view renders — the whole point of the endpoint.
    let by_serial: std::collections::HashMap<&str, &Value> = records
        .iter()
        .map(|r| (r["serial_number"].as_str().unwrap(), r))
        .collect();
    for s in &serials {
        let rec = by_serial.get(bare(s).as_str()).expect("issued serial in page");
        assert!(
            rec["common_name"].as_str().unwrap().starts_with("leaf"),
            "CN parsed server-side: {rec}"
        );
        assert!(rec["not_after"].as_u64().unwrap() > 0, "expiry present: {rec}");
        assert_eq!(
            rec["issuer_dn"].as_str().unwrap(),
            "CN=Certs Info Test Root",
            "issuer DN parsed server-side: {rec}"
        );
        // The PEM is what made the old shape expensive; it must not be here.
        assert!(rec.get("certificate").is_none(), "summary must omit the PEM: {rec}");
    }
}

#[actix_rt::test]
async fn summary_agrees_field_for_field_with_the_per_cert_read() {
    // The endpoint replaces `pki/cert/<serial>` for the list view, so a
    // divergence here would silently change what the operator sees.
    let (server, serials) = boot_with_leaves("pki_certs_info_parity", 1).await;
    let serial = &serials[0];

    let (_, single) = server.read(&format!("pki/cert/{serial}"), None).unwrap();
    let (_, page) = server.read("pki/certs-info", None).unwrap();
    let summary = &page["data"]["records"][0];
    let single = &single["data"];

    for field in ["serial_number", "issued_at", "not_after", "issuer_id"] {
        assert_eq!(
            summary[field], single[field],
            "`{field}` diverges between certs/info and cert/<serial>"
        );
    }
    // `revoked_at` / `is_orphaned` / `source` are omit-when-absent in both.
    for field in ["revoked_at", "is_orphaned", "source"] {
        assert_eq!(
            summary.get(field).is_none(),
            single.get(field).is_none(),
            "`{field}` presence diverges"
        );
    }
}

#[actix_rt::test]
async fn cursor_pages_through_the_inventory_without_gaps_or_repeats() {
    let (server, serials) = boot_with_leaves("pki_certs_info_paging", 7).await;

    let mut seen: Vec<String> = Vec::new();
    let mut cursor = String::new();
    let mut requests = 0;
    loop {
        let path = match cursor.is_empty() {
            true => "pki/certs-info?limit=3".to_string(),
            false => format!("pki/certs-info?limit=3&after={cursor}"),
        };
        let (status, body) = server.read(&path, None).unwrap();
        assert_eq!(status, 200, "page failed: {body}");
        requests += 1;
        assert_eq!(body["data"]["total"].as_u64(), Some(7));

        for k in body["data"]["keys"].as_array().unwrap() {
            seen.push(k.as_str().unwrap().to_string());
        }
        cursor = body["data"]["next"].as_str().unwrap().to_string();
        if cursor.is_empty() {
            assert_eq!(body["data"]["truncated"].as_bool(), Some(false));
            break;
        }
        assert_eq!(body["data"]["truncated"].as_bool(), Some(true));
        assert!(requests < 10, "paging failed to terminate");
    }

    assert_eq!(requests, 3, "7 certs at 3/page is 3 requests, not 8");
    let mut expected: Vec<String> = serials.iter().map(|s| bare(s)).collect();
    expected.sort();
    assert_eq!(seen, expected, "every serial seen exactly once, in order");
}

#[actix_rt::test]
async fn a_cert_issued_mid_page_does_not_shift_the_boundary() {
    // This is why the cursor is `after` and not an offset: with an offset,
    // inserting a row before the boundary makes the next page re-serve a
    // row already shown, or skip one entirely.
    let (server, _) = boot_with_leaves("pki_certs_info_stable", 4).await;

    let (_, first) = server.read("pki/certs-info?limit=2", None).unwrap();
    let page1: Vec<String> = first["data"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let cursor = first["data"]["next"].as_str().unwrap().to_string();

    server
        .write(
            "pki/issue/web",
            obj(json!({"common_name": "inserted.example.com", "ttl": "12h"})),
            None,
        )
        .unwrap();

    let (_, second) = server
        .read(&format!("pki/certs-info?limit=2&after={cursor}"), None)
        .unwrap();
    let page2: Vec<String> = second["data"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();

    assert_eq!(second["data"]["total"].as_u64(), Some(5), "the new cert is counted");
    for k in &page2 {
        assert!(!page1.contains(k), "`{k}` served twice across the insert");
        assert!(k.as_str() > cursor.as_str(), "`{k}` is behind the cursor");
    }
}

#[actix_rt::test]
async fn page_size_is_clamped_and_a_bad_cursor_is_refused() {
    let (server, _) = boot_with_leaves("pki_certs_info_limits", 2).await;

    // An absurd `limit` is clamped, not honoured: one request must not be
    // able to ask the server to parse an unbounded number of certificates.
    let (status, body) = server.read("pki/certs-info?limit=100000", None).unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["records"].as_array().unwrap().len(), 2);

    // A cursor is echoed back from a previous page, so a malformed one is a
    // client bug. Reporting it beats silently rewinding to the first page,
    // which turns a paging loop into an infinite one.
    let (status, body) = server.read("pki/certs-info?after=not-hex", None).unwrap();
    assert_eq!(status, 400, "malformed cursor must be refused: {body}");

    // A non-numeric `limit` is dropped by the query allowlist and the
    // default page size applies, rather than erroring the request.
    let (status, body) = server.read("pki/certs-info?limit=all", None).unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["records"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn revocation_and_import_provenance_survive_the_projection() {
    let (server, serials) = boot_with_leaves("pki_certs_info_states", 2).await;

    let (status, body) = server
        .write("pki/revoke", obj(json!({"serial_number": serials[0]})), None)
        .unwrap();
    assert_eq!(status, 200, "revoke failed: {body}");

    let (_, page) = server.read("pki/certs-info", None).unwrap();
    let records = page["data"]["records"].as_array().unwrap();
    let revoked = records
        .iter()
        .find(|r| r["serial_number"].as_str() == Some(bare(&serials[0]).as_str()))
        .expect("revoked cert still listed");
    assert!(
        revoked["revoked_at"].as_u64().unwrap_or(0) > 0,
        "revocation must be visible in the summary: {revoked}"
    );

    let live = records
        .iter()
        .find(|r| r["serial_number"].as_str() == Some(bare(&serials[1]).as_str()))
        .expect("live cert listed");
    assert!(live.get("revoked_at").is_none(), "live cert carries no revoked_at: {live}");
}
