//! The SDK as a real process plugin, driven through the testkit's process
//! harness: the wire protocol and capability gate of the server's
//! `process_runtime.rs`, with the host's dynamic envelopes.

use std::path::Path;

use bastion_plugin_testkit::{TestHost, TestInvocation};
use serde_json::{json, Value};

const EXE: &str = env!("CARGO_BIN_EXE_bastion-plugin-dynamic-fixture");
const PASSWORD: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const ROOT: &str = "fixture-root-password";
const USER: &str = "v-root-readonly-1793000000-0a1b2c3d";

fn exe() -> &'static Path {
    Path::new(EXE)
}

fn host(pool: bool) -> TestHost {
    TestHost::builder("fixture")
        .storage_prefix("")
        .dynamic_lease_register(true)
        .dynamic_audit_emit(true)
        .dynamic_pool_checkout(pool)
        .dynamic_connection("prod")
        .build()
}

fn ok(out: &TestInvocation) {
    assert!(out.is_success(), "status {} body {:?}", out.status(), out.response_json());
}

fn configure(h: &TestHost) {
    let conn = json!({ "url": "fake://db", "password": ROOT, "allowed_roles": ["readonly", "failing"] });
    ok(&h.invoke_process(exe(), "write", "config/prod", conn).unwrap());
    for role in ["readonly", "failing"] {
        let recipe = json!({ "connection": "prod", "creation_statements": ["CREATE {{name}} PASSWORD {{password}}"] });
        ok(&h.invoke_process(exe(), "write", &format!("roles/{role}"), recipe).unwrap());
    }
}

fn generate(role: &str) -> Value {
    json!({
        "op": "dynamic.generate", "role": role, "connection": "prod",
        "statements": [format!("CREATE {USER} PASSWORD {PASSWORD}")],
        "credential": { "username": USER, "password": PASSWORD, "expiration": "2026-10-26T18:32:11Z" },
        "ttl_secs": 600,
    })
}

fn lease_op(op: &str) -> Value {
    json!({ "op": op, "role": "readonly", "connection": "prod", "username": USER,
            "statements": [format!("DROP {USER}")], "expiration": "2026-10-26T19:00:00Z",
            "ttl_secs": 300, "internal": { "v": 1 } })
}

fn no_secret_anywhere(h: &TestHost, out: &TestInvocation) {
    let body = String::from_utf8_lossy(&out.response).to_string();
    assert!(!body.contains(PASSWORD) && !body.contains(ROOT), "response: {body}");
    for line in h.process_stderr() {
        assert!(!line.contains(PASSWORD) && !line.contains(ROOT), "stderr: {line}");
    }
    for e in &out.dynamic_events {
        assert!(!e.to_string().contains(PASSWORD), "event: {e}");
    }
}

#[test]
fn generate_renew_revoke_over_the_process_protocol() {
    let h = host(true);
    configure(&h);

    let role = h.invoke_process_dynamic(exe(), &json!({ "op": "dynamic.role", "role": "readonly" })).unwrap();
    ok(&role);
    assert_eq!(role.data().unwrap()["connection"], "prod");

    let out = h.invoke_process_dynamic(exe(), &generate("readonly")).unwrap();
    ok(&out);
    assert_eq!(
        out.dynamic_leases,
        [json!({"internal": {"v": 1}, "ttl_secs": 600, "max_ttl_secs": 0, "renewable": true})]
    );
    assert_eq!(out.dynamic_events, [json!({"event": "generate", "target_identity_type": "fake_user"})]);
    no_secret_anywhere(&h, &out);
    assert!(h.storage_dump().keys().any(|k| k.ends_with(&format!("state/{USER}"))));

    let renewed = h.invoke_process_dynamic(exe(), &lease_op("dynamic.renew")).unwrap();
    ok(&renewed);
    assert_eq!(renewed.data().unwrap()["internal"]["until"], "2026-10-26T19:00:00Z");
    assert!(renewed.dynamic_leases.is_empty(), "a renew registers no lease");

    for _ in 0..2 {
        let revoked = h.invoke_process_dynamic(exe(), &lease_op("dynamic.revoke")).unwrap();
        ok(&revoked);
        assert!(revoked.dynamic_leases.is_empty());
    }
    assert!(!h.storage_dump().keys().any(|k| k.contains("state/")), "revoked, and a repeat revoke succeeds");
}

#[test]
fn a_target_failure_registers_no_lease_and_leaks_nothing() {
    let h = host(true);
    configure(&h);
    let out = h.invoke_process_dynamic(exe(), &generate("failing")).unwrap();
    assert_eq!(out.status(), 1, "the target status");
    assert!(out.dynamic_leases.is_empty(), "the host will revoke the identity");
    let error = out.response_json().unwrap()["error"].as_str().unwrap().to_string();
    assert!(error.contains("<redacted>"), "{error}");
    no_secret_anywhere(&h, &out);
    assert!(h.process_stderr().iter().any(|l| l.contains("dynamic.generate failed (target)")));
}

#[test]
fn an_undeclared_capability_is_refused_and_recorded() {
    let h = host(false);
    configure(&h);
    let out = h.invoke_process_dynamic(exe(), &generate("readonly")).unwrap();
    assert_eq!(out.status(), 4, "host refused");
    assert_eq!(out.capability_violations, ["dynamic_pool_checkout"]);
    assert!(out.dynamic_leases.is_empty());
}

#[test]
fn config_reads_never_return_the_root_credential_and_rotate_root_replaces_it() {
    let h = host(true);
    configure(&h);
    let read = h.invoke_process(exe(), "read", "config/prod", json!({})).unwrap();
    ok(&read);
    assert_eq!(read.data().unwrap(), json!({ "url": "fake://db", "allowed_roles": ["readonly", "failing"] }));
    no_secret_anywhere(&h, &read);

    let refused =
        h.invoke_process_dynamic(exe(), &json!({ "op": "dynamic.rotate_root", "connection": "prod" })).unwrap();
    assert_eq!(refused.status(), 7, "no host secret, no rotation");

    let rotate = json!({ "op": "dynamic.rotate_root", "connection": "prod", "credential": { "password": "rotated-root-secret-1" } });
    let out = h.invoke_process_dynamic(exe(), &rotate).unwrap();
    ok(&out);
    assert!(!String::from_utf8_lossy(&out.response).contains("rotated-root-secret-1"));
    let stored = h.storage_dump().into_iter().find(|(k, _)| k.ends_with("config/prod")).unwrap().1;
    let stored = String::from_utf8_lossy(&stored).to_string();
    assert!(stored.contains("rotated-root-secret-1") && !stored.contains(ROOT));
}
