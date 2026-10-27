//! The SDK as a WASM plugin, driven through the testkit's wasmtime host with
//! the `bv.dynamic_*` imports. Needs the fixture built for wasm32 first;
//! `make dynamic-plugins-test` does that and then runs this test.

use bastion_plugin_testkit::TestHost;
use serde_json::{json, Value};

const PASSWORD: &str = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6";
const USER: &str = "v-root-readonly-1793000000-0a1b2c3d";

fn wasm() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/wasm32-unknown-unknown/release/bastion_plugin_dynamic_fixture.wasm"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}; build it with `make dynamic-plugins-test`"))
}

fn configured(wasm: &[u8], pool: bool) -> TestHost {
    let h = TestHost::builder("fixture-wasm")
        .storage_prefix("")
        .dynamic_lease_register(true)
        .dynamic_audit_emit(true)
        .dynamic_pool_checkout(pool)
        .dynamic_connection("prod")
        .build();
    let conn = json!({ "url": "fake://db", "password": "fixture-root-password", "allowed_roles": "*" });
    assert!(h.invoke(wasm, "write", "config/prod", conn).unwrap().is_success());
    let role = json!({ "connection": "prod", "creation_statements": ["CREATE {{name}}"] });
    assert!(h.invoke(wasm, "write", "roles/readonly", role).unwrap().is_success());
    h
}

fn generate() -> Value {
    json!({
        "op": "dynamic.generate", "role": "readonly", "connection": "prod",
        "statements": [format!("CREATE {USER}")],
        "credential": { "username": USER, "password": PASSWORD, "expiration": "2026-10-26T18:32:11Z" },
        "ttl_secs": 600,
    })
}

#[test]
#[ignore = "needs the wasm32 fixture artefact; run by `make dynamic-plugins-test`"]
fn generate_and_revoke_over_the_wasm_imports() {
    let wasm = wasm();
    let h = configured(&wasm, true);
    let out = h.invoke_dynamic(&wasm, &generate()).unwrap();
    assert!(out.is_success(), "{:?}", out.response_json());
    assert_eq!(
        out.dynamic_leases,
        [json!({"internal": {"v": 1}, "ttl_secs": 600, "max_ttl_secs": 0, "renewable": true})]
    );
    assert_eq!(out.dynamic_events, [json!({"event": "generate", "target_identity_type": "fake_user"})]);
    assert!(!String::from_utf8_lossy(&out.response).contains(PASSWORD));

    let revoke = json!({ "op": "dynamic.revoke", "role": "readonly", "connection": "prod", "username": USER,
                         "statements": [], "internal": { "v": 1 } });
    let out = h.invoke_dynamic(&wasm, &revoke).unwrap();
    assert!(out.is_success(), "{:?}", out.response_json());
    assert!(out.dynamic_leases.is_empty());
}

#[test]
#[ignore = "needs the wasm32 fixture artefact; run by `make dynamic-plugins-test`"]
fn an_undeclared_import_is_refused_and_recorded() {
    let wasm = wasm();
    let h = configured(&wasm, false);
    let out = h.invoke_dynamic(&wasm, &generate()).unwrap();
    assert_eq!(out.status(), 4, "{:?}", out.response_json());
    assert_eq!(out.capability_violations, ["dynamic_pool_checkout"]);
    assert!(out.dynamic_leases.is_empty());
}
