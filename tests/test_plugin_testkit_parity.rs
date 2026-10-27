//! ABI-parity guard between `bastion-plugin-testkit` and the real
//! plugin runtime (`src/plugins/runtime.rs`).
//!
//! The testkit ships an in-memory mock of the `bv.*` host-import
//! surface so plugin authors can unit-test compiled `.wasm` artifacts
//! without booting a vault. That mock is only useful while it stays
//! byte-compatible with the real runtime. These tests enforce the two
//! directions that can drift:
//!
//! 1. Every import the testkit mirrors (`HOST_IMPORTS`) must be
//!    registered — with the same signature — by the real runtime's
//!    linker. The conformance module imports all of them; if the real
//!    runtime dropped or re-typed one, instantiation fails here.
//! 2. The core invoke semantics (envelope in, `bv.set_response` out,
//!    status code, fuel accounting) must match: the same module run
//!    through both runtimes must produce the same outcome + response.
//!
//! If the host runtime *adds* a new import, add it to the testkit's
//! `HOST_IMPORTS` (and mock it) — this file's doc comment is the
//! reminder; the conformance module will then verify it exists.

use bastion_plugin_testkit::{conformance_wat, TestHost};
use bastion_vault::plugins::manifest::{Capabilities, PluginManifest, RuntimeKind};
use bastion_vault::plugins::runtime::{InvokeOutcome, WasmRuntime};
use sha2::{Digest, Sha256};

fn manifest_for(name: &str, bytes: &[u8]) -> PluginManifest {
    let mut h = Sha256::new();
    h.update(bytes);
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    PluginManifest {
        name: name.to_string(),
        version: "0.0.1".to_string(),
        plugin_type: "test".to_string(),
        engine_type: None,
        runtime: RuntimeKind::Wasm,
        abi_version: "1.0".to_string(),
        sha256: hex,
        size: bytes.len() as u64,
        capabilities: Capabilities { log_emit: false, ..Default::default() },
        description: String::new(),
        config_schema: vec![],
        signature: String::new(),
        signing_key: String::new(),
        surface: None,
        client_assets: vec![],
    }
}

/// Direction 1: the real runtime registers every import the testkit
/// mirrors, with matching signatures — otherwise instantiation of the
/// conformance module fails.
#[tokio::test]
async fn real_runtime_registers_every_testkit_import() {
    let wasm = wat::parse_str(conformance_wat()).expect("conformance wat parses");
    let manifest = manifest_for("testkit-conformance", &wasm);
    let runtime = WasmRuntime::new().expect("runtime");
    let out = runtime.invoke(&manifest, &wasm, b"ping", None).await.expect(
        "conformance module must instantiate against the real runtime — \
                 if this fails, src/plugins/runtime.rs and bastion-plugin-testkit \
                 disagree about the bv.* import surface",
    );
    assert!(matches!(out.outcome, InvokeOutcome::Success));
    assert_eq!(out.response, b"ping");
}

/// Direction 2: identical invoke semantics for a core-independent
/// module (echo via `bv.set_response`, plus a non-zero status path).
#[tokio::test]
async fn invoke_semantics_match_between_runtimes() {
    let wasm = wat::parse_str(conformance_wat()).expect("wat parses");
    let manifest = manifest_for("testkit-echo", &wasm);
    let input = br#"{"op":"read","path":"x","data":{}}"#;

    let real = WasmRuntime::new().expect("runtime").invoke(&manifest, &wasm, input, None).await.expect("real invoke");

    let host = TestHost::builder("testkit-echo").build();
    let mock = host.invoke_raw(&wasm, input).expect("testkit invoke");

    assert!(matches!(real.outcome, InvokeOutcome::Success));
    assert!(mock.is_success());
    assert_eq!(real.response, mock.response);
    assert!(real.fuel_consumed > 0);
    assert!(mock.fuel_consumed > 0);
}

// ── ABI 1.4: process host calls ─────────────────────────────────────────

use bastion_plugin_testkit::sql::{check_release as mock_check_release, MockRelease};
use bastion_plugin_testkit::TestCaller;
use bastion_vault::plugins::manifest::ResourceCredentialKind;
use bastion_vault::plugins::sql_host::{self, check_release, SqlEndpoint, SqlReleaseMaterial};
use serde_json::{json, Value};

const SQL_METHODS: [&str; 4] =
    ["resource_sql_target", "resource_sql_authorize", "resource_sql_credential", "connect_ticket_redeem"];

fn sql_params(method: &str) -> Value {
    match method {
        "resource_sql_authorize" => json!({"resource": "db", "checks": [{"capability": "sql_select", "target": "server"}]}),
        "resource_sql_credential" => json!({"resource": "db", "profile": "ro", "session_ref": "s-1"}),
        "connect_ticket_redeem" => json!({"resource": "db", "profile": "ro", "ticket": "t-1"}),
        _ => json!({"resource": "db"}),
    }
}

fn sql_manifest(declared: bool) -> PluginManifest {
    let mut m = manifest_for("dbms-management", b"x");
    m.runtime = RuntimeKind::Process;
    m.abi_version = "1.4".to_string();
    m.capabilities.caller_identity = true;
    if declared {
        m.capabilities.sql_gate = true;
        m.capabilities.resource_credentials = vec![ResourceCredentialKind::Sql];
    }
    m
}

fn code(e: &str) -> &str {
    e.split(':').next().unwrap_or(e)
}

/// The testkit mirrors every process host call the runtimes answer.
#[test]
fn process_host_call_surfaces_match() {
    let host: std::collections::BTreeSet<_> =
        bastion_vault::plugins::process_runtime::HOST_CALL_METHODS.iter().collect();
    let mock: std::collections::BTreeSet<_> = bastion_plugin_testkit::process::PROCESS_HOST_CALLS.iter().collect();
    assert_eq!(host, mock);
    for m in SQL_METHODS {
        assert!(sql_host::METHODS.contains(&m) && host.contains(&m), "{m}");
    }
    for m in ["dynamic_lease_register", "dynamic_audit_emit", "dynamic_pool_checkout"] {
        assert!(host.contains(&m), "{m}");
    }
}

/// Without the manifest capability, and outside an invocation, both refuse
/// with the same code — before any grant or vault is consulted.
#[tokio::test]
async fn sql_host_calls_refuse_in_the_same_order() {
    let caller = {
        let mut req = bastion_vault::logical::Request::new("dbms/v2/sessions");
        req.auth = Some(bastion_vault::logical::Auth::default());
        bastion_vault::plugins::invocation::InvocationCaller::from_request(&req).unwrap()
    };
    let bare = TestHost::builder("dbms-management").build();
    let declared = TestHost::builder("dbms-management").sql_gate(true).resource_credentials(true).build();
    let ana = TestCaller::new("ent-ana");
    for m in SQL_METHODS {
        let p = sql_params(m);
        let real = sql_host::handle(&sql_manifest(false), None, m, &p, Some(&caller)).await.unwrap_err();
        let mock = bare.process_host_call(Some(&ana), m, &p).unwrap_err();
        assert_eq!((code(&real), code(&mock)), ("forbidden", "forbidden"), "{m}");

        let real = sql_host::handle(&sql_manifest(true), None, m, &p, None).await.unwrap_err();
        let mock = declared.process_host_call(None, m, &p).unwrap_err();
        assert_eq!((code(&real), code(&mock)), ("no_invocation", "no_invocation"), "{m}");
    }
}

/// §5.4 rules 3–5 decide the same on both sides.
#[test]
fn release_rules_agree() {
    let cases: Vec<(&str, &str, Option<Value>, &str)> = vec![
        ("sql", "direct", Some(json!("db1:5432")), "db1:5432"),
        ("sql", "rustion-preferred", Some(json!(["x:1", "DB1:5432"])), "db1:5432"),
        ("ssh", "direct", Some(json!("db1:5432")), "db1:5432"),
        ("sql", "rustion-required", Some(json!("db1:5432")), "db1:5432"),
        ("sql", "bastion", Some(json!("db1:5432")), "db1:5432"),
        ("sql", "direct", None, "db1:5432"),
        ("sql", "direct", Some(json!([])), "db1:5432"),
        ("sql", "direct", Some(json!(5432)), "db1:5432"),
        ("sql", "direct", Some(json!(["db1"])), "db1:5432"),
        ("sql", "direct", Some(json!("db1:5433")), "db1:5432"),
        ("sql", "direct", Some(json!("[::1]:5432")), "[::1]:5432"),
    ];
    for (protocol, transport, bound, endpoint) in cases {
        let real = check_release(&SqlReleaseMaterial {
            protocol: protocol.into(),
            endpoint: SqlEndpoint::parse(endpoint).unwrap(),
            transport: transport.into(),
            transport_source: "tier".into(),
            secret_id: "s".into(),
            sql_endpoint: bound.clone(),
            username: "u".into(),
            password: zeroize::Zeroizing::new("p".into()),
            require_mfa: false,
        })
        .map_err(|r| r.reason());
        let mock = mock_check_release(&MockRelease {
            protocol: protocol.into(),
            endpoint: endpoint.into(),
            transport: transport.into(),
            secret_id: "s".into(),
            sql_endpoint: bound.clone(),
            username: "u".into(),
            password: "p".into(),
            require_mfa: false,
        });
        assert_eq!(real, mock, "{protocol} {transport} {bound:?} {endpoint}");
    }
}

/// Actor stamping is decided the same way: ABI 1.4 or later with
/// caller_identity.
#[test]
fn audit_actor_stamping_agrees() {
    for (minor, caller_identity) in [(3u32, true), (4, false), (4, true), (5, true)] {
        let mut m = sql_manifest(false);
        m.abi_version = format!("1.{minor}");
        m.capabilities.caller_identity = caller_identity;
        let real = bastion_vault::plugins::plugin_audit::stamps_actor(&m);
        let mock_host =
            TestHost::builder("p").audit_emit(true).abi_minor(minor).caller_identity(caller_identity).build();
        mock_host.process_host_call(Some(&TestCaller::new("e")), "audit_emit", &json!({"payload": {}})).unwrap();
        let mock = mock_host.audit_events()[0].get("actor").is_some();
        assert_eq!(real, mock, "1.{minor} caller_identity={caller_identity}");
    }
}

/// ABI 1.5: the dynamic-secret gate answers the same codes in both runtimes —
/// refused without the capability, "no session" with it outside a dynamic RPC.
#[tokio::test]
async fn dynamic_capability_gate_matches_between_runtimes() {
    let wat = r#"(module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "dynamic_lease_register" (func $lease (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "bv_alloc") (param i32) (result i32) i32.const 8192)
      (func (export "bv_run") (param i32 i32) (result i32)
        (i32.store (i32.const 2048) (call $lease (i32.const 0) (i32.const 0) (i32.const 4096) (i32.const 1024)))
        (call $set_response (i32.const 2048) (i32.const 4))
        (i32.const 0)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");
    let code = |bytes: &[u8]| i32::from_le_bytes(bytes[..4].try_into().unwrap());

    let mut manifest = manifest_for("parity-dynamic", &wasm);
    let real = WasmRuntime::new().unwrap().invoke(&manifest, &wasm, b"{}", None).await.unwrap();
    let mock = TestHost::builder("parity-dynamic").build().invoke_raw(&wasm, b"{}").unwrap();
    assert_eq!(code(&real.response), bastion_plugin_testkit::DYNAMIC_FORBIDDEN);
    assert_eq!(real.response, mock.response);

    manifest.capabilities.dynamic_lease_register = true;
    let real = WasmRuntime::new().unwrap().invoke(&manifest, &wasm, b"{}", None).await.unwrap();
    let mock = TestHost::builder("parity-dynamic").dynamic_lease_register(true).build().invoke_raw(&wasm, b"{}").unwrap();
    assert_eq!(code(&real.response), bastion_plugin_testkit::DYNAMIC_NO_SESSION);
    assert_eq!(real.response, mock.response);
}

/// ABI 1.5: outside a dynamic RPC the session is checked before the request
/// is parsed, in both runtimes: a malformed request still gets "no session".
#[tokio::test]
async fn dynamic_no_session_is_answered_before_the_request_is_parsed() {
    let wat = r#"(module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "dynamic_lease_register" (func $lease (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 100) "not json")
      (func (export "bv_alloc") (param i32) (result i32) i32.const 8192)
      (func (export "bv_run") (param i32 i32) (result i32)
        (i32.store (i32.const 2048) (call $lease (i32.const 100) (i32.const 8) (i32.const 4096) (i32.const 1024)))
        (call $set_response (i32.const 2048) (i32.const 4))
        (i32.const 0)))"#;
    let wasm = wat::parse_str(wat).expect("wat parses");
    let code = |bytes: &[u8]| i32::from_le_bytes(bytes[..4].try_into().unwrap());

    let mut manifest = manifest_for("parity-dynamic-parse", &wasm);
    manifest.capabilities.dynamic_lease_register = true;
    let real = WasmRuntime::new().unwrap().invoke(&manifest, &wasm, b"{}", None).await.unwrap();
    let host = TestHost::builder("parity-dynamic-parse").dynamic_lease_register(true).build();
    let mock = host.invoke_raw(&wasm, b"{}").unwrap();
    assert_eq!(code(&real.response), bastion_plugin_testkit::DYNAMIC_NO_SESSION);
    assert_eq!(real.response, mock.response);
    assert_eq!(bastion_plugin_testkit::DYNAMIC_UNAVAILABLE, -5, "the testkit names every host code");
}
