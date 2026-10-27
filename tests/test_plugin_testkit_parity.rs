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

/// ABI 1.4: the dynamic-secret gate answers the same codes in both runtimes —
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

/// ABI 1.4: outside a dynamic RPC the session is checked before the request
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
