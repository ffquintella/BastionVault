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
    let out = runtime
        .invoke(&manifest, &wasm, b"ping", None)
        .await
        .expect("conformance module must instantiate against the real runtime — \
                 if this fails, src/plugins/runtime.rs and bastion-plugin-testkit \
                 disagree about the bv.* import surface");
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

    let real = WasmRuntime::new()
        .expect("runtime")
        .invoke(&manifest, &wasm, input, None)
        .await
        .expect("real invoke");

    let host = TestHost::builder("testkit-echo").build();
    let mock = host.invoke_raw(&wasm, input).expect("testkit invoke");

    assert!(matches!(real.outcome, InvokeOutcome::Success));
    assert!(mock.is_success());
    assert_eq!(real.response, mock.response);
    assert!(real.fuel_consumed > 0);
    assert!(mock.fuel_consumed > 0);
}
