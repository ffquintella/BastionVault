use super::*;

/// Echoes the input back via `bv.set_response`.
fn echo_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (call $set_response (local.get $ptr) (local.get $len))
        (i32.const 0))
    )
    "#
}

fn fail_wat() -> &'static str {
    r#"
    (module
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (i32.const 7))
    )
    "#
}

fn loop_wat() -> &'static str {
    r#"
    (module
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (loop $forever (br $forever))
        (i32.const 0))
    )
    "#
}

/// storage_put("k", input) then storage_get("k") → response.
fn storage_round_trip_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "storage_put" (func $sput (param i32 i32 i32 i32) (result i32)))
      (import "bv" "storage_get" (func $sget (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 4096))
      (data (i32.const 0) "k")
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (local $r i32)
        (call $sput (i32.const 0) (i32.const 1) (local.get $ptr) (local.get $len))
        drop
        (local.set $r
          (call $sget (i32.const 0) (i32.const 1) (i32.const 2048) (i32.const 1024)))
        (call $set_response (i32.const 2048) (local.get $r))
        (i32.const 0))
    )
    "#
}

/// storage_put("k", input); responds with the i32 return code as 4 LE bytes.
fn storage_put_status_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "storage_put" (func $sput (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 4096))
      (data (i32.const 0) "k")
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (i32.store (i32.const 2048)
          (call $sput (i32.const 0) (i32.const 1) (local.get $ptr) (local.get $len)))
        (call $set_response (i32.const 2048) (i32.const 4))
        (i32.const 0))
    )
    "#
}

/// config_get("greeting") into a 256-byte buffer; responds with the value.
fn config_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "config_get" (func $cget (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 4096))
      (data (i32.const 0) "greeting")
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (local $r i32)
        (local.set $r
          (call $cget (i32.const 0) (i32.const 8) (i32.const 2048) (i32.const 256)))
        (call $set_response (i32.const 2048) (local.get $r))
        (i32.const 0))
    )
    "#
}

/// config_get("greeting") into a 1-byte buffer; responds with the i32
/// return code as 4 LE bytes (exercises STORAGE_BUFFER_TOO_SMALL).
fn config_tiny_buffer_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "config_get" (func $cget (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 4096))
      (data (i32.const 0) "greeting")
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (i32.store (i32.const 2048)
          (call $cget (i32.const 0) (i32.const 8) (i32.const 3072) (i32.const 1)))
        (call $set_response (i32.const 2048) (i32.const 4))
        (i32.const 0))
    )
    "#
}

/// Logs the input at info, audits it, responds with audit_emit's
/// return code as 4 LE bytes.
fn log_audit_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "log" (func $log (param i32 i32 i32)))
      (import "bv" "audit_emit" (func $audit (param i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 4096))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (call $log (i32.const 3) (local.get $ptr) (local.get $len))
        (i32.store (i32.const 2048)
          (call $audit (local.get $ptr) (local.get $len)))
        (call $set_response (i32.const 2048) (i32.const 4))
        (i32.const 0))
    )
    "#
}

/// now_unix_ms() → 8 LE bytes response.
fn now_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "now_unix_ms" (func $now (result i64)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (i64.store (i32.const 2048) (call $now))
        (call $set_response (i32.const 2048) (i32.const 8))
        (i32.const 0))
    )
    "#
}

/// crypto_encrypt("transit/keys/k1", input); on `ret >= 0` responds
/// with the ciphertext, else with the return code as 4 LE bytes at a
/// distinct marker offset (so tests can tell the two shapes apart by
/// status framing: negative path responds exactly 4 bytes).
fn crypto_encrypt_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "crypto_encrypt" (func $enc (param i32 i32 i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 8192))
      (data (i32.const 0) "transit/keys/k1")
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (local $r i32)
        (local.set $r
          (call $enc
            (i32.const 0) (i32.const 15)
            (local.get $ptr) (local.get $len)
            (i32.const 4096) (i32.const 2048)))
        (if (i32.ge_s (local.get $r) (i32.const 0))
          (then (call $set_response (i32.const 4096) (local.get $r)))
          (else
            (i32.store (i32.const 2048) (local.get $r))
            (call $set_response (i32.const 2048) (i32.const 4))))
        (i32.const 0))
    )
    "#
}

/// crypto_random(16) twice → 32-byte response.
fn crypto_random_wat() -> &'static str {
    r#"
    (module
      (import "bv" "set_response" (func $set_response (param i32 i32)))
      (import "bv" "crypto_random" (func $rand (param i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 4096))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "bv_run") (param $ptr i32) (param $len i32) (result i32)
        (call $rand (i32.const 16) (i32.const 2048) (i32.const 16))
        drop
        (call $rand (i32.const 16) (i32.const 2064) (i32.const 16))
        drop
        (call $set_response (i32.const 2048) (i32.const 32))
        (i32.const 0))
    )
    "#
}

/// Form hook: echoes its JSON input, packed-i64 return ABI.
fn hook_echo_wat() -> &'static str {
    r#"
    (module
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "bv_alloc") (param $len i32) (result i32)
        (local $ptr i32)
        (local.set $ptr (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $ptr))
      (func (export "validate") (param $ptr i32) (param $len i32) (result i64)
        (i64.or
          (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
          (i64.extend_i32_u (local.get $len))))
    )
    "#
}

fn le_i32(bytes: &[u8]) -> i32 {
    i32::from_le_bytes(bytes.try_into().expect("4 bytes"))
}

#[test]
fn echo_round_trips_envelope() {
    let host = TestHost::builder("echo").build();
    let out = host
        .invoke(
            echo_wat().as_bytes(),
            "write",
            "codes/gh",
            serde_json::json!({"secret": "JBSW"}),
        )
        .unwrap();
    assert!(out.is_success());
    assert!(out.fuel_consumed > 0);
    let v = out.response_json().unwrap();
    assert_eq!(v["op"], "write");
    assert_eq!(v["path"], "codes/gh");
    assert_eq!(v["data"]["secret"], "JBSW");
}

#[test]
fn plugin_error_status_is_surfaced() {
    let host = TestHost::builder("fail").build();
    let out = host.invoke_raw(fail_wat().as_bytes(), b"{}").unwrap();
    assert_eq!(out.outcome, InvokeOutcome::PluginError(7));
    assert_eq!(out.status(), 7);
    assert!(out.response.is_empty());
}

#[test]
fn infinite_loop_exhausts_fuel() {
    let host = TestHost::builder("loop").fuel(1_000_000).build();
    let err = host.invoke_raw(loop_wat().as_bytes(), b"{}").unwrap_err();
    assert!(matches!(err, TestkitError::FuelExhausted), "got: {err:?}");
}

#[test]
fn storage_round_trip_with_prefix_granted() {
    let host = TestHost::builder("kv").storage_prefix("").build();
    let out = host.invoke_raw(storage_round_trip_wat().as_bytes(), b"hello").unwrap();
    assert!(out.is_success());
    assert_eq!(out.response, b"hello");
    let dump = host.storage_dump();
    assert_eq!(dump.get("k").map(Vec::as_slice), Some(b"hello".as_slice()));
}

#[test]
fn storage_forbidden_without_prefix_capability() {
    let host = TestHost::builder("kv").build(); // no storage_prefix
    let out = host.invoke_raw(storage_put_status_wat().as_bytes(), b"hello").unwrap();
    assert!(out.is_success());
    assert_eq!(le_i32(&out.response), STORAGE_FORBIDDEN);
    assert!(host.storage_dump().is_empty());
}

#[test]
fn storage_forbidden_outside_declared_prefix() {
    // Prefix "managed" but the plugin writes key "k".
    let host = TestHost::builder("kv").storage_prefix("managed").build();
    let out = host.invoke_raw(storage_put_status_wat().as_bytes(), b"x").unwrap();
    assert_eq!(le_i32(&out.response), STORAGE_FORBIDDEN);
}

#[test]
fn storage_persists_across_invocations_and_can_be_seeded() {
    let host = TestHost::builder("kv")
        .storage_prefix("")
        .storage("k", b"seeded".to_vec())
        .build();
    // First invoke overwrites the seed and reads it back.
    let out = host.invoke_raw(storage_round_trip_wat().as_bytes(), b"second").unwrap();
    assert_eq!(out.response, b"second");
    // Second invoke sees the first invoke's write.
    let out2 = host.invoke_raw(storage_round_trip_wat().as_bytes(), b"third").unwrap();
    assert_eq!(out2.response, b"third");
    assert_eq!(host.storage_dump().len(), 1);
}

#[test]
fn config_value_is_readable() {
    let host = TestHost::builder("cfg").config("greeting", "hello world").build();
    let out = host.invoke_raw(config_wat().as_bytes(), b"{}").unwrap();
    assert!(out.is_success());
    assert_eq!(out.response, b"hello world");
}

#[test]
fn config_buffer_too_small_is_reported() {
    let host = TestHost::builder("cfg").config("greeting", "hello world").build();
    let out = host.invoke_raw(config_tiny_buffer_wat().as_bytes(), b"{}").unwrap();
    assert_eq!(le_i32(&out.response), STORAGE_BUFFER_TOO_SMALL);
}

#[test]
fn missing_config_returns_not_found() {
    let host = TestHost::builder("cfg").build();
    let out = host.invoke_raw(config_wat().as_bytes(), b"{}").unwrap();
    // config_wat passes the return code straight to set_response; a
    // negative length is ignored, so the response stays empty.
    assert!(out.response.is_empty());
}

#[test]
fn logs_and_audit_are_captured_when_granted() {
    let host = TestHost::builder("obs").audit_emit(true).build();
    let out = host
        .invoke_raw(log_audit_wat().as_bytes(), br#"{"event":"rotated"}"#)
        .unwrap();
    assert_eq!(le_i32(&out.response), 0);
    assert_eq!(out.logs.len(), 1);
    assert_eq!(out.logs[0].level, 3);
    assert_eq!(out.logs[0].line, r#"{"event":"rotated"}"#);
    assert_eq!(out.audit_events.len(), 1);
    assert_eq!(out.audit_events[0]["path"], "sys/plugins/obs/event");
    assert_eq!(out.audit_events[0]["data"]["plugin_event"]["event"], "rotated");
}

#[test]
fn audit_forbidden_without_capability_and_logs_dropped_when_disabled() {
    let host = TestHost::builder("obs").log_emit(false).build();
    let out = host.invoke_raw(log_audit_wat().as_bytes(), b"payload").unwrap();
    assert_eq!(le_i32(&out.response), AUDIT_FORBIDDEN);
    assert!(out.logs.is_empty());
    assert!(host.audit_events().is_empty());
}

#[test]
fn clock_can_be_pinned_and_stepped() {
    let host = TestHost::builder("clock").now_ms(1_700_000_000_000).build();
    let out = host.invoke_raw(now_wat().as_bytes(), b"{}").unwrap();
    assert_eq!(i64::from_le_bytes(out.response.clone().try_into().unwrap()), 1_700_000_000_000);
    host.set_now_ms(1_700_000_030_000);
    let out2 = host.invoke_raw(now_wat().as_bytes(), b"{}").unwrap();
    assert_eq!(i64::from_le_bytes(out2.response.clone().try_into().unwrap()), 1_700_000_030_000);
}

#[test]
fn crypto_mock_encrypt_requires_allowlisted_key() {
    // Allowed: deterministic mock ciphertext.
    let host = TestHost::builder("crypt").allow_key("transit/keys/k1").build();
    let out = host.invoke_raw(crypto_encrypt_wat().as_bytes(), b"secret").unwrap();
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    assert_eq!(out.response, format!("bvault:test:{}", B64.encode(b"secret")).into_bytes());

    // Not allowed: CRYPTO_FORBIDDEN.
    let denied = TestHost::builder("crypt").build();
    let out = denied.invoke_raw(crypto_encrypt_wat().as_bytes(), b"secret").unwrap();
    assert_eq!(out.response.len(), 4);
    assert_eq!(le_i32(&out.response), CRYPTO_FORBIDDEN);
}

#[test]
fn crypto_random_is_deterministic_per_seed() {
    let a = TestHost::builder("rng").rng_seed(42).build();
    let b = TestHost::builder("rng").rng_seed(42).build();
    let c = TestHost::builder("rng").rng_seed(43).build();
    let ra = a.invoke_raw(crypto_random_wat().as_bytes(), b"{}").unwrap().response;
    let rb = b.invoke_raw(crypto_random_wat().as_bytes(), b"{}").unwrap().response;
    let rc = c.invoke_raw(crypto_random_wat().as_bytes(), b"{}").unwrap().response;
    assert_eq!(ra.len(), 32);
    assert_eq!(ra, rb);
    assert_ne!(ra, rc);
    // The two 16-byte draws within one invocation differ (stream advances).
    assert_ne!(ra[..16], ra[16..]);
}

#[test]
fn undeclared_import_fails_instantiation() {
    // A module importing something the host never registers must be
    // refused at instantiation — the capability-boundary invariant.
    let wat = r#"
    (module
      (import "bv" "does_not_exist" (func $nope (param i32)))
      (memory (export "memory") 1)
      (func (export "bv_alloc") (param i32) (result i32) (i32.const 0))
      (func (export "bv_run") (param i32 i32) (result i32) (i32.const 0))
    )
    "#;
    let host = TestHost::builder("bad").build();
    let err = host.invoke_raw(wat.as_bytes(), b"{}").unwrap_err();
    assert!(matches!(err, TestkitError::Instantiate(_)), "got: {err:?}");
}

#[test]
fn conformance_module_instantiates_and_echoes() {
    let host = TestHost::builder("conformance").build();
    let out = host.invoke_raw(conformance_wat().as_bytes(), b"ping").unwrap();
    assert!(out.is_success());
    assert_eq!(out.response, b"ping");
}

#[test]
fn form_hook_echo_round_trips() {
    let input = serde_json::json!({"name": "gh", "secret": "JBSWY3DP"});
    let out = hooks::run_form_hook(hook_echo_wat().as_bytes(), "validate", &input).unwrap();
    assert_eq!(out, input);
}

#[test]
fn form_hook_missing_export_is_a_clear_error() {
    let err =
        hooks::run_form_hook(hook_echo_wat().as_bytes(), "nope", &serde_json::json!({})).unwrap_err();
    assert!(matches!(err, TestkitError::Invoke(_)), "got: {err:?}");
}

#[test]
fn data_helper_mirrors_translate_response() {
    let host = TestHost::builder("echo").build();
    // The echo plugin returns the envelope itself, which has no "data"
    // object member at the top level... craft one via invoke_raw.
    let out = host
        .invoke_raw(echo_wat().as_bytes(), br#"{"data": {"code": "123456"}}"#)
        .unwrap();
    assert_eq!(out.data().unwrap()["code"], "123456");
    let none = host.invoke_raw(echo_wat().as_bytes(), br#"{"data": null}"#).unwrap();
    assert!(none.data().is_none());
}
