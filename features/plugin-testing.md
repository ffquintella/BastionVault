# Plugin Unit-Test Infrastructure

**Status:** Phase 1 shipped (testkit crate + ABI parity guard + `make plugins-test`).
**Owner:** Felipe Quintella
**Related:** [`features/plugin-system.md`](plugin-system.md) (the ABI under test), [`features/plugin-extensibility.md`](plugin-extensibility.md) (form hooks), [`features/plugin-app-extensions.md`](plugin-app-extensions.md) (future `bvx` surface).

## Summary

A unit-test harness so plugin authors — and this repo — can test compiled WASM plugin artifacts **against the real `bv_run` ABI without booting a vault**:

- **`crates/bastion-plugin-testkit`** — an in-memory mock host that mirrors the full `bv.*` host-import surface of `src/plugins/runtime.rs` (same signatures, same return codes, same prefix-rebase storage isolation, same fuel/memory defaults), plus a form-hook runner mirroring the GUI's Tauri-backend sandbox.
- **ABI parity guard** — the testkit publishes `HOST_IMPORTS` + `conformance_wat()`; [`tests/test_plugin_testkit_parity.rs`](../tests/test_plugin_testkit_parity.rs) drives that module through the real `WasmRuntime`, so mock↔runtime drift fails CI instead of lying to plugin authors.
- **`make plugins-test`** — one command that runs the testkit self-tests, the parity guard, and the in-crate `plugins::` substrate tests.

This slots between the two layers that already existed: the SDK's native `host_test` stubs (fast, but never executes WASM) and full-vault integration tests (real, but heavy — plugin-system Phase 5.11). The testkit is the missing middle: it exercises the **compiled artifact and the ABI**, in milliseconds.

## Testing layers (which one to use)

| Layer | What runs | What it catches | Where |
|---|---|---|---|
| SDK `host_test` stubs | Your handler as native Rust | Business logic | `bastion-plugin-sdk` (existing) |
| **Testkit (this feature)** | **Your compiled `.wasm` in wasmtime** | ABI misuse, alloc/response bugs, capability handling, buffer-retry logic, fuel blowups | `bastion-plugin-testkit` |
| Parity guard | Testkit's conformance module in the real runtime | Testkit↔runtime drift | `tests/test_plugin_testkit_parity.rs` |
| Vault integration | Everything, against a live core | Mount wiring, ACLs, leases | plugin-system Phase 5.11 (still pending CI infra) |

## Testkit API (v1)

```rust
use bastion_plugin_testkit::TestHost;

let wasm = std::fs::read("target/wasm32-wasip1/release/my_plugin.wasm")?;
let host = TestHost::builder("my-plugin")
    .storage_prefix("")                  // grant storage, like manifest.capabilities
    .audit_emit(true)
    .allow_key("transit/keys/wrap")      // crypto allowlist
    .config("period", "30")
    .storage("codes/gh", br#"{"secret":"JBSW"}"#.to_vec())  // seed state
    .now_ms(1_700_000_000_000)           // pin bv.now_unix_ms
    .rng_seed(42)                        // deterministic bv.crypto_random
    .build();

let out = host.invoke(&wasm, "read", "codes/gh", serde_json::json!({}))?;
assert!(out.is_success());
assert_eq!(out.data().unwrap()["issuer"], "github");
assert_eq!(out.logs.len(), 1);           // captured bv.log lines
assert_eq!(out.audit_events.len(), 1);   // captured bv.audit_emit payloads
assert!(host.storage_dump().contains_key("codes/gh"));
```

Key behaviors, all mirroring the server runtime:

- `invoke(op, path, data)` builds the exact `{"op","path","data"}` envelope `PluginLogicalBackend::build_envelope` produces; `invoke_raw` takes raw bytes.
- Capability gates: no `storage_prefix` → `STORAGE_FORBIDDEN`; `audit_emit(false)` → `AUDIT_FORBIDDEN`; `log_emit(false)` → lines dropped; crypto key not in `allow_key` set → `CRYPTO_FORBIDDEN`. Same numeric codes as the server.
- Storage is rebased to `core/plugins/<name>/data/…` with the same prefix-membership and `..` rules; it **persists across invocations** of one `TestHost` (barrier semantics); `storage_dump()` returns plugin-relative keys.
- Fuel/memory default to the server's 100 M / 256 MiB; `TestkitError::FuelExhausted` is a dedicated variant so infinite-loop regressions assert cleanly.
- A module importing anything the host doesn't register fails instantiation — the capability-boundary invariant is testable.
- `hooks::run_form_hook(wasm, "validate", &json)` mirrors the GUI sandbox: empty linker, packed-`i64` return ABI, 4 MiB payload caps.

**Mock crypto disclaimer:** `bv.crypto_*` transforms are deterministic, reversible stand-ins (`bvault:test:<b64>` framing) so plumbing is assertable — they are **not** cryptography and the docs say so loudly.

## Executing the tests

```bash
make plugins-test          # testkit self-tests + ABI parity + src/plugins::* unit tests
cargo test -p bastion-plugin-testkit          # just the harness
cargo test --test test_plugin_testkit_parity  # just the drift guard
```

Out-of-tree plugin authors (`plugins-ext/*` or third-party) add the crate as a dev-dependency and point `TestHost` at their compiled artifact:

```toml
[dev-dependencies]
bastion-plugin-testkit = { path = "../../crates/bastion-plugin-testkit" }
```

A typical author flow: `cargo build --target wasm32-wasip1 --release && cargo test` with a test that reads the built `.wasm`. (A `build.rs`-free convenience for this — auto-locating the artifact — is on the Phase 2 list.)

## Keeping the mock honest

Drift is the failure mode of every mock. Two mechanisms:

1. `HOST_IMPORTS` in the testkit is the single mirrored-surface declaration; `conformance_wat()` imports every entry with its exact signature.
2. The parity test instantiates that module against the **real** `WasmRuntime` and cross-checks invoke semantics (envelope in, `set_response` out, status, fuel accounting). If `src/plugins/runtime.rs` gains, drops, or re-types an import, the parity test fails and its doc comment says what to update.

Direction to remember: when adding a host import to `runtime.rs`, **add it to `HOST_IMPORTS` + mock it in the testkit in the same PR** — the parity test enforces the reverse direction automatically.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Testkit crate (mock host, envelope invoke, capability gates, mock crypto, form-hook runner, conformance fixtures), parity test, `make plugins-test` | **Done** |
| 2 | Author ergonomics: artifact auto-location helper, `assert_` matchers, snapshot-friendly `TestInvocation` serialization; adopt in `plugins-ext/` reference plugins' CI | Todo |
| 3 | Process-runtime harness: drive a process plugin binary over the stdio JSON-frame protocol with the same mock host semantics | Todo |
| 4 | `bvx` app-module mocks (menus/windows/API/net) in lockstep with [plugin-app-extensions](plugin-app-extensions.md) Phase 6 | Todo (blocked on that feature) |
| 5 | Bundle-level checks: `bv-plugin-pack test <bundle>` — unpack a `.bvplugin`, verify hashes/signature/manifest, smoke-invoke the module via the testkit | Todo |

Phase 3 note: the process runtime's host-call set (`src/plugins/process_runtime.rs`) is a subset of the WASM one (no `crypto_*`); the harness should reuse the same `HostState` so both runtimes are tested against one mock.

## Testing requirements (of the infrastructure itself)

- Every host import has at least one testkit self-test exercising success + its gated/denied path — shipped (20 tests in `crates/bastion-plugin-testkit/src/tests.rs`).
- Parity suite must stay green on every change to `src/plugins/runtime.rs` — enforced by `make plugins-test` and the normal `cargo test` workspace run.
- Fixtures are inline WAT (same convention as `runtime.rs` tests) so no pre-built `.wasm` blobs enter the repo.

## Tracking

Update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's phase table as phases land.
