# Vendored: FerroGate Rust SDK

This directory holds the two crates from the **FerroGate Rust SDK** that
BastionVault needs — `ferro-child-verify` and `ferro-crypto` — used to verify
FerroGate-issued, composite-signed (Ed25519 + ML-DSA-65) machine-identity tokens
for the `auth/ferrogate/` backend. It is **not** part of the BastionVault Cargo
workspace (see the `exclude` list in the root `Cargo.toml`).

### What was changed vs. the release

- **Subset only.** Vendored: `ferro-crypto`, `ferro-child-verify`, and
  `ferro-svid-verify` (the last for the direct-SVID `accept_svid` mode + CRL
  enforcement). Not vendored: `ferro-proto`, `ferro-svid`, `ferro-attest` (not
  needed by the verification paths, and they drag in protoc / TPM build
  requirements).
- **Manifests de-inherited.** Each crate's `Cargo.toml` originally inherited
  `version` / `edition` / deps from the SDK `[workspace]`. Those are inlined to
  concrete values here so the crates stand alone as path dependencies (a nested
  workspace under our excluded path does not resolve inheritance cleanly). The
  inlined versions are copied verbatim from the SDK `[workspace.dependencies]`.
- **`src/` sources are byte-for-byte verbatim.** Only the two `Cargo.toml`
  files were edited; no Rust source was touched.

## Source

| | |
|---|---|
| Project | FerroGate |
| Release | `releases/v0.21.3` |
| URL | https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.21.3 |
| Asset | `ferrogate-sdk-rust-0.21.3.tgz` |
| SHA-256 | `42231c10cf08d2cf1f56974396157884187f333aa0236776144ed80b957430d0` |
| SDK version | `0.21.3` |

## Updating

```bash
make vendor-ferrogate-sdk           # newest release
make vendor-ferrogate-sdk-check     # report drift only, change nothing
```

`scripts/vendor-ferrogate-sdk.sh` resolves the newest non-prerelease release that
ships a `ferrogate-sdk-rust-*.tgz` asset, downloads it, records its SHA-256 in the
table above, copies in the three crates listed here, and de-inherits each manifest
from the SDK workspace. Pass `--version X.Y.Z` to pin a specific release. The
`Cargo.toml` files it writes are generated — do not hand-edit them.

The script is deliberately **not** wired into any build: `cargo build` must never
reach the network for these crates. Two reasons.

1. **It would not help publishing.** `cargo publish` resolves every dependency in
   its *published* (registry) form from the manifest before it will stage a
   tarball; a dependency sitting on disk at a `path` does not satisfy that. So
   downloading the SDK at build time does nothing for the root crate's
   unpublishability — only publishing these three crates to a registry does. See
   `docs/publishing-crates.md` § Known constraints.
2. **These crates are a trust root.** They verify FerroGate machine-identity
   tokens for the `auth/ferrogate/` backend. Fetching them during a build moves
   the build's trust base from "source reviewed in a commit" to "whatever that URL
   served at build time", and makes builds non-reproducible and offline-hostile.

Upgrades are therefore explicit, and a verifier change stays a reviewable commit.
Read the diff and run `cargo nextest run --lib -E 'test(ferrogate)'` before
committing.

Do not hand-edit the vendored sources; patch upstream and re-vendor instead.

### 0.15.0 → 0.21.3 (breaking, handled in-tree)

`ferro_child_verify::normalize_htu` was removed, and `verify_bound`'s internal
`htu` comparison became **byte-exact** where 0.15.0 normalized both sides. Left
alone, that silently rejects machine logins whose DPoP `htu` differs from the
configured audience only by a trailing slash, host case, or an explicit default
port — three cases BastionVault has tests asserting it accepts.
`src/modules/credential/ferrogate/verify.rs` now owns that normalization
(`normalize_origin`, a verbatim port of the removed helper) and picks the `htu`
spelling handed to `verify_bound` accordingly, so the accepted set is unchanged.
