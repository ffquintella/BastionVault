# Vendored: FerroGate Rust SDK

This directory holds the two crates from the **FerroGate Rust SDK** that
BastionVault needs — `ferro-child-verify` and `ferro-crypto` — used to verify
FerroGate-issued, composite-signed (Ed25519 + ML-DSA-65) machine-identity tokens
for the `auth/ferrogate/` backend. It is **not** part of the BastionVault Cargo
workspace (see the `exclude` list in the root `Cargo.toml`).

### What was changed vs. the release

- **Subset only.** The SDK also ships `ferro-proto`, `ferro-svid`,
  `ferro-svid-verify`, and `ferro-attest`; those are not vendored here (not
  needed by the child-token verification path, and they drag in protoc / TPM
  build requirements). They can be added later for the direct-SVID mode.
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
| Release | `releases/v0.15.0` |
| URL | https://github.com/ffquintella/FerroGate/releases/tag/releases/v0.15.0 |
| Asset | `ferrogate-sdk-rust-0.15.0.tgz` |
| SHA-256 | `2755507d7a3b0b6970efdd4be45f02dbdf7b0d4413ab2c9f1b0326873a2f4eef` |
| SDK version | `0.15.0` |

## Updating

Download the newer `ferrogate-sdk-rust-<v>.tgz` from the FerroGate releases page,
verify its SHA-256 against the release digest, extract over this directory, and
update the table above. Upgrades are deliberately explicit (no git/path tracking
of a working tree) so a verifier change is a reviewable commit.

Do not hand-edit the vendored sources; patch upstream and re-vendor instead.
