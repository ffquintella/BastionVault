# Publishing crates to the Cloudsmith registry

BastionVault's library crates are published to the Cloudsmith Cargo
registry **`uox/bastionvault`**. This page is the contributor-facing
procedure. For *why* the workspace is being split into publishable
crates in the first place, see
[roadmaps/workspace-decomposition.md](https://github.com/ffquintella/BastionVault/blob/main/roadmaps/workspace-decomposition.md).

## The registry

Declared once, in the tracked `.cargo/config.toml`:

```toml
[registries]
uox-bastionvault = { index = "sparse+https://cargo.cloudsmith.io/uox/bastionvault/" }
```

Cloudsmith's web UI still shows the **git** index
(`https://dl.cloudsmith.io/public/uox/bastionvault/cargo/index.git`).
Both endpoints are live; we use the **sparse** one. Cargo then fetches
only the index entries a resolve actually needs over plain HTTPS instead
of cloning the whole index repo, which is what crates.io has defaulted to
since cargo 1.68 and needs no `git` binary on PATH — that matters for the
container build and for Windows CI runners. Fall back to the `.git` URL
only if Cloudsmith's sparse endpoint has an outage.

## Credentials — never in the repo

The Cloudsmith API key is a **publish credential**. Leaking it lets
someone push a crate that this workspace, the container build, and every
developer machine will then resolve and compile. Treat it like a signing
key.

Store it in one of exactly two places, both outside the repository:

```bash
make crates-login
```

writes it to `$CARGO_HOME/credentials.toml` (usually
`~/.cargo/credentials.toml`) via `cargo login`. For CI, set the
environment variable instead — no file involved:

```
CARGO_REGISTRIES_UOX_BASTIONVAULT_TOKEN
```

(The env var name is mechanical: `CARGO_REGISTRIES_` + the registry name
uppercased with `-` → `_` + `_TOKEN`.)

### What is guarded, and how

Cloudsmith's own instructions say to put the token in
`.cargo/credentials` — meaning **`~/.cargo/credentials`**. Read from
inside a project directory that reads as "the repo's `.cargo/`", which is
exactly the mistake that leaks a key. So:

| Path | Read by cargo? | Tracked? | Guard |
|---|---|---|---|
| `$CARGO_HOME/credentials.toml` | yes | no — outside the repo | the recommended location |
| `.cargo/credentials`, `.cargo/credentials.toml` | **no** | would be | `.gitignore`d as a backstop |
| `.cargo/config.toml` | **yes** | **yes** | ⚠ a token here **would be committed** — the file's header comment says so at the point of temptation |

Cargo has no `config.local.toml` override, so there is no in-repo place
to hide a token. Per-machine registry settings belong in
`$CARGO_HOME/config.toml` or in `CARGO_*` env vars.

## Publishing

```bash
make crates-verify        # package the dependency-free crates; no token needed
make crates-publish-dry   # dry-run the whole set in dependency order
make crates-publish       # for real — prompts for confirmation
```

`scripts/publish-crates.sh` drives all three. Dry run is the default;
`--execute` is required to upload, and it refuses to run on a dirty tree
so every published artefact corresponds to a real commit.

Other flags:

```bash
scripts/publish-crates.sh --only bv_crypto,bv-client   # subset (order still enforced)
scripts/publish-crates.sh --registry other-registry
```

### Publish order is load-bearing

A registry rejects a crate whose dependencies it cannot resolve, so the
script publishes in topological order:

```
bv-errors                (no workspace deps)
bv-shamir                -> bv-errors
bv-context               -> bv-errors
bv-metrics               (no workspace deps)
bv_plugin_surface        (no workspace deps)
bv_crypto                (no workspace deps)
bv-storage               -> bv-errors, bv-metrics, bv_crypto
bv-logical               -> bv-errors, bv-context, bv-storage
bv-utils                 -> bv-errors, bv-shamir, bv-storage, bv-logical, bv_crypto
bv-audit                 -> bv-errors, bv-logical, bv-storage
bv_plugin_manifest       -> bv_plugin_surface
bastion-plugin-sdk       -> bv_plugin_surface
bastion-plugin-testkit   (no workspace deps)
bv-client                -> bv_plugin_surface
bv-plugin-pack           -> bv_crypto, bv_plugin_manifest
```

`bv_crypto` has no workspace dependencies of its own but is listed above the
Tier 0 storage crates deliberately: `bv-storage` (the barriers) and `bv-utils`
both depend on it, so it must reach the registry first.

### Internal deps must name the registry

An internal dependency needs **all three** of `version`, `path`, and
`registry`:

```toml
bv_plugin_surface = { version = "0.1.0", path = "../bv_plugin_surface", registry = "uox-bastionvault" }
```

- Without `version`, `cargo publish` refuses the crate outright.
- Without `registry`, the *published* manifest points at **crates.io**,
  and publishing fails with `no matching package named bv_plugin_surface
  found / location searched: crates.io index`.

`path` still wins for local builds, so adding these keys changes nothing
about `cargo build` or `cargo check`.

### On a virgin registry, dependents report "deferred"

Cargo resolves every dependency in its **published** form before it will
stage a tarball, and `--no-verify` does not skip that step. So a crate
cannot be dry-run or verified until its dependencies are actually live.
The dry run classifies this rather than failing:

```
── bv_plugin_manifest 0.1.0 ───────────────────────────
   SKIPPED — needs 'bv_plugin_surface' on the registry first (publish order).
```

That is expected on the first publish, not a fault. A real `--execute`
run publishes in order, waiting for the index between crates, so each
dependent becomes resolvable as its turn arrives.

### Publishing is irreversible

A registry never lets a version be re-uploaded, and Cloudsmith's delete
does not free the version for reuse. A bad publish is fixed by **yanking
and bumping**, never by overwriting. That is why the default is a dry run
and why `make crates-publish` asks you to type the registry name.

## Accidental-publish guard

Every publishable crate carries:

```toml
publish = ["uox-bastionvault"]
```

which makes a bare `cargo publish` (no `--registry`) fail immediately
instead of pushing an internal crate to crates.io. `bastion-vault-gui`
carries `publish = false` — it ships as a signed installer, never as a
crate.

## Known constraints

**~~The root `bastion_vault` crate path-depends on unpublished
`ferro-*` crates.~~ Resolved 2026-08-14.** It used to path-depend on
`ferro-child-verify`, `ferro-svid-verify`, and `ferro-crypto` in the
vendored tree `third_party/ferrogate-sdk-rust/`, and a crate cannot be
published while any dependency is unpublished. FerroGate now publishes
all three to its own Cloudsmith registry, `uox/ferrogate` (public;
registered as `uox-ferrogate` in `.cargo/config.toml`), and the root
crate depends on them with `version` + `registry` — option 1 below, which
this doc already called the clean answer. The vendored tree is gone.

**The root `bastion_vault` crate still isn't published, for a different
reason.** The `[patch.crates-io]` entries for `sspi` / `picky*` /
`hiqlite` are workspace-local config and are *not* themselves a hard
blocker, but a published `bastion_vault` would resolve those deps from
crates.io rather than from the forks, which is a behaviour change nobody
has validated. Also note that publishing a crate whose dependencies come
from a *third* registry requires the destination registry to allow
cross-registry deps — Cloudsmith does, crates.io does not — so
`bastion_vault` could only ever go to `uox-bastionvault`, never to
crates.io.

Two ways forward, when it matters:

1. Validate the `[patch.crates-io]` forks' published equivalents (or
   publish the forks too) and ship the facade to `uox-bastionvault`.
2. Keep the facade crate unpublished. The decomposition roadmap makes
   this viable: consumers depend on the split crates, and
   `bastion_vault` stays a local assembly point.

Nothing here blocks publishing the library crates above — all fifteen are
free of vendored path deps.

## CI

Not wired up yet. When it is, the shape is:

- publish only on a tag, never on a branch push;
- token from the repository secret, via
  `CARGO_REGISTRIES_UOX_BASTIONVAULT_TOKEN`;
- `scripts/publish-crates.sh --execute`, which already enforces the clean
  tree and the ordering.

See [roadmaps/workspace-decomposition.md](https://github.com/ffquintella/BastionVault/blob/main/roadmaps/workspace-decomposition.md)
Phase 6 for how per-crate versions relate to the product version that
`make bump-*` moves.
