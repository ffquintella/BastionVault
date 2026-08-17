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

## Two version schemes

Conflating these is the mistake this section exists to prevent.

| | what it is | who moves it |
|---|---|---|
| **Product** | one number — what `bvault --version` prints and what the installers are named after. Root crate, `bvault-cli`, GUI. **Not published.** | `make bump-patch` / `bump-minor` / `bump-major` |
| **Library** | 38 independent numbers, one per publishable crate under `crates/`. Moved by **content**, not by release. | `make crates-bump` |

`bv-shamir` has not changed since it was extracted in Phase 1. It should
not be republished because the GUI shipped, and under this split it is
not.

`bv-server` is the exception that proves the rule: Tier 4 like
`bvault-cli`, but it carries its own `0.1.0` because nothing prints it.
It is unpublishable either way, so the number is inert.

## Releasing only what changed

```bash
make crates-plan               # what changed, and what would ship — builds nothing
make crates-bump               # patch-bump exactly those crates
cargo check --workspace --exclude bastion-vault-gui   # refresh Cargo.lock
git commit
make crates-publish-changed    # build + upload exactly those, in dependency order
make crates-tag-push           # push the release record
```

`make crates-plan` answers "what needs publishing?" per crate, from three
inputs:

1. the crate's last release tag, `<name>-v<version>`, written by the
   publish step;
2. `git diff <that tag> HEAD -- <the crate's directory>`;
3. the registry's sparse index — is the version in the manifest already
   published, in which case a change needs a bump before it can ship.

Each crate lands in one of three states: **publish** (this version is not
on the registry), **bump** (it is, and the crate changed since), or
**skip**. `make crates-publish-changed` refuses to run while anything is
in `bump`, because a published version cannot be overwritten and failing
early beats failing halfway through an ordered run.

Add `OFFLINE=1` to skip the index lookups and infer from tags alone.

### A patch bump does not cascade. That is the whole point.

Internal dependencies are declared `version = "0.1.0"`, which is a
**caret** requirement matching every `0.1.x`:

- **`0.1.0` → `0.1.1`** — nothing else is touched. The 32 crates that
  depend on `bv-errors` keep `version = "0.1.0"`, their packaged tarballs
  are unchanged, and they are not republished. A consumer resolving them
  picks up `0.1.1` on its own.
- **`0.1.x` → `0.2.0`** — `^0.1.0` stops matching, so `crates-bump`
  rewrites every dependent's requirement. Those manifests are now
  changed, so the next plan wants to bump and republish them too. The
  cascade is correct: a breaking change in a dependency *is* a change in
  its dependents.

Three things would destroy this property, and all three are called out in
`AGENTS.md` § Per-crate versioning: pinning internal deps with `=`,
moving dependencies into `[workspace.dependencies]` (cargo inlines the
concrete version at package time, so a workspace-level bump changes every
published manifest while changing no file in any crate directory — see
§ Known constraints), and letting `make bump-*` touch library versions.

`crates-bump` cannot decide whether your change is breaking. Nothing can:
that is a judgement about the crate's public API, and getting it wrong is
a broken downstream build rather than a failing test here. Patch is the
default; pass `MINOR=<crate>` deliberately.

## Publishing

```bash
make crates-verify              # package the dependency-free crates; no token needed
make crates-publish-changed-dry # dry-run only what changed
make crates-publish-changed     # for real — prompts for confirmation
make crates-publish-dry         # dry-run ALL 38, for validating the whole set
make crates-publish             # publish all 38 — the first release, or a re-cut
```

`scripts/publish-crates.sh` drives all of them. Dry run is the default;
`--execute` is required to upload, and it refuses to run on a dirty tree
so every published artefact corresponds to a real commit.

Other flags:

```bash
scripts/publish-crates.sh --only bv_crypto,bv-client   # subset (order still enforced)
scripts/publish-crates.sh --changed                     # only what the plan says
scripts/publish-crates.sh --plan-file .crates-plan.json # reuse a computed plan
scripts/publish-crates.sh --registry other-registry
```

### Tags are the record of what was published

A successful `--execute` tags each crate `<name>-v<version>`,
**immediately after that crate uploads** rather than at the end — a run
that dies halfway must still leave a correct baseline for the crates that
made it. Without a tag a crate reads as "never released" forever and gets
republished on every run.

Tags are created locally and **never pushed by the publish script**. The
upload is already irreversible; making the release record public stays a
separate, deliberate action — `make crates-tag-push`.

### Publish order is load-bearing, and derived

A registry rejects a crate whose dependencies it cannot resolve, so
publishing happens in topological order. That order is **derived from
`cargo metadata`** by `scripts/crates-plan.sh`, not maintained by hand.

The hand-maintained list this replaced had already drifted: `bv-core` and
`bv-kernel` were created in Phase 4.5 carrying
`publish = ["uox-bastionvault"]` and were never added to it, so every
release would have silently skipped the entire kernel — 38 publishable
crates, not the 36 the list knew about.

Which crates are publishable is derived the same way: the `publish` field
plus a fixpoint over the dependency graph, because a crate cannot ship
while anything it depends on cannot. That is how `bv-server` and
`bvault-cli` drop out today, and how they will rejoin on their own if
`bastion_vault` ever becomes publishable.

Path-only dev-dependencies are ignored, because cargo strips them from
the published manifest. Without that rule `bv-kernel` would look
unpublishable: it dev-depends on `bastion_vault` and `bv-server` to get
its test fixtures.

Run `make crates-plan` to see the current order.

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

**The root crate had no `publish` key at all until Phase 6**, which means
"any registry" — i.e. crates.io by default. A bare `cargo publish` in the
repo root would have tried to push the whole server there. It now carries
`publish = false`, and `make crates-plan` warns about any manifest that
is missing the key, so this cannot silently come back.

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

Nothing here blocks publishing the library crates above — all 38 are free
of vendored path deps.

**`[workspace.dependencies]` is deliberately not used, and this is where
the reason lives.** Consolidating shared external dependency versions
into the root manifest was a Phase 6 item and it was dropped, because it
is incompatible with releasing only what changed:

- Cargo **inlines** the concrete version when it packages a crate, so a
  crate using `serde = { workspace = true }` publishes a manifest saying
  `serde = "1.0.228"`.
- So bumping `serde` at the workspace level changes the *published
  manifest* of all 35 crates that use it, while changing **no file in any
  crate directory**.
- Change detection is a `git diff` of the crate's directory. It would see
  nothing, and 35 crates would go out of date on the registry silently.

The fix would be to treat the root manifest as part of every crate's
change signature — which means one `serde` bump republishes all 38, i.e.
exactly the whole-workspace release the per-crate scheme exists to avoid.
Per-crate dependency declarations keep the blast radius where the change
is: bumping `serde` for one crate changes one manifest and republishes
one crate.

The cost is real and worth stating: 83 external dependencies are declared
in more than one manifest, so version skew between crates is possible and
nothing here prevents it. `Cargo.lock` still unifies them for anything
built *from this workspace*; the exposure is a consumer resolving two of
our crates from the registry and getting two different minor versions of
a shared dependency. If that ever bites, the answer is a lint that
compares declarations across manifests, not a shared table.

## CI

Not wired up yet, and deliberately left manual for the first release —
the very first publish creates 38 versions that can never be reused, and
that is not a run to debug through a workflow file. When it is wired up,
the shape is:

- publish only on a tag, never on a branch push;
- token from the repository secret, via
  `CARGO_REGISTRIES_UOX_BASTIONVAULT_TOKEN`;
- `scripts/publish-crates.sh --changed --execute`, which enforces the
  clean tree, the ordering, and the "bump before you ship" rule;
- push the `<crate>-v<version>` tags it writes, or the next run
  republishes everything.

Note that CI needs the tags fetched (`fetch-depth: 0`), not just the
commit: without them every crate reads as "never released".

See [roadmaps/workspace-decomposition.md](https://github.com/ffquintella/BastionVault/blob/main/roadmaps/workspace-decomposition.md)
Phase 6 for how per-crate versions relate to the product version that
`make bump-*` moves.
