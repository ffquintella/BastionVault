# Roadmap: Packaging & Distribution

Status: **Active — Waves 1 + 2 shipped except for the Phase 1.5 trusted-proxy work. Wave 3 part-shipped: the CLI installers build on all four platforms, the GUI installers are wired to Tauri's bundler, and the downloads website's Phases 1 + 2 are done. What is left in Wave 3 is the release-signing CI and the `manifest.json` publish; the EV Authenticode custody question that gated it was answered on 2026-08-26 (see § Decisions), leaving a PKCS#11 branch in `sign_authenticode()` as the engineering work.**

## Goal

Give operators and end users **first-class, signed, verifiable
distribution channels** for every BastionVault artefact, with no
operator left writing their own Containerfile or compiling installers
from source.

Three deliverables, in order of operator value:

1. **Server container image** — one OCI image, parameterisable into
   standalone or Hiqlite-cluster shapes, signed and SBOM-attested.
2. **Native client installers** — `.deb`, `.rpm`, `.pkg`, `.msi` for
   both the Tauri GUI and the `bvault` CLI, on Linux / macOS / Windows.
3. **Client distribution website** — a small OCI image that serves the
   client installers from inside the operator's network with a clean
   landing page, signature surfacing, and a JSON manifest the GUI can
   poll for "update available" notices.

Each deliverable has its own feature spec; this document is the
sequencer.

## Deliverables and specs

| Deliverable | Spec | Roadmap row |
|---|---|---|
| Server container image (Podman / OCI), standalone + cluster | [features/packaging-podman-server.md](../features/packaging-podman-server.md) | Server Container Image |
| Native client installers (deb / rpm / pkg / msi for GUI + CLI) | [features/packaging-client-binaries.md](../features/packaging-client-binaries.md) | Native Client Installers |
| Client distribution website (OCI image, signed manifest + downloads) | [features/packaging-distribution-website.md](../features/packaging-distribution-website.md) | Client Distribution Website |

## Sequencing

The three deliverables share the same release pipeline (one tag → many
artefacts → one signed manifest → one set of consumers), so they ship in
phased waves rather than three independent timelines. Each wave is one
release.

### Wave 1 — Server image, standalone — **shipped**

- Server image Phase 1 (standalone, amd64, unsigned). **Done.** See
  [`deploy/container/`](../deploy/container/) and the
  [`container-image` workflow](../.github/workflows/container-image.yml).
- No client installers yet.
- No downloads website yet.

Operators can pull a working server container and run a single-node
deployment.

### Wave 2 — Server cluster + first Linux client installers — **shipped (with one caveat)**

- Server image Phase 2 (cluster mode, 3-node compose reference). **Done.**
  See [`deploy/compose/cluster.yml`](../deploy/compose/cluster.yml) and
  the per-node configs in [`deploy/compose/cluster/`](../deploy/compose/cluster/).
- Server image Phase 3 (multi-arch + Cosign + SBOM). **Done.**
  Extended [`container-image.yml`](../.github/workflows/container-image.yml)
  to build `linux/amd64` + `linux/arm64`, Cosign keyless sign, and
  attach a CycloneDX SBOM. New `:debug` variant lives at
  [`deploy/container/Containerfile.debug`](../deploy/container/Containerfile.debug).
- Client installers Phase 1 — CLI (Linux deb + rpm, amd64). **Done.**
  cargo-deb / cargo-generate-rpm metadata in `Cargo.toml`; static
  manpage + completions in [`installers/cli/`](../installers/cli/);
  `make linux-cli-packages` builds both.
- Client installers Phase 1 — GUI (Linux deb + rpm, amd64). **Skeleton.**
  Postinst/prerm scripts in
  [`gui/src-tauri/installers/linux/`](../gui/src-tauri/installers/linux/);
  the `tauri.conf.json` wiring is deferred until a real `tauri build`
  pass on a Linux host validates the asset paths.

Server is now signed and HA-deployable. End users on Linux can install
the CLI from native packages today; the GUI side completes once a
Linux build host runs the bundler against the staged scripts.

### Wave 3 — macOS + Windows client installers + downloads website — **part-shipped**

- Client installers Phase 2 (macOS .pkg, GUI + CLI, x86_64 + arm64 +
  universal2 GUI). **CLI half done** — `make macos-cli-pkg` (pkgbuild +
  productbuild). GUI `.pkg` wired to Tauri's bundler via `make gui-macos-pkg`.
- Client installers Phase 3 (Windows .msi, GUI + CLI, x64 + arm64).
  **CLI half done** — `make windows-cli-packages` builds the `.msi` and
  `.nupkg` off-Windows: `cross` → `x86_64-pc-windows-gnu` in Docker, `wixl`
  for the msi, `build-nupkg.py` for the nupkg. GUI `.msi` builds in a
  disposable ARM64 Win11 VM via Tart (`make gui-windows-msi`).
- Client installers Phase 4 (Cosign signing on every artefact +
  `manifest.json` published to the GitHub release). **Local step done,
  publishing BLOCKED.** `make sign-packages` signs everything from
  env-supplied keys (GPG deb/rpm, Authenticode msi via `osslsigncode`,
  Developer ID + notarise pkg, Cosign, SHA256SUMS). What remains is a CI
  matrix, real release keys and the `manifest.json` publish. The EV
  Authenticode custody question that used to gate this was answered on
  2026-08-26 — hardware token, Authenticode optional and never a build gate
  (§ Decisions) — which leaves one concrete engineering task: a PKCS#11 branch
  in `sign_authenticode()`, since an EV key cannot exist as a file.
- Downloads website Phase 1 (the static-server binary). **Done.**
  `cmd/bv-downloads-server/` — `manifest.rs` / `render.rs` / `serve.rs`, 39
  tests, acceptance run against `cmd/bv-downloads-server/fixtures/v0.4.0/`.
- Downloads website Phase 2 (containerised, amd64). **Done.**
  [`deploy/downloads/Containerfile`](../deploy/downloads/Containerfile),
  [`deploy/downloads/README.md`](../deploy/downloads/README.md),
  `.github/workflows/downloads-image.yml.disabled` (build + push on tag,
  **unsigned** — signing is Phase 3), and
  `make downloads-image{,-run,-test}` over
  [`deploy/downloads/test/smoke.sh`](../deploy/downloads/test/smoke.sh).

Every supported platform now has a CLI installer, and the operator can host
the downloads container internally and point users at it instead of at
GitHub. The wave closes when a tagged release actually produces signed
artefacts and a published `manifest.json` — i.e. when the signing CI is
unblocked.

### Wave 4 — Polish + repos + GUI hookup

- Server image Phase 4 (Helm chart for Kubernetes deploys).
- Downloads website Phase 3 (multi-arch + signing + SBOM + optional TLS).
- Downloads website Phase 4 (GUI in-app "update available" banner using
  the manifest endpoint).
- Client installers Phase 5 — *stretch* (apt + dnf repos for
  subscribe-once installs).

Wave 4 closes out the initiative. Apt / dnf repos may slip to a
follow-up release if EV Authenticode procurement lags or if signing-key
custody decisions require their own review.

## Cross-cutting decisions, made up-front

- **Distroless base for both server and downloads images.** Same CVE
  cadence, same nonroot UID, same hardening posture across the two
  containers we ship.
- **Cosign keyless signing via GitHub OIDC** for every container image
  and every client artefact. SLSA v1 provenance attestation on the
  server image; CycloneDX SBOMs attached as Cosign attestations.
- **Native + Cosign** for client installers. Authenticode on Windows,
  notarised pkg on macOS, GPG-signed deb / rpm on Linux, Cosign
  alongside everywhere. Operators and users verify both.
- **No auto-update of installed clients.** The GUI surfaces a banner;
  the user re-runs the installer. Silent self-replacement of a
  secrets-manager client is too easy to weaponise.
- **No auto-init / auto-unseal in the server image.** Operators run
  `bvault operator init` and `operator unseal` themselves, the same as
  on bare metal.
- **One manifest format**, defined by
  [features/packaging-distribution-website.md](../features/packaging-distribution-website.md),
  is what every consumer (downloads website, GUI update banner, future
  CLI `bvault upgrade --check` if we ever ship one) reads. We resist the
  urge to grow a second.
- **The release pipeline is one workflow that emits all artefacts for a
  tag.** Splitting it across multiple workflows turns "did this release
  ship cleanly?" into a multi-tab investigation; one workflow with a
  matrix and a single publish job keeps the answer to one URL.

## What is shipped vs. still to do

**Shipped (Waves 1 + 2):**

- `deploy/container/Containerfile` — distroless, nonroot server build.
  As of the FIDO2 RP migration the builder stage no longer needs
  `libssl-dev` / `OPENSSL_STATIC` — server crate is openssl-free.
- `deploy/container/Containerfile.debug` — `:debug` variant on
  `debug-nonroot` with `ss` / `ip` / `tcpdump` / `curl` for incident
  response.
- `deploy/container/config/config.hcl.sample` and `deploy/container/README.md`.
- `deploy/compose/standalone.yml` — single-node reference compose.
- `deploy/compose/cluster.yml` + `deploy/compose/cluster/{node1,node2,node3}.hcl`
  + `deploy/compose/cluster/README.md` — 3-node Hiqlite Raft reference.
- `.github/workflows/container-image.yml` — GHCR build, multi-arch
  (`linux/amd64` + `linux/arm64`), Cosign keyless signing on the
  manifest digest, CycloneDX SBOM via `syft` attached as a Cosign
  attestation. Both production and `:debug` variants per tag.
- `.dockerignore`.
- `Cargo.toml` `[package.metadata.deb]` + `[package.metadata.generate-rpm]`
  for the `bvault` CLI; `installers/cli/` static manpage + completions;
  `make linux-cli-packages`.
- `gui/src-tauri/installers/linux/{postinst,prerm}` — bundler scriptlet
  inputs for the GUI deb/rpm (skeleton; needs a real Tauri build host
  pass to wire into `tauri.conf.json`).

**Shipped (Wave 3, so far):**

- macOS `.pkg` for the CLI — `make macos-cli-pkg` (pkgbuild + productbuild);
  `make macos-client-install` installs both macOS halves on the host.
- Windows `.msi` + `.nupkg` for the CLI — `make windows-cli-packages`, which
  cross-builds `x86_64-pc-windows-gnu` in Docker via `cross` and packages with
  `wixl` + `build-nupkg.py`, so no Windows host is needed.
  `make cli-packages-all` builds the whole four-platform CLI set from a Mac.
- GUI installers wired to Tauri's bundler — `make gui-linux-packages`
  (emulated amd64 Docker container), `make gui-windows-msi` (disposable ARM64
  Win11 VM via Tart, cross-compiling to x64), `make gui-macos-pkg`.
- Key-agnostic local signing — `make sign-packages`: GPG deb/rpm, Authenticode
  msi via `osslsigncode`, Developer ID + notarised pkg, optional NuGet, plus
  Cosign and a `SHA256SUMS` over every artifact, all from env-supplied keys.
- The downloads site, Phases 1 + 2 — `cmd/bv-downloads-server/` (the binary,
  its fixtures and 39 tests), `deploy/downloads/{Containerfile,README.md}`,
  `deploy/downloads/static/`, `deploy/downloads/test/smoke.sh`,
  `.github/workflows/downloads-image.yml.disabled`, and the
  `make downloads-image{,-run,-test}` targets. Unsigned, amd64, no TLS —
  all three are Phase 3.

**Still to do:**

- **Release-signing CI + real keys + `manifest.json` publish** (Wave 3 /
  installers Phase 4). The local signing step is done; what is missing is the
  workflow that runs it on a tag with production keys and publishes the
  manifest this site consumes. No longer blocked on custody — § Decisions
  settles that — but it needs the PKCS#11 branch in `sign_authenticode()`, and
  it must treat an unsigned Windows artefact as a supported outcome rather
  than a failure.
- Downloads website Phase 3 — `linux/arm64`, Cosign keyless signing, the
  CycloneDX SBOM attestation, and the `BV_DOWNLOADS_TLS_*` Rustls path
  (Wave 4).
- Downloads website Phase 4 — the GUI in-app "update available" banner
  (Wave 4).
- Trusted-proxy / PROXY-protocol client-IP propagation (Wave 2 / Phase 1.5).
- Helm chart for Kubernetes deploys (Wave 4 / server image Phase 4).
- A real `tauri build` pass on a Linux host to validate the GUI deb/rpm
  scriptlet paths end to end.
- apt / dnf repo hosting (Wave 4 stretch).

**Note on the workflows.** Every image workflow in this repository carries a
`.disabled` suffix (commit 8ba5d8c) — the definitions are in version control
but GitHub Actions does not dispatch them, and the integration CI that runs
today lives in the internal `esi/bv-build` repository. That applies to
`container-image.yml.disabled` and to the new
`downloads-image.yml.disabled` alike; the links elsewhere in this file to
`.github/workflows/container-image.yml` predate the rename.

The three feature specs each have a "Current State" section spelling
out what does and does not exist; this roadmap closes when all three
of those sections read **Done**.

## Decisions

- **Where does the EV Authenticode certificate live? — hardware token,
  and Authenticode signing is optional.** *Decided 2026-08-26.* The EV
  key lives on a FIPS 140-2 Level 2 hardware token held by a release
  manager, not in a cloud HSM. Custody stays entirely with us, which is
  the defensible position for a secrets-management product: no third
  party ever holds a capability to sign as BastionVault, and the audit
  trail is ours rather than a vendor's.

  The cost of that choice is that a token cannot sign unattended, so
  **Authenticode signing must not be a hard gate on any build or
  release.** It is an opt-in step, exactly as
  [`installers/sign/sign-artifacts.sh`](../installers/sign/sign-artifacts.sh)
  already behaves — absent `BV_WIN_*` key material it *skips* the
  artefact and continues rather than failing. That skip is now a
  decided property, not an accident of the script: unsigned Windows
  artefacts are a supported release outcome, and CI must be able to
  produce a complete release without a human present.

  This does not leave Windows artefacts unattested. Cosign keyless
  signing and `SHA256SUMS` run fine unattended, so every artefact still
  carries a verifiable provenance signature in CI; Authenticode is the
  additional layer that suppresses the SmartScreen interstitial, and it
  is applied out-of-band by the release manager when the token is
  available.

  **Engineering consequence, not yet implemented:** an EV key cannot
  exist as a file, so neither of `sign_authenticode()`'s current key
  paths (`-pkcs12 $BV_WIN_PFX`, or `-certs`/`-key`) can drive it. A
  third branch is needed using `osslsigncode`'s PKCS#11 support
  (`-pkcs11engine` / `-pkcs11module` / `-pkcs11cert`). Tracked as part
  of Wave 3 / Client installers Phase 4.

## Open questions tracked here, not in the specs

- **Do we ship Linux arm64 installers in Wave 2 or hold them for Wave
  3?** The cross-build is straightforward; the question is whether we
  test arm64 desktops in Wave 2 CI. Default plan: arm64 lands in Wave 3
  alongside macOS arm64 to amortise the test infrastructure.
- **apt / dnf repo hosting**: same reverse-proxy + static-volume shape
  as the downloads container, or a separately-operated CDN? Default
  plan: same shape as the downloads container so operators only need
  to learn one pattern.

These are open by design — they are infrastructure / cost / opex
decisions, not engineering ones, and will be answered before the wave
that needs the answer. Answered ones move up to § Decisions.

## Tracking

Update this file when each wave closes. Update the global
[roadmap.md](../roadmap.md) Packaging & Distribution rows when a row
flips from `Todo` to `In Progress` (entering Wave 1 / 2 / 3) or to
`Done` (exiting Wave 4). Each individual phase landing also updates
[CHANGELOG.md](../CHANGELOG.md) under `[Unreleased]`.
