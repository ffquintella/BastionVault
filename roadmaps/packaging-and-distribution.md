# Roadmap: Packaging & Distribution

Status: **Active — Wave 1 / Phase 1 shipped (standalone server image, amd64, unsigned). Wave 1 / Phases 1.5–2 next.**

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

### Wave 2 — Server cluster + first Linux client installers

- Server image Phase 2 (cluster mode, 3-node compose reference).
- Server image Phase 3 (multi-arch + Cosign + SBOM).
- Client installers Phase 1 (Linux deb + rpm, GUI + CLI, amd64).

Server is now signed and HA-deployable. End users on Linux can install
the GUI and CLI from native packages, but those packages are still hand-
distributed by the operator.

### Wave 3 — macOS + Windows client installers + downloads website

- Client installers Phase 2 (macOS .pkg, GUI + CLI, x86_64 + arm64 +
  universal2 GUI).
- Client installers Phase 3 (Windows .msi, GUI + CLI, x64 + arm64).
- Client installers Phase 4 (Cosign signing on every artefact +
  `manifest.json` published to the GitHub release).
- Downloads website Phase 1 (the static-server binary).
- Downloads website Phase 2 (containerised, amd64).

Now every supported platform has an installer; the operator can host
the downloads container internally and point users at it instead of at
GitHub.

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

## What is **not** yet implemented

Everything. No `Containerfile`, no `cargo deb` config, no WiX project,
no notarisation script, no Cosign workflow, no downloads server crate,
no Helm chart, no apt / dnf repo, no Tauri-build CI matrix.

The three feature specs each have a "Current State" section spelling
out what does and does not exist; this roadmap closes when all three
of those sections read **Done**.

## Open questions tracked here, not in the specs

- **Where does the EV Authenticode certificate live?** Cloud HSM
  (AzureCS / DigiCert KeyLocker) versus a hardware token held by a
  release manager. Cloud HSM is faster to onboard but harder to audit;
  hardware token requires a person with the token to be on the release
  call. Decision needed before Wave 3.
- **Do we ship Linux arm64 installers in Wave 2 or hold them for Wave
  3?** The cross-build is straightforward; the question is whether we
  test arm64 desktops in Wave 2 CI. Default plan: arm64 lands in Wave 3
  alongside macOS arm64 to amortise the test infrastructure.
- **apt / dnf repo hosting**: same reverse-proxy + static-volume shape
  as the downloads container, or a separately-operated CDN? Default
  plan: same shape as the downloads container so operators only need
  to learn one pattern.

These three are open by design — they are infrastructure / cost / opex
decisions, not engineering ones, and will be answered before the wave
that needs the answer.

## Tracking

Update this file when each wave closes. Update the global
[roadmap.md](../roadmap.md) Packaging & Distribution rows when a row
flips from `Todo` to `In Progress` (entering Wave 1 / 2 / 3) or to
`Done` (exiting Wave 4). Each individual phase landing also updates
[CHANGELOG.md](../CHANGELOG.md) under `[Unreleased]`.
