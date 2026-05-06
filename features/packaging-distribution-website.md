# Feature: Client Distribution Website (Container Image)

## Summary

Ship a self-contained **OCI container image** that runs a small static
website serving signed client binaries — the BastionVault GUI installers
and the `bvault` CLI — for every supported platform. Operators host this
container inside their network; their users browse to it, pick the
installer for their OS, download it, and verify it against the signature
shown next to the download.

The image is the second half of the project's distribution story:

- [features/packaging-podman-server.md](packaging-podman-server.md) packages
  the **server** for operators.
- [features/packaging-client-binaries.md](packaging-client-binaries.md)
  produces the **client artefacts** (deb, rpm, pkg, msi).
- This feature **distributes those client artefacts** to end users in
  air-gapped or self-hosted environments where the public GitHub Releases
  page is not reachable.

The container is the canonical answer to "how do my users get the GUI?"
when an operator runs BastionVault on an internal network. It is **not**
a replacement for the public release artefacts; the same files served by
this container are also published on GitHub Releases.

## Motivation

- **Most BastionVault deployments are private.** Customers running a
  secrets manager rarely allow desktop machines to reach `github.com` to
  download installers. They need a way to host the installers themselves
  next to the server.
- **A static site behind nginx is the right shape**, not a bespoke admin
  panel. The site is read-only, anonymous (no login), and serves
  immutable signed files. Anything more would be re-implementing a
  package server we don't need.
- **Bundling it as a container image** matches how the server ships
  ([features/packaging-podman-server.md](packaging-podman-server.md)) and
  removes the operator's chore of writing nginx config, managing TLS, and
  templating per-version download lists.
- **Signed and verifiable downloads are non-negotiable** for a security
  product. The site presents the SHA-256 hash and the Cosign signature
  next to every file; the file itself carries the platform-native
  signature (Authenticode for MSI, notarised pkg, signed deb / rpm).

## Current State

- **No distribution site exists.** No container image, no static-site
  generator, no template, no Cosign-signature surfacing.
- The client binaries themselves are produced by the sibling spec
  ([features/packaging-client-binaries.md](packaging-client-binaries.md))
  and do not yet exist as official artefacts either; the two features
  ship together.
- The Packaging & Distribution row in [roadmap.md](../roadmap.md) currently
  reads `Todo`.

## Design

### What the operator sees

```
podman run -d --name bv-downloads \
  -p 8080:8080 \
  -v ./client-artifacts:/srv/bv-downloads:ro,Z \
  ghcr.io/ffquintella/bastionvault-downloads:vX.Y.Z
```

That's the entire interface. The operator drops a directory of signed
client artefacts into a host volume, mounts it read-only, and the
container serves a clean, branded download page over HTTP (or HTTPS if
the operator mounts a cert).

The directory layout the container expects is fixed and minimal:

```
/srv/bv-downloads/
├── manifest.json                # Version, file list, hashes, signatures
└── vX.Y.Z/
    ├── bastionvault-gui_X.Y.Z_amd64.deb
    ├── bastionvault-gui-X.Y.Z-1.x86_64.rpm
    ├── BastionVault-X.Y.Z-arm64.pkg
    ├── BastionVault-X.Y.Z-x64.msi
    ├── bvault_X.Y.Z_amd64.deb
    ├── bvault-X.Y.Z-1.x86_64.rpm
    ├── bvault-X.Y.Z-darwin-arm64.pkg
    ├── bvault-X.Y.Z-windows-x64.msi
    └── *.sig                    # Cosign signatures, one per file
```

The container has **no** business logic that runs at request time beyond
serving these files: no upload, no admin panel, no API, no per-user
state. The static index page is generated **at container start** from
`manifest.json`, then served as plain HTML; there is no server-side
rendering on the request path.

### What the user sees

A single landing page styled with the BastionVault brand and laid out as:

```
┌────────────────────────────────────────────────────┐
│ BastionVault Client Downloads                      │
│ Version vX.Y.Z (released YYYY-MM-DD)               │
├────────────────────────────────────────────────────┤
│  [Linux] [macOS] [Windows]                         │
│                                                    │
│  Linux                                             │
│   • Debian / Ubuntu (amd64) — GUI .deb  [hash]    │
│   • Debian / Ubuntu (amd64) — CLI .deb  [hash]    │
│   • RHEL / Fedora (x86_64) — GUI .rpm   [hash]    │
│   • RHEL / Fedora (x86_64) — CLI .rpm   [hash]    │
│                                                    │
│  How to verify a download:                         │
│    sha256sum bastionvault-gui_X.Y.Z_amd64.deb     │
│    cosign verify-blob --signature …                │
│                                                    │
│  Server image:                                     │
│    ghcr.io/ffquintella/bastionvault:vX.Y.Z         │
└────────────────────────────────────────────────────┘
```

The page is single-file static HTML; no JavaScript framework. A trivial
amount of vanilla JS detects the user agent on first load and highlights
the matching platform tab — but the full file list works without JS.

### Container layout

Two-stage build, same shape as
[features/packaging-podman-server.md](packaging-podman-server.md):

```
┌──────────── Stage 1: builder ────────────┐
│ FROM docker.io/library/rust:<pin>-slim    │
│  - cargo build --release --bin bv-downloads-server │
│    (small Rust binary that:                │
│     1. parses manifest.json,               │
│     2. renders index.html via askama,      │
│     3. serves /srv/bv-downloads/* via axum)│
└──────────────────────────────────────────┘
                  │ COPY --from=builder
                  ▼
┌──────────── Stage 2: runtime ────────────┐
│ FROM gcr.io/distroless/cc-debian12:nonroot│
│  - /usr/local/bin/bv-downloads-server     │
│  - /usr/share/bv-downloads/static/        │
│    (CSS, fonts, brand assets — small)     │
│  - USER 65532:65532                       │
│  - EXPOSE 8080                            │
│  - ENTRYPOINT ["/usr/local/bin/           │
│         bv-downloads-server"]             │
└──────────────────────────────────────────┘
```

Why a Rust server instead of plain nginx serving a static directory:

- We render the index from `manifest.json` so the operator never has to
  hand-edit HTML when they add a new version. Doing this with nginx +
  envsubst + a templated mountpoint is more brittle than a 200-line
  Rust binary.
- The same binary serves the manifest as JSON at
  `/manifest.json`, which the GUI's "check for updates" logic
  ([features/packaging-client-binaries.md](packaging-client-binaries.md)
  Phase 4) can poll without scraping HTML.
- We can enforce **no directory listing of unrelated paths**, **no
  symlink traversal**, and **strict MIME types** in code, audit them in
  one file, and not depend on an upstream nginx config matrix.

The Rust binary uses `axum` + `tower-http`'s `ServeDir` with explicit
MIME overrides (`application/vnd.debian.binary-package`,
`application/x-rpm`, `application/x-newton-compatible-pkg`,
`application/x-msi`) and a single index handler. It exposes:

| Path | Behaviour |
|---|---|
| `/` | Generated landing page (`text/html`). |
| `/manifest.json` | The mounted `manifest.json` (`application/json`). |
| `/vX.Y.Z/<file>` | The file from the mounted directory, with the right MIME. |
| `/vX.Y.Z/<file>.sig` | The Cosign signature next to the file. |
| `/healthz` | `200 OK` with body `ok`. |

Anything outside that set returns `404`.

### `manifest.json` shape

```json
{
  "version": "0.4.0",
  "released": "2026-06-01",
  "server_image": "ghcr.io/ffquintella/bastionvault:v0.4.0",
  "files": [
    {
      "platform": "linux",
      "arch": "amd64",
      "kind": "gui-deb",
      "name": "bastionvault-gui_0.4.0_amd64.deb",
      "size": 41234567,
      "sha256": "abc…",
      "cosign_signature": "vX.Y.Z/bastionvault-gui_0.4.0_amd64.deb.sig",
      "cosign_certificate": "vX.Y.Z/bastionvault-gui_0.4.0_amd64.deb.pem"
    }
  ]
}
```

`platform`, `arch`, and `kind` are closed enums:

- `platform`: `linux`, `macos`, `windows`
- `arch`: `amd64`, `arm64`, `x86_64`, `aarch64` (we accept both common
  spellings — the index page presents one)
- `kind`: `gui-deb`, `gui-rpm`, `gui-pkg`, `gui-msi`, `cli-deb`,
  `cli-rpm`, `cli-pkg`, `cli-msi`

The container refuses to start with a malformed manifest. It does **not**
guess: if a file is listed in the manifest but missing from disk, the
container fails fast at start with an explicit error naming the missing
file. Same the other way around — a file present on disk but missing
from the manifest is logged as a warning and not surfaced on the
landing page.

### TLS

The container does **not** terminate TLS itself by default; the operator
is expected to put it behind their existing reverse proxy (Traefik,
Caddy, nginx, an ingress controller). For deployments without one, the
container accepts an optional pair of mounted files:

```
podman run -d \
  -e BV_DOWNLOADS_TLS_CERT=/etc/tls/cert.pem \
  -e BV_DOWNLOADS_TLS_KEY=/etc/tls/key.pem \
  -v ./tls:/etc/tls:ro,Z \
  -p 8443:8443 \
  ghcr.io/ffquintella/bastionvault-downloads:vX.Y.Z
```

When both env vars are set the binary serves on `:8443` with the
project's standard Rustls config (PQ-friendly hybrid suites included);
when neither is set it serves on `:8080` plain HTTP. Setting only one is
a startup error.

### Tags, signing, SBOM

Same approach as the server image
([features/packaging-podman-server.md](packaging-podman-server.md)
Phase 3):

- Multi-arch `linux/amd64` + `linux/arm64`.
- Cosign keyless signed via the GitHub OIDC issuer.
- CycloneDX SBOM attached as a Cosign attestation.
- Tags: `vX.Y.Z`, `vX.Y`, `vX`, `latest`.

### Module Architecture

```
deploy/downloads/
├── Containerfile
├── README.md
└── static/
    ├── style.css
    ├── logo.svg
    └── (small set of brand assets)

cmd/bv-downloads-server/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── manifest.rs            # parse/validate manifest.json
    ├── render.rs              # askama templates → static index.html
    └── serve.rs               # axum routes (index, manifest, files, healthz)

.github/workflows/
└── downloads-image.yml        # Build + sign + SBOM + push on tag
```

## Implementation Scope

### Phase 1 — Static Server Binary

| File | Purpose |
|---|---|
| `cmd/bv-downloads-server/*` | The Rust binary above. |
| `deploy/downloads/static/*` | Minimal CSS + brand assets. |
| `tests/downloads_server.rs` | Unit + integration tests for manifest parsing, MIME mapping, 404 behaviour. |

Acceptance: `cargo run -p bv-downloads-server -- --root ./fixtures/v0.4.0`
serves an index page that lists every fixture file with the correct
hash and signature link.

### Phase 2 — Container Image, amd64

| File | Purpose |
|---|---|
| `deploy/downloads/Containerfile` | Two-stage build for `linux/amd64`. |
| `deploy/downloads/README.md` | Operator docs: directory layout, mounted volumes, TLS env-var contract. |
| `.github/workflows/downloads-image.yml` | Build + push on tag. **Not yet signed.** |

Acceptance: `podman run` against a fixture directory of signed artefacts
produces a working browseable site; `curl /manifest.json` returns the
parsed manifest; `curl /vX.Y.Z/<file>` returns the file with the right
MIME.

### Phase 3 — Multi-Arch + Signing + SBOM + TLS

| File | Purpose |
|---|---|
| `.github/workflows/downloads-image.yml` (extension) | `buildx` for `linux/amd64` + `linux/arm64`; `cosign sign` keyless on the resulting digest; `syft` SBOM + `cosign attest`. |
| `cmd/bv-downloads-server/src/serve.rs` (extension) | `BV_DOWNLOADS_TLS_CERT` + `BV_DOWNLOADS_TLS_KEY` integration with Rustls. |
| `docs/docs/operations/downloads-image.md` | Operator-facing docs. |

Acceptance: same Cosign + SBOM verification path as the server image; a
manifest list resolves to two arch-specific manifests; TLS mode serves a
working HTTPS page when certs are mounted.

### Phase 4 — GUI Update Channel Hookup

| File | Purpose |
|---|---|
| `gui/src/lib/updateChannel.ts` (new) | Tiny client in the Tauri GUI that polls `<configured-base>/manifest.json` once per app start, compares the version against the running build, and surfaces a non-blocking "new version available" notice with a click-through to the download page. |
| `features/packaging-client-binaries.md` (cross-reference) | The downloaded artefact is the platform-native installer the user ran in the first place; the GUI does not auto-update — it only links out. |

Acceptance: a GUI built against a `0.4.0` server, pointed at a downloads
container hosting `0.4.1`, surfaces an in-app banner with a link.
Auto-download and auto-install are explicitly out of scope.

### Not In Scope

- **Authentication or per-user gating.** The site is read-only and
  anonymous. Operators wanting access control put the container behind
  their existing SSO-aware reverse proxy.
- **Upload, admin panel, version-management UI.** Adding a new version
  means dropping new files into the mounted directory and updating
  `manifest.json`. Anything more is the operator's CI.
- **Auto-update of installed clients.** The site links the user to a
  fresh installer; reinstall is an explicit user action. Silent
  background updates of a desktop-resident secrets-manager client are not
  a tradeoff we are willing to make.
- **Hosting the server container image itself.** The server image lives
  on a registry (GHCR), not on this static site. Mixing image
  distribution with binary distribution would force this container to
  re-implement a registry.
- **Non-OCI distribution.** No `.tar.gz` static-site export; if a
  customer wants something other than the container, they can use the
  standalone `bv-downloads-server` binary directly.

## Testing Requirements

### Unit Tests

- `manifest.rs`: well-formed manifest accepted; missing `version`
  rejected; closed-enum values outside the allowed set rejected; entries
  pointing at non-existent files rejected at startup.
- `render.rs`: index renders correctly across (`linux/macos/windows`) ×
  (`gui/cli`) × (`amd64/arm64`) sample manifests.
- `serve.rs`: `/healthz` returns 200; arbitrary paths return 404; symlink
  traversal attempts (`/../etc/passwd`) return 404 without filesystem
  access.

### Integration Tests

- `tests/downloads_server.rs`: spin the binary against a fixture root,
  exercise every documented endpoint, confirm hashes and signature
  paths in the rendered HTML match the fixture's `manifest.json`.
- **Container smoke**: `podman build && podman run` against the same
  fixture; `curl localhost:8080/` returns valid HTML; `curl
  localhost:8080/vX.Y.Z/<file>` returns the file with the right MIME.
- **TLS smoke** (Phase 3): same with `BV_DOWNLOADS_TLS_*` env vars set
  against a self-signed fixture cert; `curl --cacert …` works on `:8443`.
- **GUI hookup** (Phase 4): a Tauri test that mocks the manifest endpoint
  and asserts the in-app banner shows the right version and link.

### Cucumber BDD Scenarios

- Operator drops a new release directory + manifest entry into the
  mounted volume; the next user load of the page surfaces the new
  files. (No restart of the container required.)
- A user on Windows lands on the page; the Windows tab is
  pre-highlighted; the user clicks the MSI download; the Cosign
  signature path next to it is correct.
- Operator misconfigures the manifest (file listed but missing from
  disk); the container fails to start with a clear error naming the
  missing file.

### Negative Tests

- Symlink in the mounted volume pointing outside `/srv/bv-downloads`:
  request returns 404 and the file is not read.
- A request for a path with `..` segments: returns 404.
- A `manifest.json` with an unknown `kind`: container refuses to start
  with a clear single-line error.
- TLS env vars set with a missing cert file: refuses to start.

## Security Considerations

- **No write paths.** The container has no upload, no admin, no PUT, no
  POST. The operator cannot accidentally enable one with an env var.
- **Read-only mounted volume** is the documented and tested path. The
  container itself runs nonroot and has no capability to write back to
  the volume even if compromised.
- **Strict path handling**: requests are resolved through `tower-http`'s
  `ServeDir` with `follow_symlinks(false)`; explicit normalisation rejects
  `..`. The volume is only ever read; symlink traversal cannot escape.
- **Per-file integrity is on the user.** The page renders the SHA-256
  and Cosign signature path next to every download; the operator docs
  walk the user through `sha256sum` and `cosign verify-blob`. The site
  itself does not "verify on behalf of the user" because that just moves
  the trust point to the site.
- **No telemetry, no remote logging.** The container does not phone
  home, does not aggregate download counts beyond the operator's own
  reverse-proxy logs, does not embed analytics scripts. Operators in
  air-gapped environments can run it without an outbound allow-list.
- **No JavaScript framework.** The single inline JS block is for the
  cosmetic platform-tab highlight and works without it. There is nothing
  to XSS into; user input never reaches the page.
- **TLS uses the project's PQ-friendly Rustls stack** when enabled. No
  OpenSSL.
- **Image signing and SBOM are mandatory in the operator docs** — same
  as the server image. Unverified pulls are not advertised.
- **The auto-update banner in the GUI never auto-downloads.** It links
  out and the user re-runs the installer manually. A secrets-manager
  client that silently swaps its own binary is not a posture we ship.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md),
[roadmap.md](../roadmap.md) (Packaging & Distribution → Client
Distribution Website row: `Todo` → `In Progress` (Phase 1) → `Done`
(Phase 4)), and this file's "Current State" / phase markers.
