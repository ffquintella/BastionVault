# BastionVault client downloads image

A small OCI image that serves your BastionVault client installers — the
desktop GUI and the `bvault` CLI — from inside your own network, with the
SHA-256 and Cosign signature shown next to every download.

Most BastionVault deployments are private, and desktop machines in them
cannot reach `github.com` to fetch an installer. Run this container next to
the server, drop your signed artefacts into a directory, mount it read-only,
and point your users at it.

- Spec: [`features/packaging-distribution-website.md`](../../features/packaging-distribution-website.md)
- Roadmap: [`roadmaps/packaging-and-distribution.md`](../../roadmaps/packaging-and-distribution.md)
- Server image (a different container): [`deploy/container/README.md`](../container/README.md)

## Status

**Phase 2 — `linux/amd64`, unsigned.** The image is not yet Cosign-signed and
carries no SBOM attestation, and it does not terminate TLS. Those are
Phase 3, together with `linux/arm64`. Until then, put it behind the reverse
proxy you already run and verify the *artefacts* rather than the image.

## Quick start

```bash
podman run -d --name bv-downloads \
  -p 8080:8080 \
  -v ./client-artifacts:/srv/bv-downloads:ro,Z \
  ghcr.io/ffquintella/bastionvault-downloads:vX.Y.Z
```

That is the whole interface. No config file, no database, no login.

## Directory layout

The mounted directory is the server's `--root`. Its shape is fixed:

```
/srv/bv-downloads/
├── manifest.json                          # the only source of truth
└── v0.4.0/
    ├── bastionvault-gui_0.4.0_amd64.deb
    ├── bastionvault-gui_0.4.0_amd64.deb.sig
    ├── bastionvault-gui_0.4.0_amd64.deb.pem
    ├── bvault_0.4.0_amd64.deb
    └── …
```

`manifest.json` decides what exists. A file on disk that the manifest does
not name is **not served** and does not appear on the page — the container
logs a warning about it at startup and otherwise ignores it. A file the
manifest names but that is not on disk is a **startup failure**, with one log
line naming the file.

### `manifest.json`

```json
{
  "version": "0.4.0",
  "released": "2026-06-01",
  "server_image": "ghcr.io/ffquintella/bastionvault:v0.4.0",
  "files": [
    {
      "platform": "linux",
      "arch": "amd64",
      "kind": "cli-deb",
      "name": "bvault_0.4.0_amd64.deb",
      "size": 4123456,
      "sha256": "e9147c…",
      "cosign_signature": "v0.4.0/bvault_0.4.0_amd64.deb.sig",
      "cosign_certificate": "v0.4.0/bvault_0.4.0_amd64.deb.pem"
    }
  ]
}
```

| Field | Required | Notes |
|---|---|---|
| `version` | yes | Without the leading `v`. The artefacts live in `v<version>/`. |
| `released` | yes | Free-form; rendered verbatim. |
| `server_image` | no | Shown on the page if present. |
| `files[].platform` | yes | `linux` \| `macos` \| `windows` |
| `files[].arch` | yes | `amd64` \| `arm64` \| `x86_64` \| `aarch64` |
| `files[].kind` | yes | `gui-deb` \| `gui-rpm` \| `gui-pkg` \| `gui-msi` \| `cli-deb` \| `cli-rpm` \| `cli-pkg` \| `cli-msi` |
| `files[].name` | yes | Bare file name, resolved under `v<version>/`. |
| `files[].size` | yes | Bytes. A mismatch against disk is a startup warning. |
| `files[].sha256` | yes | 64 lowercase hex characters. |
| `files[].cosign_signature` | no | Root-relative path. |
| `files[].cosign_certificate` | no | Root-relative path. |

`platform`, `arch` and `kind` are **closed sets**. An unrecognised value is a
one-line startup error naming the bad value and listing the accepted ones —
the container does not guess and does not skip the entry.

File names are restricted to `A-Z a-z 0-9 . _ + -`. That is what lets the
server match a request path against its allow-list byte-for-byte without
percent-decoding, which is in turn what makes path traversal structurally
impossible rather than filtered-out.

## Routes

| Path | Response |
|---|---|
| `/` | The generated landing page (`text/html`). |
| `/manifest.json` | Your `manifest.json`, byte for byte (`application/json`). |
| `/v<version>/<file>` | The artefact, with the MIME its `kind` pins. |
| `/v<version>/<file>.sig` | The Cosign signature (`application/octet-stream`). |
| `/v<version>/<file>.pem` | The Cosign certificate (`application/x-pem-file`). |
| `/healthz` | `200 ok` (`text/plain`). |

**Everything else is `404`**, including directory paths, `/index.html`,
`/static/*`, and any path with `..` or percent-encoded segments in it. There
is no directory listing, and every response carries
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

`/manifest.json` is the endpoint the GUI's "update available" banner will
poll (spec Phase 4). It is served as the operator's own bytes rather than a
re-serialisation, so a detached signature over the manifest still verifies.

## Adding a release

1. Copy the new `vX.Y.Z/` directory and its `.sig` / `.pem` files into the
   mounted volume.
2. Update `manifest.json`.
3. **Restart the container.** The page is rendered once at startup and served
   as a static string thereafter — there is no template evaluation on the
   request path — so a new version needs `podman restart bv-downloads`.

## Configuration

Every flag has an environment-variable equivalent, so you can configure the
container without overriding its entrypoint.

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--root` | `BV_DOWNLOADS_ROOT` | `/srv/bv-downloads` | The mounted artefact directory. |
| `--addr` | `BV_DOWNLOADS_ADDR` | `0.0.0.0:8080` | Listen address. |
| `--static-dir` | `BV_DOWNLOADS_STATIC` | *(built in)* | Override the branding. |
| `--verify-hashes` | `BV_DOWNLOADS_VERIFY_HASHES` | off | Re-hash every artefact at startup; refuse to start on a mismatch. |
| `--render-only` | — | off | Print the page to stdout and exit. Useful in CI. |

`--verify-hashes` reads every artefact once at startup, so on a large release
directory it trades a few seconds of start time for the guarantee that the
hashes on the page describe the bytes being served. Worth it on a release
host; skip it if start latency matters more.

### Branding

`style.css` and `logo.svg` are compiled into the binary, so the page renders
with nothing mounted. `/usr/share/bv-downloads/static/` in the image holds the
same two files as an editable reference:

```bash
# copy the reference assets out of the image
id=$(podman create ghcr.io/ffquintella/bastionvault-downloads:vX.Y.Z)
podman cp "$id:/usr/share/bv-downloads/static" ./my-branding
podman rm "$id"

# edit ./my-branding/style.css and ./my-branding/logo.svg, then mount them back
podman run -d --name bv-downloads \
  -p 8080:8080 \
  -v ./client-artifacts:/srv/bv-downloads:ro,Z \
  -v ./my-branding:/etc/bv-downloads/static:ro,Z \
  -e BV_DOWNLOADS_STATIC=/etc/bv-downloads/static \
  ghcr.io/ffquintella/bastionvault-downloads:vX.Y.Z
```

A `BV_DOWNLOADS_STATIC` that does not contain both files is a startup error,
not a silent fall back to the built-in branding.

Both files are inlined into the page and pinned by a `sha256-` source
expression in its Content-Security-Policy, which is recomputed at startup —
so your CSS works without weakening the policy.

## TLS

**Not implemented yet (Phase 3.)** Terminate TLS at the reverse proxy,
ingress controller or load balancer you already run.

Setting `BV_DOWNLOADS_TLS_CERT` or `BV_DOWNLOADS_TLS_KEY` today is a hard
startup error rather than a silently ignored variable. When Phase 3 lands the
contract will be:

- both set → serve HTTPS on `:8443` with the project's Rustls stack
- neither set → serve HTTP on `:8080`
- exactly one set → refuse to start

An operator who believes they configured HTTPS and got plaintext is the
failure this refusal exists to prevent, so the behaviour is the same before
and after the feature exists: never plaintext on a port you asked to be TLS.

## Hardening

- **No write path.** No upload, no admin panel, no API. `POST` / `PUT` /
  `DELETE` / `PATCH` reach one handler, which only ever opens files for
  reading, and answer `404`.
- **Mount the volume read-only** (`:ro`). It is the documented and tested
  configuration; the server never opens it for writing.
- **Runs as UID 65532** (`nonroot`), on a Wolfi base with busybox and `apk`
  removed. There is no shell in the image — `podman exec` will not give you
  one. Rebuild with `--build-arg INCLUDE_SHELL=1` if you need one to debug.
- **No outbound connections.** No CA bundle is installed, nothing is fetched,
  nothing phones home, and there is no analytics script. It runs unchanged in
  an air-gapped network.
- **Symlinks are refused.** A manifest entry that resolves to a symlink, or to
  anything outside the mounted root, fails at startup; a symlink swapped in
  afterwards makes that path `404` rather than being followed.
- **No `HEALTHCHECK` in the image**, because there is no shell to run one.
  Probe `GET /healthz` from your orchestrator instead.

Verification is the user's job, deliberately: the page shows the SHA-256 and
links the signature, and tells the user how to check both. A site that
verified on the user's behalf would just move the trust point to the site.

## Building locally

```bash
make downloads-image                      # linux/amd64 by default
make downloads-image PLATFORM=linux/arm64
make downloads-image-run                  # serve the checked-in fixtures on :8080
make downloads-image-test                 # build, run, curl every route, tear down
```

Or directly:

```bash
podman build -f deploy/downloads/Containerfile -t bastionvault-downloads:dev .
podman run --rm -p 8080:8080 \
  -v ./cmd/bv-downloads-server/fixtures/v0.4.0:/srv/bv-downloads:ro,Z \
  bastionvault-downloads:dev --verify-hashes
```

The build context is the repository root. The builder stage runs on the build
host's architecture and cross-compiles, so an amd64 image builds at native
speed on an Apple Silicon Mac.

## Running the binary without a container

The image is a convenience, not a requirement:

```bash
cargo build --release -p bv-downloads-server
./target/release/bv-downloads-server --root /srv/bv-downloads --addr 0.0.0.0:8080
```

The binary has no runtime dependencies beyond glibc and needs no files beside
it.
