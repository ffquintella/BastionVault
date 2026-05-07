# BastionVault Server — Container Image

Operator quickstart for the official BastionVault server OCI image.

This document covers **Wave 1, Phase 1** of the [Packaging &
Distribution](../../roadmaps/packaging-and-distribution.md) initiative:
standalone-mode, `linux/amd64`, **unsigned**. Cluster mode, multi-arch,
Cosign signing, SBOM attestation, and the Helm chart land in subsequent
waves. The full design is in
[features/packaging-podman-server.md](../../features/packaging-podman-server.md).

## Pulling

```sh
podman pull ghcr.io/ffquintella/bastionvault:vX.Y.Z
```

The image runs unmodified on Docker, containerd, and CRI-O. Podman is
the supported reference runtime; its rootless model and daemonless
architecture line up with the project's secure-by-default posture.

## What's in the image

| Path | Purpose |
|---|---|
| `/usr/local/bin/bvault` | The server + CLI binary. |
| `/usr/local/bin/bv-ssh-helper` | Helper used by the SSH secret engine. |
| `/etc/bvault/config.hcl` | Inert sample config — **must** be overridden. |
| `/var/lib/bvault/data` | Storage volume mount-point (Hiqlite SQLite + Raft logs by default). |
| `/etc/bvault/tls/` | TLS material mount-point (`server.crt`, `server.key`). |

The runtime is `gcr.io/distroless/cc-debian12:nonroot` — glibc and
ca-certificates and nothing else. There is no shell, no package
manager, no userspace network tools (`ss`, `ip`, `tcpdump`, `curl`).
Phase 3 will publish a `:debug` variant with those tools for incident
response. Until then, debug from outside the container.

The container runs as UID `65532:65532` (the distroless `nonroot` user).
Mounted volumes must be writable by that UID for `data/`; config and
TLS material are read-only.

## Running standalone

1. Write a real config (replace the placeholder secrets in
   [config/config.hcl.sample](config/config.hcl.sample) and fill in your
   own).
2. Generate a TLS keypair (or borrow one from your existing PKI).
3. Run:

```sh
podman run -d --name bastionvault \
  -p 8200:8200 \
  -v bv-data:/var/lib/bvault/data \
  -v ./config.hcl:/etc/bvault/config.hcl:ro,Z \
  -v ./tls:/etc/bvault/tls:ro,Z \
  ghcr.io/ffquintella/bastionvault:vX.Y.Z
```

A ready-made `podman compose` file lives at
[deploy/compose/standalone.yml](../compose/standalone.yml).

4. Initialise the vault. There is **no auto-init** — the operator runs
   it explicitly, exactly as on bare metal:

```sh
podman exec bastionvault bvault operator init
```

Save the unseal keys and root token from that command somewhere safe;
the container image cannot recover them for you.

5. Unseal:

```sh
podman exec bastionvault bvault operator unseal <key-1>
podman exec bastionvault bvault operator unseal <key-2>
podman exec bastionvault bvault operator unseal <key-3>
```

## Health checks

This image does **not** ship a `HEALTHCHECK` instruction in Phase 1.
Wire your orchestrator's readiness probe at the existing
`/v1/sys/health` HTTP endpoint instead:

| Probe | Endpoint | Healthy when |
|---|---|---|
| Readiness | `GET /v1/sys/health?standbyok=true` | Returns 200 (initialised + unsealed + active or standby). |
| Liveness | `GET /v1/sys/health?uninitcode=200&sealedcode=200` | Returns 200 even if sealed — the process is alive. |

A `bvault status`-based binary health check arrives in Phase 3 alongside
the `:debug` variant.

## What this image deliberately does not do

- **Auto-init or auto-unseal.** Both bury the most security-critical
  bootstrap moment behind container start, where it cannot be reviewed.
- **Run as root.** The image is hard-coded to UID 65532. Overriding
  with `--user 0` is not supported.
- **Template the config from environment variables.** Templating
  belongs in the operator's deployment tool (Helm, Compose, Ansible)
  where the resulting config can be audited; baking it into the image
  hides what's running.
- **Cluster mode.** Phase 1 is standalone only. Cluster mode (multi-node
  Hiqlite Raft) lands in Wave 2.
- **TLS termination off-the-shelf.** The sample config requires TLS
  material at `/etc/bvault/tls/`. There is no `tls_disable = true`
  shortcut in the bundled config.

## Building locally

```sh
podman build -f deploy/container/Containerfile -t bastionvault:dev .
```

The build context is the repository root. The build is currently
unoptimised (no cargo-chef, no layer caching) and takes 10–15 minutes
on a clean machine; Phase 3 will tighten this.

## Verifying the image

Image signing (Cosign keyless) and SBOM attestation arrive in Wave 2,
Phase 3. Until then, pin the digest yourself:

```sh
podman pull ghcr.io/ffquintella/bastionvault:vX.Y.Z
podman inspect ghcr.io/ffquintella/bastionvault:vX.Y.Z \
  --format '{{ index .RepoDigests 0 }}'
```

Reference that digest in your deployment so a tag rewrite cannot
substitute a different image under you.

## Cluster mode (3 nodes, Hiqlite Raft)

A reference 3-node cluster lives at
[`deploy/compose/cluster.yml`](../compose/cluster.yml) with per-node
HCL configs in [`deploy/compose/cluster/`](../compose/cluster/). The
image is the same as standalone mode — cluster-vs-standalone is decided
by the mounted `config.hcl`, not by an env-var or flag.

```sh
cd deploy/compose
podman compose -f cluster.yml up -d
podman compose -f cluster.yml logs -f bv-1 | grep -E "leader|raft"
```

After leader election, run `bvault operator init` against any node and
unseal each node individually (cluster nodes do not auto-share the
unseal state — that's a deliberate seal-per-node property). See
[`deploy/compose/cluster/README.md`](../compose/cluster/README.md) for
the full cookbook.

## Roadmap pointers

| Capability | Wave | Tracking |
|---|---|---|
| Cluster mode (Hiqlite multi-node) | 2 / Phase 2 | **Done** — [`deploy/compose/cluster.yml`](../compose/cluster.yml) |
| Trusted-proxy / PROXY-protocol client-IP propagation | 2 / Phase 1.5 | [features/packaging-podman-server.md](../../features/packaging-podman-server.md) — "Client IP visibility" |
| `linux/arm64` + Cosign signing + CycloneDX SBOM + `:debug` | 3 / Phase 3 | same spec |
| Helm chart for Kubernetes | 4 / Phase 4 | same spec |
