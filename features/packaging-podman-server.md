# Feature: Server Container Image (Podman / OCI)

## Summary

Ship an **official OCI container image for the BastionVault server** that an
operator can run unmodified in two shapes:

1. **Standalone** — single-process server with embedded Hiqlite, file
   storage, MySQL, or any other supported backend, suitable for development,
   small deployments, and air-gapped sites.
2. **Cluster** — N replicas joined into a Hiqlite Raft cluster, running
   inside the same image with a different start command and a peer-discovery
   configuration. Rolling upgrades, leader election, and snapshot transfer
   all work without rebuilding the image.

The image is built with **Podman / Buildah** (rootless-capable) but the
resulting OCI artefact runs unchanged on Docker, containerd, CRI-O,
Kubernetes (see [features/kubernetes-integration.md](kubernetes-integration.md)),
and Podman pods. There is **one image**, parameterised by environment
variables and a mounted config file — not separate `:standalone` and
`:cluster` tags. The cluster shape is selected at start time, not at build
time, so the same digest can be promoted from dev to staging to prod.

The image is the canonical server distribution channel alongside the
distro-native packages tracked in
[features/packaging-client-binaries.md](packaging-client-binaries.md). The
client-side counterpart (GUI + CLI binaries served from a static site) is
[features/packaging-distribution-website.md](packaging-distribution-website.md).

## Motivation

- **Operators expect a container today.** A secrets manager that ships only
  as `cargo install` and a `systemd` unit is not deployable on the
  platforms most BastionVault candidates already run (Kubernetes, Nomad,
  Podman-on-RHEL, OpenShift, Amazon ECS). The HashiCorp Vault image is the
  baseline; we have to clear it.
- **One image, many shapes** keeps the support surface small. The
  alternative — separate `bastionvault-standalone` and `bastionvault-ha`
  images — duplicates the build pipeline, the CVE patch cadence, and the
  signing infrastructure with no benefit, because the only difference is
  the entrypoint command and a few env vars.
- **Podman-first, not Docker-first.** Podman's rootless model and
  daemonless architecture line up with the project's secure-by-default
  posture (no privileged daemon owning every container's network and
  storage). The image works on Docker too, but the build and the operator
  documentation lead with Podman.
- **Reproducible, signed images** are the only credible distribution
  channel for a security product. The build pipeline produces a
  Cosign-signed image with a Sigstore-verifiable provenance attestation
  (SLSA level 3 target) so that operators can confirm the image came from
  the BastionVault release pipeline before running it.

## Current State

- **Phase 1 shipped.** Two-stage [`deploy/container/Containerfile`](../deploy/container/Containerfile)
  (rust:slim builder → `gcr.io/distroless/cc-debian12:nonroot` runtime),
  [inert sample config](../deploy/container/config/config.hcl.sample),
  [operator README](../deploy/container/README.md), [`podman compose` reference](../deploy/compose/standalone.yml),
  and a [`linux/amd64` GHCR push workflow](../.github/workflows/container-image.yml)
  triggered on `v*.*.*` tags. **Unsigned** and **standalone-only** in this phase;
  the `Partial` row in [roadmap.md](../roadmap.md) reflects this.
- The server binary itself is a single static-leaning Rust binary
  (`bvault`, [bin/bastion_vault.rs](../bin/bastion_vault.rs)) that compiles
  into the runtime image as-is. The Hiqlite cluster CLI and PQC TLS
  surface land below it as published features
  ([roadmaps/hiqlite-default-ha-storage.md](../roadmaps/hiqlite-default-ha-storage.md)).
- **Phases 1.5 (client-IP propagation), 2 (cluster mode + mode-resolver
  helper), 3 (`linux/arm64` + Cosign keyless + CycloneDX SBOM + `:debug`
  variant), and 4 (Helm chart)** are pending.

## Design

### Image layout

A two-stage build:

```
┌──────────── Stage 1: builder ────────────┐
│ FROM docker.io/library/rust:<pin>-slim    │
│  - apt: pkg-config, clang, cmake (for     │
│    optional sub-deps), git, libssl-dev    │
│  - ENV OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1│
│  - cargo build --release --bin bvault     │
│  - cargo build --release --bin bv-ssh-    │
│    helper                                 │
│  - ldd guard: fail if bvault dynamically  │
│    links libssl/libcrypto (distroless has │
│    neither)                               │
└──────────────────────────────────────────┘
                  │ COPY --from=builder
                  ▼
┌──────────── Stage 2: runtime ────────────┐
│ FROM gcr.io/distroless/cc-debian12:nonroot│
│  - /usr/local/bin/bvault                  │
│  - /usr/local/bin/bv-ssh-helper           │
│  - /etc/bvault/config.hcl (sample)  │
│  - USER 65532:65532 (nonroot, baked in)   │
│  - EXPOSE 8200 8201 (api, cluster)        │
│  - ENTRYPOINT ["/usr/local/bin/bvault"]   │
│  - CMD ["server", "-config",              │
│         "/etc/bvault/config.hcl"]   │
└──────────────────────────────────────────┘
```

Why distroless: the runtime contains glibc + ca-certificates and nothing
else. No shell, no package manager, no debug tools. The CVE surface is the
absolute minimum compatible with a dynamically-linked Rust binary.

**OpenSSL caveat.** The host crypto stack is OpenSSL-free, but
`webauthn-rs` 0.5 (FIDO2 / WebAuthn attestation, used by [`auth/fido2`](../roadmaps/tauri-gui-fido2.md))
transitively pulls in `openssl-sys`. The builder stage installs
`libssl-dev` and sets `OPENSSL_STATIC=1` + `OPENSSL_NO_VENDOR=1` so
openssl is statically linked into `bvault` from the system static libs;
the distroless **runtime** never gains a `libssl.so.3` on disk. A
post-build `ldd` check fails the build if a dynamic link sneaks back in.
Replacing the `webauthn-rs` openssl dep is tracked under [Deferred
sub-initiatives → FIDO2 / WebAuthn](../roadmap.md) in the global roadmap.

The production runtime intentionally has no `ip` / `ss` / `netstat` /
`tcpdump` / `curl`. **It does not need them to know who is connecting:**
client IP visibility is a server-application concern (see "Client IP
visibility" below) and the server gets the connecting peer's address from
the kernel via its listening socket. Putting userspace network tools in
the production image would expand the post-exploit toolbox without
adding any visibility the application doesn't already have.

A second variant, `:debug`, uses `gcr.io/distroless/cc-debian12:debug-nonroot`
which adds a busybox shell **plus a small, fixed set of network
inspection tools — `ss`, `ip`, `tcpdump`, `curl` — for operator-side
incident response** (e.g. "is my reverse proxy actually forwarding the
client IP?", "what does the kernel see on this socket?"). Operators are
expected to run `:latest` in production and only pull `:debug`
interactively, with full awareness that they are widening the runtime's
attack surface for the duration of the investigation.

### Tags

| Tag | Meaning |
|---|---|
| `vX.Y.Z` | Immutable release tag, exact server version. **Use this in production.** |
| `vX.Y` | Latest patch in a minor line (rolls forward on each patch). |
| `vX` | Latest minor in a major line. |
| `latest` | Latest stable release. **Not** for production pinning. |
| `vX.Y.Z-debug` | Same image with a busybox shell for troubleshooting. |
| `nightly` | HEAD of `main`, rebuilt daily. Not signed for production use. |

A multi-arch manifest list covers `linux/amd64` and `linux/arm64` from day
one. `linux/arm/v7`, `linux/ppc64le`, `linux/s390x` are not in scope.

### Run shape: standalone

```
podman run -d --name bastionvault \
  -p 8200:8200 \
  -v bv-data:/var/lib/bvault/data \
  -v ./config.hcl:/etc/bvault/config.hcl:ro,Z \
  ghcr.io/ffquintella/bastionvault:vX.Y.Z
```

The default `config.hcl` baked into the image is **inert** — it points
storage at `/var/lib/bvault/data` (which the operator must mount) and does
nothing else. The image refuses to start without an operator-supplied
config or an env-var override of every required key. There is **no
auto-init**: the operator runs `bvault operator init` on first boot, just
like running it on bare metal. Auto-init is a footgun for a secrets
manager and we do not ship it.

### Run shape: cluster

The same image, started with `BASTIONVAULT_MODE=cluster` and the Hiqlite
peer list:

```
podman run -d --name bv-1 \
  -p 8200:8200 -p 8201:8201 \
  -v bv-1-data:/var/lib/bvault/data \
  -e BASTIONVAULT_MODE=cluster \
  -e BASTIONVAULT_NODE_ID=1 \
  -e BASTIONVAULT_CLUSTER_PEERS='1=bv-1:8201,2=bv-2:8201,3=bv-3:8201' \
  -v ./cluster-tls/:/etc/bvault/tls/:ro,Z \
  ghcr.io/ffquintella/bastionvault:vX.Y.Z
```

The entrypoint script at the top of `CMD` resolves the mode:

- `BASTIONVAULT_MODE=standalone` (default) → `bvault server -config …`
- `BASTIONVAULT_MODE=cluster` → `bvault server -config … -hiqlite-cluster`
  with the peer list and node id passed through as flags.

Cluster TLS uses the existing PQC-friendly Rustls stack
([roadmaps/hiqlite-default-ha-storage.md](../roadmaps/hiqlite-default-ha-storage.md)
phases 4–5: X25519MLKEM768). The image expects mTLS material at
`/etc/bvault/tls/{ca.pem,node.pem,node.key}` and refuses to start a
cluster node without them. No insecure cluster mode is exposed.

### Configuration surface

Every config option is reachable three ways, in order of precedence:

1. CLI flag (`-storage=hiqlite -api-addr=0.0.0.0:8200`).
2. Environment variable, `BASTIONVAULT_<UPPER_SNAKE>` (e.g.
   `BASTIONVAULT_STORAGE=hiqlite`).
3. HCL config file at `/etc/bvault/config.hcl`.

The image does **not** add a fourth, container-only configuration system
(no `entrypoint.sh` that templates a config from environment variables).
Templating belongs in the operator's deployment tool (Helm, Compose,
Ansible) where the operator can audit the resulting config; baking it into
the image hides what's running. The entrypoint only resolves the mode flag
and execs `bvault`; everything else is passed through.

### Client IP visibility

Identifying the IP address of every connecting client is a first-class
requirement for a secrets manager: every audit-log line, every
authentication event, every rate-limit decision, and every "who unsealed
me at 03:14?" forensics query needs the real source address, not the
loopback address of a sidecar or the cluster-internal IP of an ingress.

This requirement is met **inside the binary**, not by adding userspace
network tools to the container image. The image's job is twofold:

1. **Don't strip away kernel-level peer information.** The container
   runs with the default network namespace (or the operator's chosen
   shared namespace) and `actix-web`'s socket layer reports the peer
   `SocketAddr` for every accepted connection. Distroless does not get
   in the way of this — the syscalls (`getpeername`, `accept4`) are
   kernel-level and need no userspace tools.
2. **Surface the trusted-proxy contract through configuration**, so
   that a deployment behind an ingress / reverse proxy / L4 load
   balancer can promote forwarded headers (or the PROXY protocol) to
   the canonical client-IP field instead of recording the proxy's IP
   on every line.

Two new env-var / config keys are added for this and documented in the
operator quickstart:

| Key | Behaviour |
|---|---|
| `BASTIONVAULT_TRUSTED_PROXIES` | Comma-separated list of CIDRs whose `X-Forwarded-For` / `Forwarded` (RFC 7239) headers may be promoted to the canonical client IP. Empty by default → headers ignored, the socket-level peer is the only client IP recorded. The application walks the X-F-F chain right-to-left and stops at the first hop **not** in this list, so an attacker spoofing `X-Forwarded-For` from outside the trusted set cannot impersonate an internal IP. |
| `BASTIONVAULT_PROXY_PROTOCOL` | `off` (default), `v1`, or `v2`. When set, the API listener accepts a HAProxy PROXY-protocol header on each new TCP connection and uses it as the canonical peer address. Mutually exclusive with `BASTIONVAULT_TRUSTED_PROXIES`: a single deployment uses one mechanism. |

When **neither** is set the image behaves identically to a bare-metal
install behind no proxy: the socket-level peer is the client IP. This is
the right default for direct-exposure deployments.

For audit purposes the server records both the **socket-level peer** and
the **derived client IP** on every event, so a reviewer can always tell
"this request came in on socket X from proxy Y, and Y attested it was
originally from Z." Recording only the derived value would erase the
proxy hop and make a forged-header incident harder to investigate.

The `:debug` image variant carries `ss` + `ip` + `tcpdump` + `curl`
specifically so an operator stuck on "the audit log keeps recording
10.0.0.1, which is my ingress, not the user's IP" can verify what
the kernel sees on the socket and what header the proxy is sending,
without rebuilding the image.

### Volumes

| Path | Purpose |
|---|---|
| `/var/lib/bvault/data` | Backend storage (Hiqlite SQLite + Raft logs, file backend dirs, audit chain). Required for any persistent run. |
| `/etc/bvault/config.hcl` | Operator-supplied config file. Read-only. |
| `/etc/bvault/tls/` | TLS material (server cert + key + chain) for both API and Hiqlite cluster. Read-only. |
| `/var/log/bvault/audit.log` | Optional audit-log mount when `audit` device is `file`. |

All four are documented; only `/var/lib/bvault/data` and a config source
are required.

### Health checks

`HEALTHCHECK CMD ["/usr/local/bin/bvault", "status", "-format=health"]`
exists on the image. The status subcommand returns 0 when the server is
unsealed and serving, 1 when sealed, 2 when unreachable. Container
orchestrators map this to readiness directly.

A dedicated HTTP `/v1/sys/health` endpoint already exists; the
HEALTHCHECK uses the binary so it works inside distroless without curl.

### Signing and provenance

Every published tag is signed with **Sigstore Cosign** using GitHub's
keyless signing (OIDC issuer = `https://token.actions.githubusercontent.com`,
identity bound to `ffquintella/BastionVault`). The release pipeline also
emits a SLSA v1 provenance attestation (`slsa-github-generator`).
Verification one-liner shipped in the operator docs:

```
cosign verify ghcr.io/ffquintella/bastionvault:vX.Y.Z \
  --certificate-identity-regexp 'https://github.com/ffquintella/BastionVault/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Unverified images are not supported.

### SBOM

Each image carries a CycloneDX SBOM as an attached cosign attestation
(`cosign attest --type cyclonedx`). The SBOM is generated by `syft` over
the final image filesystem so it matches what is actually shipped, not
what `Cargo.lock` *would* produce.

### Module Architecture

```
deploy/container/
├── Containerfile                # Two-stage Podman/Docker build
├── Containerfile.debug          # Same, with the :debug runtime base
├── entrypoint.sh                # Resolves mode flag, execs bvault
├── config/
│   └── config.hcl.sample        # Inert sample config
└── README.md                    # Operator quickstart

deploy/compose/
├── standalone.yml               # podman-compose / docker-compose for standalone
└── cluster.yml                  # 3-node Hiqlite cluster on a single host

.github/workflows/
└── container-image.yml          # Build + sign + SBOM + push on tag
```

## Implementation Scope

### Phase 1 — Standalone Image, amd64 — **DONE**

Acceptance bar fully met: 6 deliverable files shipped, `openssl-sys` build
issue resolved (libssl-dev + `OPENSSL_STATIC=1` + `ldd` guard), and the
audit chain now carries the socket-level peer IP on every entry
(see [`src/audit/entry.rs`](../src/audit/entry.rs); 2 regression tests).

| File | Purpose |
|---|---|
| [`deploy/container/Containerfile`](../deploy/container/Containerfile) | Two-stage build for `linux/amd64`. **Done.** |
| ~~`deploy/container/entrypoint.sh`~~ | **Dropped from Phase 1**: distroless has no shell. The standalone path uses `bvault` as ENTRYPOINT directly; the mode resolver moves to a tiny static-built helper binary in Phase 2. |
| [`deploy/container/config/config.hcl.sample`](../deploy/container/config/config.hcl.sample) | Hiqlite single-node config with placeholder secrets that fail validation (loud failure on unmodified bundled config). **Done.** |
| [`deploy/container/README.md`](../deploy/container/README.md) | Operator quickstart. **Done.** |
| [`deploy/compose/standalone.yml`](../deploy/compose/standalone.yml) | `podman compose` reference. **Done.** |
| [`.dockerignore`](../.dockerignore) | Build-context filter (excludes `target/`, submodules, GUI bundles). **Done.** |
| [`.github/workflows/container-image.yml`](../.github/workflows/container-image.yml) | Build + push to GHCR on `v*.*.*` tags + `workflow_dispatch`. **Done. Not yet signed.** |

Acceptance: `podman run` with the sample config starts a server, `bvault
operator init` from inside another shell works, the container survives a
restart with the data volume mounted, **and audit-log entries for
operator init / unseal / KV writes carry the connecting client's
socket-level IP** (verified by hitting the API from a second container
on the same Podman network and grepping the audit chain for that
container's address). The audit-side wiring (`AuditEntry.auth.remote_address`
+ `AuditEntry.request.remote_address` populated from
`Request.connection.peer_addr`) is in [`src/audit/entry.rs`](../src/audit/entry.rs);
two regression tests guard it.

### Phase 1.5 — Trusted-Proxy / PROXY-Protocol Client-IP Propagation

| File | Purpose |
|---|---|
| `src/http/client_ip.rs` (new) | `BASTIONVAULT_TRUSTED_PROXIES` parser + right-to-left X-Forwarded-For walker; surfaces a `ClientIp { socket_peer, derived }` struct for the audit + rate-limit layers. |
| `src/http/proxy_protocol.rs` (new) | Optional HAProxy PROXY-protocol v1 + v2 acceptor in front of the actix-web listener. Off unless `BASTIONVAULT_PROXY_PROTOCOL` is set. |
| `src/audit/event.rs` (extension) | Add `client_ip_socket` and `client_ip_derived` to every audit event; never collapse them into one field. |
| `deploy/container/config/config.hcl.sample` (extension) | Document both env vars in commented form. |
| `docs/docs/operations/container-image.md` (Phase 3 extension) | "Running behind a reverse proxy" + "Running behind an L4 load balancer with PROXY protocol" sections. |

Acceptance: behind an nginx fixture configured with
`X-Forwarded-For $proxy_add_x_forwarded_for`, audit events show the
real client IP in `client_ip_derived` and the nginx IP in
`client_ip_socket`; behind an haproxy fixture configured with `send-proxy-v2`,
the same property holds with `BASTIONVAULT_PROXY_PROTOCOL=v2`. With
neither set, both fields equal the socket peer. A spoofed
`X-Forwarded-For` originating from outside the trusted CIDR list is
**not** promoted to `client_ip_derived`.

### Phase 2 — Cluster Mode

| File | Purpose |
|---|---|
| `deploy/container/entrypoint.sh` (extension) | Cluster mode branch. Reads `BASTIONVAULT_MODE`, `BASTIONVAULT_NODE_ID`, `BASTIONVAULT_CLUSTER_PEERS`, builds `-hiqlite-*` flags. |
| `deploy/compose/cluster.yml` | 3-node cluster reference. |
| `tests/cluster_image.rs` | Integration test: spin a 3-node cluster from the published image with `podman compose`, write a secret on leader, read on follower, kill leader, confirm a new leader is elected, read still works. |

Acceptance: a 3-node Hiqlite cluster runs to convergence under the
official image; rolling restart by digest preserves the leader's data.

### Phase 3 — Multi-Arch + Signing + SBOM

| File | Purpose |
|---|---|
| `.github/workflows/container-image.yml` (extension) | `buildx`/`buildah manifest` for `linux/amd64` + `linux/arm64`; `cosign sign` keyless on the resulting digest; `syft` SBOM + `cosign attest`. |
| `deploy/container/Containerfile.debug` | `:debug` variant for incident response. Adds `ss`, `ip`, `tcpdump`, `curl` from `iproute2` + `tcpdump` + `curl` packages on top of the `debug-nonroot` base. **No** package manager carried into the final image. |
| `docs/docs/operations/container-image.md` | Operator-facing docs: pulling, verifying, mounting volumes, env-var matrix, cluster cookbook, **plus a "Client IP propagation" cookbook covering direct exposure, X-Forwarded-For behind an ingress, and PROXY-protocol behind an L4 load balancer**. |

Acceptance: `cosign verify` and `cosign verify-attestation` both succeed
against a published `vX.Y.Z` tag; the manifest list resolves to two
arch-specific manifests; `syft scan registry:…` returns the SBOM.

### Phase 4 — Helm Chart Reference

| File | Purpose |
|---|---|
| `deploy/helm/bastionvault-server/` | Server Helm chart (StatefulSet for cluster mode, Deployment for standalone, PVC for storage, Service + Ingress, ConfigMap for `config.hcl`, Secret for TLS material). |

Acceptance: `helm install bv .` brings up a cluster on `kind`; the chart
is published to the same OCI registry as the image
(`oci://ghcr.io/ffquintella/charts/bastionvault-server`).

### Not In Scope

- **Auto-init / auto-unseal.** Both bury the most security-critical
  bootstrap moment behind container start, where it cannot be reviewed.
  Operators run `operator init` and `operator unseal` themselves, the same
  as on bare metal.
- **A `:dev` image with insecure defaults** (TLS off, dev mode auto-unsealed,
  predictable root token). The dev-mode binary already exists; we will not
  publish it as an image because the line between "I pulled the dev image
  by mistake" and "production secrets are now world-readable" is too thin.
- **Windows containers.** The server binary supports Windows but the
  cluster-image story does not benefit from a Windows base; demand to be
  reconsidered if asked.
- **Distro-specific images** (Alpine, RHEL UBI, Wolfi). Distroless is the
  one supported runtime; alternative bases create CVE matrices to track
  and break image-signing automation. Operators preferring Wolfi or UBI
  can build their own from the published `Containerfile` as a starting
  point.

## Testing Requirements

### Unit / Lint

- `hadolint deploy/container/Containerfile` and `…/Containerfile.debug`
  must pass with no warnings.
- The entrypoint shell script is checked with `shellcheck -e SC2086`
  (the one exception is the deliberate word-splitting on the peer list).

### Integration Tests

- **Standalone smoke**: `podman build && podman run`, exec `bvault status`
  inside another container, expect `sealed: true` initially; init + unseal
  + write a KV secret + read it back.
- **Cluster smoke** (Phase 2 acceptance, automated): bring up a 3-node
  cluster with `podman compose`, run a write on the leader, read on each
  follower, kill the leader pod, confirm a new leader within 5 seconds,
  confirm the previously-written secret is still readable.
- **Restart-with-data**: stop the standalone container, restart it with
  the same volume, confirm it comes up sealed-but-initialised; unseal,
  confirm previously-written secrets are still present.
- **Permission hygiene**: confirm the runtime user is `65532:65532`
  (nonroot in distroless), confirm the binary is not setuid, confirm
  `/var/lib/bvault/data` is writable by that uid only.
- **Client-IP direct** (Phase 1.5): from a second container at a known
  IP on the same Podman network, hit the API; assert the audit chain
  records that IP as both `client_ip_socket` and `client_ip_derived`.
- **Client-IP through nginx** (Phase 1.5): nginx fixture in front of
  the server, `X-Forwarded-For $proxy_add_x_forwarded_for`,
  `BASTIONVAULT_TRUSTED_PROXIES` set to the nginx container's CIDR; a
  request from a third container shows that container's IP in
  `client_ip_derived` and the nginx IP in `client_ip_socket`.
- **Client-IP spoof** (Phase 1.5): the same nginx fixture, but the
  third container injects its own `X-Forwarded-For: 10.0.0.1` header.
  The audit chain records the third container's real IP, **not**
  `10.0.0.1`, because nginx appends and the right-to-left walk stops
  at the first untrusted hop.
- **Client-IP via PROXY protocol** (Phase 1.5): haproxy fixture with
  `send-proxy-v2`, `BASTIONVAULT_PROXY_PROTOCOL=v2`; same property as
  the nginx test.

### Cucumber BDD Scenarios

- Operator pulls the published image by tag, verifies it with `cosign`,
  starts a standalone container with a mounted config and data volume,
  initialises the vault, writes a secret, reads it back.
- Operator deploys the cluster Compose file, watches three replicas join
  and elect a leader, writes a secret on the leader, kills the leader's
  container, confirms the same secret is still readable from a different
  replica.
- Operator pulls a published image without verifying its signature; the
  documentation explicitly warns this is unsupported and the operator
  reverses course and verifies it.

### Negative Tests

- Container started without a config and without env-var overrides:
  refuses to start with a clear, single-line error message naming what is
  missing. **No** silent-default fallback.
- Cluster mode started without `BASTIONVAULT_CLUSTER_PEERS`: refuses with
  a single-line error.
- Cluster mode started without TLS material in `/etc/bvault/tls/`:
  refuses with a single-line error.
- Image pulled at a tag whose signature does not verify: documented
  failure mode in the operator docs (cosign exits non-zero); supply chain
  considered compromised, no run path proceeds.

## Security Considerations

- **Distroless runtime**: no shell, no package manager, no `curl`, no
  `nc`. Reduces both the post-exploit toolbox and the CVE patch cadence.
- **No `libssl.so.3` in the runtime image**, even though `webauthn-rs`
  transitively links openssl-sys for FIDO2 attestation. The builder
  statically links openssl into `bvault` (`OPENSSL_STATIC=1` +
  `OPENSSL_NO_VENDOR=1`) and a post-build `ldd` check enforces the
  invariant. The "running container has no libssl on disk" property
  holds even though the build chain is not openssl-free.
- **Nonroot UID** (`65532:65532`) baked into the runtime stage. The image
  refuses to run as root; if Kubernetes / Podman tries to override with
  `--user 0`, the binary itself fails its capability check.
- **No CAP_NET_ADMIN, no CAP_SYS_ADMIN.** Default Podman caps are
  sufficient; the operator docs name the capability set explicitly so a
  reviewer can audit it.
- **TLS material is mounted, not baked.** The image never embeds keys.
- **Audit log volume is documented as a separate mount** so a compromised
  data volume doesn't take the audit chain with it. The operator can put
  the audit volume on a different filesystem or storage class.
- **Image signing is mandatory in the operator docs.** We do not advertise
  unsigned-pull paths.
- **SBOM attestation**: every published tag has an attached CycloneDX
  SBOM, so operators can run `grype` / `trivy` against the registry
  without re-pulling and re-scanning the filesystem locally.
- **No auto-unseal.** A container that auto-unseals at start is a
  container that hands plaintext-access to anyone who can `podman
  inspect` its environment. We refuse this even when asked.
- **Cluster TLS uses the project's PQ-aware Rustls stack** by default
  (X25519MLKEM768 hybrid). The cluster mode does not expose an
  insecure-cluster fallback.
- **Health endpoint is read-only and identity-free.** The HEALTHCHECK
  binary call returns sealed/unsealed without exposing any secret or any
  identity.
- **Trusted-proxy CIDR list is empty by default.** A misconfigured
  deployment that puts the server behind a reverse proxy *without*
  setting `BASTIONVAULT_TRUSTED_PROXIES` records the proxy's IP on
  every audit line — an obvious, loud, easy-to-detect failure mode. A
  forwarded-header reader that *defaults* to trusting `X-Forwarded-For`
  is the textbook way operators end up letting any client spoof any
  source IP, so we choose the louder default deliberately.
- **Right-to-left X-Forwarded-For walk + trusted-CIDR gate** prevents
  a client from injecting an `X-Forwarded-For` value that the audit
  layer will believe. Only contiguous hops from the closest proxy
  inward, all in the trusted set, contribute to the derived client IP;
  the first untrusted hop terminates the walk.
- **Audit chain records both the socket peer and the derived client
  IP.** Collapsing them into one field would erase the proxy hop and
  make a forged-header incident harder to investigate; keeping both is
  cheap and forensically essential.
- **PROXY-protocol mode is mutually exclusive with X-F-F trust.** A
  deployment that mixes the two creates an ambiguity (which one wins?)
  and the resulting bug is exactly the kind that hides until it
  matters; the binary refuses the combination at startup.
- **The `:debug` image's expanded toolset is opt-in by tag.** The
  default `:latest` / `:vX.Y.Z` images carry no userspace network
  tools at all. Operators that pull `:debug` are asked, in the
  operator docs, to roll back to `:vX.Y.Z` once the investigation
  closes.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md),
[roadmap.md](../roadmap.md) (Packaging & Distribution → Server Container
Image row: `Todo` → `In Progress` (Phase 1) → `Done` (Phase 4)), and
this file's "Current State" / phase markers.
