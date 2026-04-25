# Feature: Kubernetes Integration

## Summary

Add first-class **Kubernetes integration** so workloads running in a Kubernetes cluster can authenticate to BastionVault using their pod's service-account token, fetch secrets via a sidecar / CSI driver / mutating webhook, and never see a long-lived BastionVault token. Three deliverables, in order of value:

1. **`kubernetes` auth backend** — pods present their projected service-account token; BastionVault verifies it against the cluster's TokenReview API; matching `role` config returns a BastionVault token. This is the foundational primitive; everything else depends on it.
2. **`bastion-vault-csi-driver`** — Container Storage Interface driver that mounts secrets into pods as in-memory `tmpfs` files. Drop-in compatible with the `secrets-store-csi-driver` ecosystem so customers using AKS / EKS / GKE add-ons keep working.
3. **`bastion-vault-agent` injector** — mutating admission webhook that injects a sidecar / init-container into annotated pods; the sidecar authenticates, fetches secrets, and writes them as files for the application container.

A fourth deliverable, **`kubernetes` dynamic-secrets engine** (vault-issued K8s service-account tokens for *external* callers consuming the cluster), is deferred to the dynamic-secrets framework ([features/dynamic-secrets.md](dynamic-secrets.md)) — it fits that chassis cleanly and avoids duplicating credential-lifecycle code.

The whole stack is pure-Rust + rustls; no OpenSSL, no `aws-lc-sys`. The CSI driver and agent injector are compiled binaries that ship as container images.

## Motivation

- **K8s is where the secrets workload lives.** Any secrets-manager that doesn't have a clean K8s story is a non-starter for the modern application platform team. Vault's K8s auth + Vault Agent + the official CSI provider are the single most-cited reasons customers stay on Vault despite its other flaws.
- **The status quo for K8s secrets is bad.** `kubectl create secret generic` ships secrets as base64-encoded ConfigMap-equivalents in etcd; etcd encryption-at-rest is opt-in and often misconfigured; secrets reach pods as files mounted from the kubelet's cache, where any container with `hostPath` access can read them. BastionVault's value prop — barrier encryption + identity-bound access + audit — is exactly what's missing here.
- **Pure-Rust K8s clients exist now.** `kube` (the rust-kubernetes ecosystem) is mature; `tower` + `hyper` + `rustls` give us a clean K8s API stack with no C deps. Building this used to require a CGO sidecar; today it doesn't.
- **The feature is naturally split across in-tree and out-of-tree work.** The auth backend lives inside `bastion-vault` (it's a credential module like the others). The CSI driver and agent are separate binaries that consume BastionVault's public API; they don't need to be in `src/modules/`. This is a clean boundary that keeps the core small.

## Current State

- **No K8s integration exists in the repo.** No `kubernetes` auth backend, no CSI driver, no admission webhook.
- **The auth-backend trait machinery is ready** ([src/modules/credential/](../src/modules/credential)). The existing `oidc` and `saml` modules are the closest analogues — token-bearing-credential verifiers that map external identity to a BastionVault entity. The K8s backend will follow the same pattern.
- **The Tauri GUI ships in embedded mode** for desktop users; the K8s story is server-mode only. None of the GUI work changes.
- **Kubernetes Integration row currently reads `Todo`** ([roadmap.md:55](roadmap.md:55)). The roadmap also notes that work is deferred to a future initiative ([roadmap.md:101](roadmap.md:101)).

## Design

### Component 1 — `kubernetes` Auth Backend

A new credential module at `src/modules/credential/kubernetes/`. Wire-compatible with Vault's `auth/kubernetes/login` endpoint so customers' existing Helm charts, Terraform modules, and example apps work after a base-URL swap.

**Configuration** (`POST /v1/auth/kubernetes/config`):

| Field | Description |
|---|---|
| `kubernetes_host` | API server URL (e.g. `https://kubernetes.default.svc`). |
| `kubernetes_ca_cert` | PEM-encoded API-server CA cert. |
| `token_reviewer_jwt` | A long-lived JWT for a service account that can call `TokenReview`. Optional if the BastionVault pod itself runs with that permission via projected SA token. |
| `pem_keys` | Optional pre-shared SA-signing public keys for "issuer-only" mode (no TokenReview API call; verify the JWT signature locally — useful when BastionVault runs outside the cluster). |
| `issuer` | Expected `iss` claim. Default `https://kubernetes.default.svc.cluster.local`. |
| `disable_local_ca_jwt` | If true, do not auto-load the in-pod CA + token. Default `false`. |

**Roles** (`POST /v1/auth/kubernetes/role/:name`):

| Field | Description |
|---|---|
| `bound_service_account_names` | Allowed SA names. `*` disallowed. |
| `bound_service_account_namespaces` | Allowed namespaces. `*` disallowed. |
| `audience` | Required `aud` claim on the projected token (matches the projection in the pod spec). |
| `token_policies` | BastionVault policies attached on successful login. |
| `token_ttl` / `token_max_ttl` | Issued-token lifetimes. |
| `alias_name_source` | What goes into the entity-alias name: `serviceaccount_uid` (default; immutable) or `serviceaccount_name` (human-readable, mutable). |

**Login flow** (`POST /v1/auth/kubernetes/login`):

1. Pod posts `{"role": "myapp", "jwt": "<projected-sa-token>"}`.
2. Backend looks up the role; refuses if missing.
3. Verifies the JWT — preferred path: call the cluster's `TokenReview` API with the JWT; fallback path: local signature verification using `pem_keys`.
4. Asserts `aud`, `iss`, SA name + namespace match the role bounds.
5. Resolves or creates the BastionVault entity + alias keyed by the SA UID (or name, per `alias_name_source`).
6. Issues a token with the role's `token_policies`, `token_ttl`, and a `metadata` block carrying `service_account_name`, `service_account_namespace`, `service_account_uid`, `pod_name`, `pod_uid`.
7. Returns the token.

The JWT verification path is the security-critical bit. The implementation **prefers TokenReview** because it lets the cluster control-plane revoke a leaked SA token (e.g. by deleting the pod) and have BastionVault refuse it on the next login. Local-key verification is faster but cannot detect post-issuance revocation.

### Component 2 — `bastion-vault-csi-driver`

A separate cargo workspace member at `cmd/bastion-vault-csi-driver/`. Implements the [Kubernetes CSI](https://kubernetes-csi.github.io/) interface for the `secrets-store.csi.x-k8s.io` provider type.

**How it appears to a pod:**

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: myapp-secrets
spec:
  provider: bastion-vault
  parameters:
    vaultAddress: "https://bastion.internal:8200"
    roleName: "myapp"
    objects: |
      - objectName: "db-password"
        secretPath: "secret/data/myapp/db"
        secretKey: "password"
      - objectName: "api-key"
        secretPath: "secret/data/myapp/api"
        secretKey: "key"
```

```yaml
# Pod spec excerpt
volumes:
  - name: secrets
    csi:
      driver: secrets-store.csi.k8s.io
      readOnly: true
      volumeAttributes:
        secretProviderClass: "myapp-secrets"
volumeMounts:
  - name: secrets
    mountPath: /var/run/secrets/myapp
```

**Driver flow on volume mount:**

1. Receive `NodePublishVolume` from kubelet with the `SecretProviderClass` parameters and the pod's projected SA token.
2. Authenticate to BastionVault via the `kubernetes` auth backend using the SA token + the configured `roleName`.
3. Fetch each `objectName` from `secretPath`/`secretKey`.
4. Write each as `<mountPath>/<objectName>` on a `tmpfs` mount (so the secret never hits disk).
5. Return success.
6. On `NodeUnpublishVolume`, unmount and zeroise the tmpfs region.

**Rotation**: the driver supports the `secrets-store-csi-driver`'s rotation reconciler (poll-based). On each reconcile, fetch + diff + atomically replace any changed file. Apps using `inotify` get a re-read trigger for free.

### Component 3 — `bastion-vault-agent` Injector

A separate workspace member at `cmd/bastion-vault-agent/`. Two binaries:

- **`bastion-vault-agent`** — runs as a sidecar (or init-container) inside the application pod; authenticates, fetches secrets, writes them to a shared volume.
- **`bastion-vault-injector`** — a mutating admission webhook. Operators install it cluster-wide; pods carrying `bastion-vault.io/inject: "true"` plus a few `bastion-vault.io/agent-*` annotations get the sidecar + volumes injected automatically.

Annotation surface (Vault-Agent compatible names where the semantics line up):

```yaml
metadata:
  annotations:
    bastion-vault.io/inject: "true"
    bastion-vault.io/role: "myapp"
    bastion-vault.io/agent-inject-secret-db-password: "secret/data/myapp/db"
    bastion-vault.io/agent-inject-template-db-password: |
      {{ with secret "secret/data/myapp/db" }}{{ .Data.data.password }}{{ end }}
    bastion-vault.io/agent-inject-mode: "init"   # or "sidecar"
```

The agent's template language is a deliberately small subset of Vault Agent's (`{{ secret "..." }}`, `{{ with }}`, `{{ if }}`, `{{ range }}`, `{{ env "..." }}`) so existing Vault templates port over with minimal change. Pure-Rust template engine via `minijinja` (no Tera, no Handlebars; minijinja is small + audit-friendly).

**Init-container mode**: agent fetches secrets once, writes them to an `emptyDir` volume, exits. App container starts with secrets pre-populated.

**Sidecar mode**: agent stays running, refreshes secrets on TTL or on lease-renew, signals the app via signal / file-watch / template-command.

### Cross-Component: K8s Client Stack

All three components share a small `crates/bv_kube/` crate:

- `kube` (rust-kubernetes) for the K8s API client.
- `rustls` for TLS to the API server.
- `tower` for retry / backoff / rate-limiting.
- A thin `BastionVaultClient` that wraps our public API + the K8s auth login flow.

This crate is *not* a build-time dependency of `bastion-vault` itself; it's only pulled in by the K8s tooling binaries.

### Module Architecture (in-tree)

```
src/modules/credential/kubernetes/
├── mod.rs                  -- KubernetesModule; route registration
├── backend.rs              -- KubernetesBackend; TokenReview client; key cache
├── config.rs               -- /v1/auth/kubernetes/config
├── role.rs                 -- /v1/auth/kubernetes/role/:name
├── path_login.rs           -- /v1/auth/kubernetes/login
├── verify.rs               -- JWT verify: TokenReview path + local pubkey path
└── alias.rs                -- entity-alias creation/resolution
```

### Out-of-Tree Components

```
cmd/bastion-vault-csi-driver/
├── Cargo.toml
├── src/main.rs
├── src/grpc.rs              -- CSI gRPC service (NodeService, IdentityService)
├── src/mount.rs             -- tmpfs management
├── src/rotation.rs          -- reconcile loop
└── deploy/                  -- Helm chart, DaemonSet manifest

cmd/bastion-vault-agent/
├── Cargo.toml
├── src/agent/main.rs        -- sidecar / init binary
├── src/agent/template.rs    -- minijinja templates
├── src/agent/lifecycle.rs   -- once / continuous / signal-on-change
├── src/injector/main.rs     -- admission webhook
├── src/injector/mutate.rs   -- pod mutation logic
├── src/injector/cert.rs     -- self-signed webhook cert bootstrap
└── deploy/                  -- Helm chart, ValidatingAdmissionPolicy alternative

crates/bv_kube/
├── Cargo.toml
└── src/lib.rs               -- shared K8s client + BastionVaultClient
```

## Implementation Scope

### Phase 1 — `kubernetes` Auth Backend (TokenReview Path)

| File | Purpose |
|---|---|
| `src/modules/credential/kubernetes/*` | All in-tree files above. |
| `crates/bv_kube/src/lib.rs` | TokenReview client (called only by the auth backend in Phase 1). |

Dependencies:

```toml
kube           = { version = "0.96", default-features = false, features = ["client", "rustls-tls"] }
k8s-openapi    = { version = "0.23", default-features = false, features = ["v1_31"] }
jsonwebtoken   = "9"          # local-key verification fallback
```

### Phase 2 — Local Pubkey JWT Verification + GUI Surface

| File | Purpose |
|---|---|
| `src/modules/credential/kubernetes/verify.rs` (extension) | Local-key JWT verify (no TokenReview round-trip; useful when BastionVault is outside the cluster). |
| `gui/src/routes/SettingsPage.tsx` (extension, Identity tab) | "Kubernetes" subsection — manage configs and roles. |

### Phase 3 — CSI Driver

| File | Purpose |
|---|---|
| `cmd/bastion-vault-csi-driver/*` | Standalone binary + Helm chart. |

Dependencies:

```toml
tonic       = { version = "0.12", default-features = false, features = ["codegen", "prost"] }
prost       = "0.13"
nix         = "0.29"      # tmpfs mount syscalls (Linux)
caps        = "0.5"       # capability dropping
```

### Phase 4 — Agent Injector

| File | Purpose |
|---|---|
| `cmd/bastion-vault-agent/*` | Two binaries (`agent`, `injector`) + Helm chart. |

Dependencies:

```toml
minijinja   = { version = "2", default-features = false }
notify      = "6"           # file-watch for app reload signalling
axum        = "0.7"         # admission webhook HTTP server (TLS via rustls)
```

### Phase 5 — Reference Helm Charts + Documentation

| File | Purpose |
|---|---|
| `deploy/kubernetes/bastion-vault-server/` | Server Helm chart. |
| `deploy/kubernetes/bastion-vault-csi-driver/` | CSI driver chart. |
| `deploy/kubernetes/bastion-vault-agent-injector/` | Injector chart. |
| `docs/docs/kubernetes.md` | Operator guide. |

### Not In Scope

- **`kubernetes` dynamic-secrets engine** (Vault issuing K8s SA tokens for external callers). Tracked under [features/dynamic-secrets.md](dynamic-secrets.md).
- **Vault Secrets Operator-style CRDs** (e.g. `BastionVaultSecret`, `BastionVaultPKISecret`). The CSI driver + agent cover the same use cases without inventing a new CRD layer; if customers ask for CRDs we ship them as a Phase 6.
- **Service-mesh-native integration** (SPIFFE / SPIRE issuer). The K8s SA token is the chosen identity primitive; SPIFFE is a follow-up if asked for.
- **Windows pods.** CSI driver is Linux-only in v1; tmpfs mount semantics are Linux-specific. Windows pods can use the agent injector (init/sidecar mode), which has no kernel-mount dependency.
- **Vault PKI auto-rotation of pod TLS certs.** Belongs to PKI ([features/pki-secret-engine.md](pki-secret-engine.md)) + agent template integration; documented separately once both ship.
- **K8s External Secrets Operator parity.** ESO is a separate ecosystem with its own CRDs; we're not aiming for parity, only for SecretProviderClass / Vault Agent compatibility.

## Testing Requirements

### Unit Tests

- TokenReview response parsing: success / unauthorized / expired / wrong audience.
- Local-key JWT verify: valid signature accepted; expired token rejected; wrong issuer rejected.
- Role bound-name / bound-namespace matching: glob behaviour, case sensitivity, edge cases (empty list = deny-all).
- Entity-alias resolution: same SA UID across two logins resolves to the same alias; rotated SA name with `alias_name_source=serviceaccount_uid` keeps the alias stable.
- minijinja template subset: every documented function works; undocumented functions refused (the template engine is sandboxed to the allowlist).

### Integration Tests

- **kind cluster** (CI uses `kind` for K8s): deploy BastionVault, deploy a test pod with a projected SA token, log in, get a BastionVault token, write a secret via that token, confirm the secret is fetchable.
- **CSI driver**: deploy CSI driver as DaemonSet, create a `SecretProviderClass`, create a pod that mounts it, exec into the pod, confirm secret files exist with right contents and right permissions; rotate the secret, wait for the reconcile, confirm the file updates without pod restart.
- **Agent injector**: deploy injector, annotate a pod, confirm the mutating webhook injects the sidecar; sidecar fetches secrets and writes them to the shared volume; app reads them.
- **TokenReview revocation**: log a pod in, delete the pod (which invalidates the SA token), attempt re-login with the old token, confirm rejection.

### Cucumber BDD Scenarios

- Operator deploys BastionVault server + CSI driver to a fresh cluster; deploys a sample app with a `SecretProviderClass`; the app starts with secrets present at `/var/run/secrets/myapp/`.
- Operator rotates a secret in BastionVault; within the configured rotation interval the file inside the running pod has the new value.
- Operator deletes a pod that had a leaked SA token; replays the leaked token against `auth/kubernetes/login`; the call fails because TokenReview marks it invalid.

### Negative Tests

- Login with a JWT whose `aud` doesn't match the role: rejected.
- Login with a JWT whose SA namespace isn't in `bound_service_account_namespaces`: rejected.
- CSI driver fed a `SecretProviderClass` referring to a path the pod's role isn't allowed: mount fails with a clear error in the kubelet event log.
- Agent injector fed an annotation with a template that calls an un-allowlisted minijinja function: pod admission rejected with a webhook denial reason.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as every other module; `kube`, `tonic`, and `axum` all configured for `rustls`.
- **TokenReview is the preferred verification path** because it respects post-issuance revocation. Local-key verification is offered for the BastionVault-outside-cluster case and is loud about the tradeoff in operator-facing docs.
- **Role bounds must enumerate; wildcards are forbidden** for `bound_service_account_names` and `bound_service_account_namespaces`. `*` is a footgun that turns the K8s integration into "any pod in the cluster gets the policy"; we refuse it at config-write time.
- **CSI driver runs as a privileged DaemonSet** because it has to mount tmpfs into pods. Linux capabilities are dropped to the minimum needed (`CAP_SYS_ADMIN` for the mount, dropped immediately after); seccomp profile bundled in the Helm chart.
- **CSI tmpfs is `mount(MS_NOEXEC|MS_NOSUID|MS_NODEV)`** plus zeroised on unmount. Secrets never hit disk and never linger.
- **Agent sidecar runs as the same UID as the app container** (operator-configurable); the shared `emptyDir` is `medium=Memory` so secrets stay on tmpfs in the pod's memory, not disk.
- **Injector webhook serves over rustls with a cert auto-rotated weekly**; the cert is bootstrapped via Kubernetes' built-in CA approval flow (CertificateSigningRequest), not via static secrets.
- **Audit chain**: every `auth/kubernetes/login` event records SA UID, namespace, name, audience, pod UID, pod name, source IP. CSI mounts and agent fetches show up as standard `secret/read` events from the BastionVault token issued at login time, so the chain from "pod started" to "secret read" is fully connected in the audit log.
- **Annotation injection abuse**: the injector validates that the requesting pod's serviceAccount has permission to mount the requested role (a soft-policy check at admission time). This prevents a low-privilege namespace from creating a pod that injects a high-privilege role's secrets.
- **Defense-in-depth against compromised CSI**: the CSI driver authenticates with the *pod's* SA token, not its own privileged token. A compromised CSI driver can only fetch secrets accessible to the SAs whose pods it's currently servicing, not the union of every secret in the cluster.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md) (move from `Todo` → `In Progress` (Phase 1) → `Done` (Phase 5)), and this file's "Current State" / phase markers.
