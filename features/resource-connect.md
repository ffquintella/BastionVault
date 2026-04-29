# Feature: Connect to Server Resources (SSH / RDP)

## Summary

Add a **Connect** button to server-typed resources in the GUI. When the operator clicks it, BastionVault opens a new window with the appropriate session client based on the resource's OS type:

- **Linux / macOS / BSD / Unix** → an in-app **SSH terminal** (xterm.js front-end driven by a pure-Rust SSH client running inside the Tauri host).
- **Windows** → an in-app **RDP session** (canvas front-end driven by [`ironrdp`](https://github.com/Devolutions/IronRDP), Devolutions' pure-Rust RDP stack).
- **Other / unknown** → button hidden (or disabled with a tooltip explaining why).

The session pulls its credentials directly from the resource's stored secrets (SSH key, RDP password, …). The operator never copy-pastes credentials, never sees the cleartext, and the credential never lives outside the running session window.

This builds on the existing **Resources** layer ([features/resources.md](resources.md), shipped) and the existing **SSH secret engine** ([features/ssh-secret-engine.md](ssh-secret-engine.md), shipped — CA + OTP + ML-DSA-65 PQC modes). The SSH side is largely a thin GUI layer over plumbing that already exists; the RDP side is genuinely new and the larger half of the work.

## Motivation

- **Bastion-host pattern.** The whole point of a vault that holds server credentials is to actually use them to reach those servers. Making the operator copy a password / SSH key into a separate terminal is the workflow we keep telling them not to use. A Connect button collapses "open vault → find resource → reveal secret → switch to terminal → paste → connect" into one click.
- **Audit completeness.** Every Connect launches an audit event (`session.open`) and closes one (`session.close`) with start time, end time, target identity, and which credential was injected. A SOC can answer "who opened a session to web01 at 03:14 last night?" without joining vault-audit + jumphost-syslog + workstation-syslog.
- **Credential never lands.** Today, even with the masked-reveal in `ResourcesPage.tsx`, an operator who clicks Reveal can copy the password into the OS clipboard, where it persists. The Connect path injects the credential straight into the session protocol — it never goes to the clipboard, never lands in shell history, never gets pasted into a chat tab by mistake.
- **OS-aware UX.** Once a resource carries an `os_type`, a lot of follow-on work (right default port, right default username, right default credential field, right session client) becomes trivial. Today every server gets the same generic UI.

## Current State

- Resources have a `server` type with text fields including a free-form `os` field ([gui/src/lib/resourceTypes.ts](../gui/src/lib/resourceTypes.ts)). There's no structured `os_type` enum, so the GUI can't make decisions based on it.
- The SSH secret engine ships CA-signed certs, OTP, and PQC certs — everything the SSH side of this feature needs to mint a session credential ([features/ssh-secret-engine.md](ssh-secret-engine.md)).
- There is no in-app terminal. There is no in-app RDP client.
- Tauri v2 supports multi-window apps natively (`WebviewWindowBuilder`) and we already use it (e.g. the Add Local Vault dialog uses the dialog plugin in a separate context). Opening a new window for a session is mechanically straightforward.

## Scope

### In scope

- **New `os_type` structured field** on the `server` resource type, replacing/augmenting the existing free-form `os` text field. Values: `linux`, `windows`, `macos`, `bsd`, `unix`, `other`. Stored on the resource record, surfaced as a `select` field type in the resource editor.
- **`select` field type** in the resource-type schema (`ResourceFieldDef.type` extended), so other resource types can also use enums going forward.
- **Connect button** on the resource detail view, visible when `type === "server"` and `os_type` is set to a supported value. Hidden / disabled with a tooltip otherwise.
- **In-app SSH session window** — new Tauri WebviewWindow with an xterm.js terminal, driven by a pure-Rust SSH client (`russh` 0.45) running in the Tauri host. Credential sourced from the resource's bound credential source (see "Credential sources" below).
- **In-app RDP session window** — new Tauri WebviewWindow with a canvas surface, driven by [`ironrdp`](https://crates.io/crates/ironrdp) (pure-Rust, MIT/Apache, Microsoft-spec-compliant) running in the Tauri host. Bitmap deltas streamed to the WebView via a binary Tauri channel; keyboard / mouse events streamed back.
- **Four credential-source kinds**, all selectable on the resource and resolved at connect time: a static `credential` secret on the resource itself, an LDAP / Active Directory bind via the LDAP secret engine, a freshly-minted SSH credential via the SSH secret engine (CA-signed cert / OTP / PQC), or a freshly-minted client cert via the PKI engine.
- **Session-audit events** — `session.open` and `session.close` go through the existing audit pipeline with target resource id, OS type, credential source (which secret), and outcome.
- **Per-mount Connect policy** — operators can disable the Connect button globally or per-resource-type via a new `connect.enabled = false` knob on the resource-type definition (so a regulated environment can keep the metadata + secrets layer but force operators through their existing PAM tool).
- **Per-OS protocol pin** — the GUI enforces the OS → protocol mapping (no "use SSH on a Windows host" dropdown). Operators with mixed-protocol hosts can model them as two resources or set `os_type = other` to opt out of Connect.

### Out of scope (explicit)

- **VNC.** RDP covers Windows comprehensively; VNC adds a third protocol with its own auth shape and no compelling reason in our user base. A future operator can add it as a separate feature.
- **Session recording / playback.** A real PAM product records every keystroke for later replay. We may add this as a separate feature once basic Connect lands, but it's not part of this feature.
- **Credential rotation triggered by session close.** The SSH engine's OTP mode already has one-shot semantics; for static SSH keys / RDP passwords the rotation cadence is the operator's existing rotation schedule. Coupling rotate-on-close to this feature couples two large changes; better as a follow-on.
- **Web SSO / SAML / OIDC handoff** for the session windows. Sessions auth with the credentials in the vault, not with the vault user's identity (that would require the target system to trust the vault's identity provider, which is its own product).
- **Mobile / web Vault.** This is desktop-only — the session windows are Tauri WebviewWindows, no browser deployment.
- **Multi-hop / jump-host orchestration.** v1 connects directly from the GUI host to the target. A future feature can add `via = <bastion-resource>` chaining.
- **File transfer (SCP / SFTP).** SSH sessions are interactive-only in v1. SFTP would slot in as a separate feature reusing the same `russh` session.

## Design

### `os_type` field — schema change

Extend `ResourceFieldDef.type` ([gui/src/lib/types.ts:165](../gui/src/lib/types.ts:165)) to include a `select` variant:

```ts
export interface ResourceFieldDef {
  key: string;
  label: string;
  type: "text" | "number" | "url" | "ip" | "fqdn" | "select";
  placeholder?: string;
  /** Required for `select`; ignored otherwise. */
  options?: { value: string; label: string }[];
}
```

Add `os_type` to the default `server` definition in [gui/src/lib/resourceTypes.ts](../gui/src/lib/resourceTypes.ts):

```ts
{
  key: "os_type",
  label: "OS Type",
  type: "select",
  options: [
    { value: "linux",   label: "Linux" },
    { value: "windows", label: "Windows" },
    { value: "macos",   label: "macOS" },
    { value: "bsd",     label: "BSD" },
    { value: "unix",    label: "Other Unix" },
    { value: "other",   label: "Other / unknown" },
  ],
},
```

The free-form `os` field stays — it captures the human-readable distro/version (`Ubuntu 24.04`, `Windows Server 2022`); the new `os_type` is the structured enum the GUI dispatches on.

**Migration**: existing records have no `os_type`. The detail view shows a banner "Set OS Type to enable Connect" until the operator picks one. A small heuristic in the GUI's edit modal can pre-fill from the free-form `os` value (`/windows/i` → `windows`, etc.) — operator confirms before saving.

### Credential sources

The Connect path resolves a **credential source** at connect time and feeds the result straight into the protocol library. Four kinds are supported:

| Kind | What it is | SSH? | RDP? | Source of truth |
|---|---|---|---|---|
| `secret`   | A "credential" secret stored on the resource itself, with `username` + `password` (and optional `private_key`) | yes | yes | `resource/<name>/secret/<secret-id>` |
| `ldap`     | LDAP / Active Directory account that the operator authenticates against at connect time, or that the LDAP secret engine manages (static role / library check-out) | yes (password) | yes (NLA) | LDAP mount + the operator's bind, or `ldap/static-cred/<role>` / `ldap/library/check-out/<set>` |
| `ssh-engine` | A freshly-minted SSH credential from the in-tree SSH secret engine — CA-signed user cert, OTP, or ML-DSA-65 PQC cert | yes | n/a | `ssh/sign/<role>` (CA mode), `ssh/creds/<role>` (OTP), `ssh/sign-pqc/<role>` (PQC) |
| `pki`      | A freshly-minted client X.509 cert from the in-tree PKI engine, used as smartcard-style auth (Windows AD-integrated CredSSP for RDP; certificate auth for SSH where the host is configured for it) | yes (cert auth) | yes (smartcard / NLA cert) | `pki/issue/<role>` |

Both engine-backed sources (`ssh-engine`, `pki`) produce **fresh, short-lived credentials per connect**. The resource never holds the secret bytes — only the *recipe* for minting them.

#### `secret` — static credential on the resource

A new built-in secret shape for credential-typed secrets: a JSON object with named fields (`username`, `password`, optional `private_key`, optional `passphrase`). The resource module already accepts arbitrary JSON `Map<String, Value>` per secret ([src/modules/resource/mod.rs:120](../src/modules/resource/mod.rs:120)), so nothing in the storage layer needs to change — this is a **convention**: secrets whose JSON contains a `username` field are surfaced in the GUI as "Credentials" with a dedicated editor (split-input for username / masked password / paste-PEM for private key) instead of the generic key-value editor.

A new `ResourceSecretShape` enum on the GUI side keys off the secret's field shape:

```ts
type ResourceSecretShape =
  | { kind: "credential"; username: string; has_password: boolean; has_private_key: boolean }
  | { kind: "kv"; keys: string[] };
```

The Settings page can also let admins register additional shapes (e.g., `aws-access-key`, `api-token`) for the same auto-detection logic — same pattern as `ResourceTypeDef`.

#### `ldap` — AD / LDAP credential

Two sub-modes:

1. **Operator-supplied bind** — at connect time the GUI pops a small "LDAP credentials" prompt; the operator types `domain\username` (or `user@realm`) + password. The host runs an LDAP simple-bind through the existing LDAP client ([src/modules/ldap/client.rs](../src/modules/ldap/client.rs)) against the resource's bound LDAP mount; on success the same credentials are forwarded to the SSH/RDP session. The vault never persists them.
2. **Vault-managed account** — the resource is bound to either an LDAP **static role** (`ldap/static-cred/<role>`) or an LDAP **library set** (`ldap/library/check-out/<set>`). The host pulls a fresh credential at connect time. For library check-out, `session.close` triggers a check-in (the same mutex the LDAP engine uses today guarantees no parallel session double-uses the account).

In both cases the LDAP mount must already be configured on this BastionVault instance — the binding stores `ldap_mount = "openldap/"` plus either `bind_mode = "operator"` or `static_role = "..."` / `library_set = "..."`.

#### `ssh-engine` — vault-issued SSH credential

The resource binds to one of:

- An SSH **CA-signing role** (`ssh/roles/<role>` configured for `cert` mode). At connect time the host calls `ssh/sign/<role>` with the operator's local SSH public key (read from the keystore the GUI manages on the workstation), gets back a signed user cert, and feeds the (key, cert) pair to `russh` for cert-based auth.
- An SSH **OTP role** (`ssh/roles/<role>` configured for `otp` mode). At connect time the host requests a one-shot password via `ssh/creds/<role>`, then drives a password-auth login. The target's `bv-ssh-helper` (already shipped, Phase 2 of the SSH engine) consumes it once.
- An SSH **PQC CA role** (`ssh/sign-pqc/<role>`). Same as the CA mode but with ML-DSA-65 cert / signing key — for environments cutting their SSH PKI over to PQC.

The resource binding stores `ssh_mount = "ssh/"`, `ssh_role = "admins"`, and the mode (`ca` / `otp` / `pqc`). No credential is persisted on the resource — the role binding is.

#### `pki` — vault-issued client X.509

The resource binds to a **PKI role** (`pki/issue/<role>`). At connect time the host calls `pki/issue/<role>` with the resource hostname as the requested CN/SAN, gets back a fresh cert + key + chain, and feeds them to:

- **SSH** with `russh`'s certificate-auth path (the host SSH server must be configured to accept x509 certs — uncommon, but supported by `lsh` / Tectia / patched OpenSSH). Niche; we ship the plumbing without making it the default UX.
- **RDP** as the smartcard-style cert for CredSSP. The host wraps the issued cert in a synthetic smartcard via `ironrdp`'s `cred_ssp` module so an AD-integrated Windows host accepts it the same way it accepts a PIV smartcard. **This is the headline use case for `pki`** — short-lived AD smartcard auth without a hardware token.

The resource binding stores `pki_mount = "pki/"`, `pki_role = "ad-smartcard"`, and the cert TTL (clamped by the role's `max_ttl`). The cert is destroyed in-process on session close — the issued serial appears on the engine's normal CRL only if the operator force-revokes via `pki/revoke`.

### Configuring the credential source on the resource

The resource detail page gets a new **Connection** tab (alongside the existing Info / Secrets / History / Sharing tabs) that lets the operator define one or more **connection profiles** for the resource. Each profile is the bound (protocol, target, credential-source) tuple the Connect button uses.

```
┌─ Connection profiles ──────────────────────────┐
│                                                │
│  ▸ Default                       SSH    [Edit] │
│      target  : 10.0.1.50:22                    │
│      user    : felipe                          │
│      cred    : SSH engine • role=admins (CA)   │
│                                                │
│  ▸ Break-glass                   SSH    [Edit] │
│      target  : 10.0.1.50:22                    │
│      user    : root                            │
│      cred    : Resource secret • root-password │
│                                                │
│  + Add connection profile                      │
└────────────────────────────────────────────────┘
```

The Connect button's behaviour follows from the profile list:

- **Zero profiles, but a credential-shaped secret exists on the resource** → Connect uses that secret with `username` / `password` defaults, and the GUI offers a one-click "Save as default profile" prompt after first use.
- **One profile** → Connect runs it directly (no picker).
- **Two or more profiles** → Connect drops a small dropdown (Default / Break-glass / …); operator picks one, GUI launches.
- **No profiles and no credential-shaped secret** → Connect button disabled with a tooltip pointing to the Connection tab.

Each profile is an editor over this struct:

```rust
pub struct ConnectionProfile {
    pub id: String,                              // stable per-resource id
    pub name: String,                            // operator-visible label, e.g. "Default", "Break-glass"
    pub protocol: SessionProtocol,               // ssh | rdp — pre-filled from os_type but overridable
    pub target_host: Option<String>,             // overrides the resource's hostname/ip when set
    pub target_port: Option<u16>,                // overrides the resource's port / protocol default
    pub username: Option<String>,                // ssh user / rdp user; some sources supply their own
    pub credential_source: CredentialSource,     // see below — the four kinds
    pub host_key_pin: Option<HostKeyPin>,        // TOFU pin (SSH host key fingerprint, RDP cert thumbprint)
    pub allow_legacy_auth: bool,                 // opt-in, logged at WARN every connect
}

pub enum CredentialSource {
    Secret {
        secret_id: String,                       // points at a credential-shaped resource secret
    },
    Ldap {
        ldap_mount: String,                      // e.g. "openldap/"
        bind_mode: LdapBindMode,                 // operator | static_role | library_set
        static_role: Option<String>,
        library_set: Option<String>,
    },
    SshEngine {
        ssh_mount: String,                       // e.g. "ssh/"
        ssh_role: String,                        // role in CA / OTP / PQC mode
        mode: SshEngineMode,                     // ca | otp | pqc
    },
    Pki {
        pki_mount: String,                       // e.g. "pki/"
        pki_role: String,
        cert_ttl_secs: Option<u64>,              // clamped by the role's max_ttl
    },
}

pub enum SessionProtocol { Ssh, Rdp }
pub enum LdapBindMode    { Operator, StaticRole, LibrarySet }
pub enum SshEngineMode   { Ca, Otp, Pqc }
```

Profiles persist on the resource record itself, under a new `connection_profiles: Vec<ConnectionProfile>` field. No new storage engine — the resource module already serializes its `data: Map<String, Value>`. A schema-version bump on `ResourceMeta` is the only migration step.

Each `CredentialSource` editor in the GUI is a small dedicated panel:

- **Secret** → dropdown of credential-shaped secrets on this resource; "+ New credential" launches the credential-secret editor inline.
- **LDAP** → dropdown of mounted LDAP engines; sub-radio for bind mode; if `static_role` / `library_set`, a dropdown of available roles / sets fetched from that mount.
- **SSH engine** → dropdown of mounted SSH engines; dropdown of roles; mode pre-filled from the role's configured mode.
- **PKI** → dropdown of mounted PKI engines; dropdown of roles; optional TTL override.

Validation runs on save: the resource must reach the bound mount via the operator's policies, and the bound role must exist. Failing validation produces an explicit "you can save this profile but it won't work because…" warning rather than a silent broken state at connect time.

### Resource detail — Connect button

In [gui/src/routes/ResourcesPage.tsx](../gui/src/routes/ResourcesPage.tsx), the detail view's header gets a primary `Connect` button when:

- `resource.type === "server"`, AND
- `resource.fields.os_type` is set, AND
- the matching protocol is `linux | macos | bsd | unix` → SSH, or `windows` → RDP, AND
- the resource-type's `connect.enabled !== false`.

Clicking either runs the only profile (single-profile case) or pops a small profile picker (multi-profile case). The picker carries no editable fields — every detail (target / user / credential) was bound on the Connection tab; the operator confirms with one click.

For the LDAP **operator-supplied bind** mode the picker also shows a small inline LDAP credential prompt (the operator types domain user + password; the host bind-validates against the mount before the protocol session opens).

On confirm, the GUI calls a new Tauri command (`session_open_ssh` / `session_open_rdp`) with the chosen `connection_profile_id`. The command:

1. Loads the profile from the resource record.
2. Resolves the `CredentialSource` — pulls the secret / runs the LDAP bind / signs the SSH cert / issues the PKI cert. All work is host-side; no plaintext credential ever crosses the IPC boundary into the JS layer.
3. Spawns a new `tauri::WebviewWindow` pointing at `/session/ssh/<token>` or `/session/rdp/<token>`.
4. Returns a one-shot in-process token the new window uses to claim its session handle from the host.

The session window UI is its own React route loaded into the new WebviewWindow. The credential never travels to the JS side — only the in-process token does.

### SSH session window

```
┌──────────────────────────────────────────────────┐
│  ssh felipe@web01.example.com  [Disconnect]      │
├──────────────────────────────────────────────────┤
│                                                  │
│   xterm.js terminal                              │
│   reads/writes via ipc to the Tauri host         │
│                                                  │
└──────────────────────────────────────────────────┘
```

- **Frontend**: `xterm.js` (MIT, ~140 KiB gzipped, the de-facto standard) + `xterm-addon-fit` for resize.
- **Backend**: pure-Rust `russh` 0.45 (BSD-2-Clause; the maintained fork of `thrussh`) drives the SSH protocol. Pulls in `russh-keys` for parsing the resource's stored key. Already TLS-free (SSH transport is its own protocol), no rustls-vs-aws-lc concerns.
- **PTY**: `russh::ChannelMsg::Data` events stream stdout into the terminal; the terminal's `onData` callback streams back into the channel. Resize events become `ChannelMsg::WindowChange`.
- **IPC shape**: a Tauri `Channel<Bytes>` per direction (host→front for stdout, front→host for stdin), plus a small command set: `session_resize`, `session_close`. Not raw events — channels keep the binary stream tight.
- **Auth**:
  - `ssh-key` secret → `russh_keys::PrivateKeyWithHashAlg` → `client.authenticate_publickey`.
  - `root-password` (or any password-typed secret) → `client.authenticate_password`.
  - **Future**: integrate with the SSH secret engine's OTP / CA modes — the GUI calls `pki/sign/<role>` first, gets a fresh signed cert, hands it to `russh` as the auth credential.
- **Host-key verification**: persisted at `resource/<name>/known_hosts` on the resource record itself, prompted on first connect and pinned thereafter (TOFU model identical to OpenSSH). Operator can clear / re-pin via the resource detail page.

### RDP session window

```
┌──────────────────────────────────────────────────┐
│  rdp:Administrator@10.0.1.50  [Disconnect]      │
├──────────────────────────────────────────────────┤
│                                                  │
│   <canvas> rendering bitmap deltas               │
│                                                  │
│                                                  │
└──────────────────────────────────────────────────┘
```

- **Frontend**: HTML5 `<canvas>` + a small TypeScript event loop. Receives bitmap-update messages over a Tauri `Channel<Bytes>`, forwards keyboard / mouse events back over a second channel. No third-party RDP-in-browser library needed (avoid xrdp-html, FreeRDP-WebSocket, etc.; we own the wire from the host).
- **Backend**: [`ironrdp`](https://github.com/Devolutions/IronRDP) (Devolutions, MIT/Apache-2.0). Pure Rust, actively maintained, used in Devolutions Gateway. Implements the RDP wire protocol up through bitmap codecs (RDP 6.x bitmap, RemoteFX), CredSSP/NLA auth, and the GFX/EGFX redirection.
- **Auth**:
  - Password → CredSSP (NLA) is the modern default. ironrdp's `connector` module handles the negotiation.
  - **Out of scope for v1**: smartcard auth, certificate auth, RD Gateway. v1 targets direct LAN-style connections; gateway support is a follow-on.
- **Cert/TLS verification**: TOFU on first connect, pinned on the resource record (mirroring the SSH known_hosts pattern). RDP servers are commonly self-signed; refusing them out of the gate would be unusable, but pinning ensures a future MITM is detected.
- **Performance**: bitmap deltas are the chokepoint. We rely on ironrdp's existing codec support; canvas updates are `putImageData(...)` against the dirty rect. 1080p sessions at LAN latency target 30 fps; the bottleneck in early benchmarks is canvas paint, not protocol.

### Tauri command surface (new)

```rust
// gui/src-tauri/src/commands/session.rs

#[tauri::command]
async fn session_open_ssh(
    state: State<'_, AppState>,
    app: AppHandle,
    args: SessionSshArgs,
) -> CmdResult<SessionHandle>;

#[tauri::command]
async fn session_open_rdp(
    state: State<'_, AppState>,
    app: AppHandle,
    args: SessionRdpArgs,
) -> CmdResult<SessionHandle>;

#[tauri::command]
async fn session_input(state: State<'_, AppState>, token: String, bytes: Vec<u8>) -> CmdResult<()>;

#[tauri::command]
async fn session_resize(state: State<'_, AppState>, token: String, cols: u16, rows: u16) -> CmdResult<()>;

#[tauri::command]
async fn session_close(state: State<'_, AppState>, token: String) -> CmdResult<()>;

struct SessionHandle {
    /// Random one-shot token the spawned window uses to claim its
    /// session. The actual session state lives on AppState behind
    /// this token.
    pub token: String,
    /// Window label for the WebviewWindow that was opened.
    pub window_label: String,
}
```

The session lifecycle lives entirely on the Rust side; the JS layer holds nothing but the token.

### `AppState` extension

```rust
pub struct AppState {
    // ...existing fields...
    pub sessions: Arc<Mutex<HashMap<String /* token */, SessionState>>>,
}

enum SessionState {
    Ssh(SshSession),   // wraps russh::client::Handle + the two Channel<Bytes> ends
    Rdp(RdpSession),   // wraps ironrdp's connection state + bitmap channel
}
```

Sessions are dropped when the WebviewWindow closes (a `WindowEvent::CloseRequested` listener emits `session_close`).

### Audit events

A new audit event family `session`:

```json
{
  "type": "session",
  "event": "open" | "close" | "open_failed",
  "session_id": "...",
  "protocol": "ssh" | "rdp",
  "resource": "web01.example.com",
  "resource_type": "server",
  "os_type": "linux",
  "target_host": "10.0.1.50",
  "target_port": 22,
  "target_user": "felipe",
  "credential_source": "resource:web01/ssh-key",
  "actor": { "entity_id": "...", "display_name": "..." },
  "duration_ms": 32418,                 // close only
  "exit": "user_disconnected" | "remote_eof" | "auth_failed" | "timeout"
}
```

Same HMAC-redaction policy as other audit events; the credential bytes themselves never appear here, only the source path of the secret used.

### Resource-type config — new `connect` block

```ts
export interface ResourceTypeDef {
  id: string;
  label: string;
  color: "info" | "success" | "warning" | "error" | "neutral";
  fields: ResourceFieldDef[];
  /** New: per-type session-launch policy. Optional — omitted = enabled. */
  connect?: {
    enabled?: boolean;
    /** Default port per OS type when the resource doesn't pin one. */
    default_ports?: { ssh?: number; rdp?: number };
    /** Default username per OS type. */
    default_users?: { linux?: string; macos?: string; windows?: string };
  };
}
```

Settings page gets a per-type toggle so a regulated environment can disable Connect globally without touching individual resources.

### Module / file layout

```
gui/src-tauri/src/commands/session.rs    -- Tauri command set above
gui/src-tauri/src/session/
├── mod.rs                               -- AppState integration
├── ssh.rs                               -- russh wrapper, channel plumbing
├── rdp.rs                               -- ironrdp wrapper, bitmap channel
├── known_hosts.rs                       -- TOFU pin store, persisted on the resource record
└── audit.rs                             -- session.* event emitter

gui/src/routes/SessionSshWindow.tsx      -- xterm.js + Tauri channel glue
gui/src/routes/SessionRdpWindow.tsx      -- canvas + Tauri channel glue
gui/src/components/ConnectDialog.tsx     -- pre-launch dialog (host/port/user/cred)
gui/src/components/ResourceConnectButton.tsx -- the button itself, wired into ResourcesPage
gui/src/lib/sessionApi.ts                -- thin wrappers around the new Tauri commands
```

## Phases

### Phase 1 — `os_type` field + schema plumbing — **Done**

| Deliverable | Location |
|---|---|
| `select` field type added to `ResourceFieldDef` | [gui/src/lib/types.ts](../gui/src/lib/types.ts) |
| `os_type` added to default `server` resource type | [gui/src/lib/resourceTypes.ts](../gui/src/lib/resourceTypes.ts) |
| Resource editor renders `select` as a `<select>` element | [gui/src/routes/ResourcesPage.tsx](../gui/src/routes/ResourcesPage.tsx) |
| Settings page exposes the same on custom types | [gui/src/routes/SettingsPage.tsx](../gui/src/routes/SettingsPage.tsx) |
| Migration heuristic: pre-fill `os_type` from `os` | edit modal |
| Vitest coverage for the new field shape and edit-modal pre-fill | `gui/src/test/` |

No backend changes — resource fields are already a flexible `Map<String, Value>` on the storage record. Phase 1 is GUI-only and ships first because it unlocks everything else without committing to the session implementation.

### Phase 2 — Connection profiles + Connection tab + `secret` credential source — **Done**

| Deliverable | Location |
|---|---|
| `ConnectionProfile` + `CredentialSource` storage shape on the resource record | `src/modules/resource/mod.rs` |
| `ResourceSecretShape` detection (credential-shaped vs. kv-shaped) | `gui/src/lib/types.ts` |
| Credential-secret editor (username / masked password / paste-PEM private key) | `gui/src/components/CredentialSecretEditor.tsx` |
| New **Connection** tab on the resource detail page | `gui/src/routes/ResourcesPage.tsx` |
| Profile editor with the `secret` source enabled (other sources stubbed for Phases 3-5) | `gui/src/components/ConnectionProfileEditor.tsx` |
| Profile validation on save (mount + role reachable under operator's policies) | host + GUI |
| Vitest coverage for the profile editor and the secret-shape detection | `gui/src/test/` |

### Phase 3 — SSH session window + `secret` source — **Done** (`ssh-engine` source deferred to a follow-up alongside Phases 5/6)

| Deliverable | Location |
|---|---|
| `russh = "0.45"` + `russh-keys` deps | [gui/src-tauri/Cargo.toml](../gui/src-tauri/Cargo.toml) |
| `xterm` + `xterm-addon-fit` deps | [gui/package.json](../gui/package.json) |
| `gui/src-tauri/src/session/{mod,ssh,known_hosts,audit}.rs` | new files |
| `session_open_ssh`, `session_input`, `session_resize`, `session_close` Tauri commands | `gui/src-tauri/src/commands/session.rs` |
| Credential resolver: `secret` (password / private_key) and `ssh-engine` (CA / OTP / PQC) | `gui/src-tauri/src/session/credential.rs` |
| `SessionSshWindow.tsx` route | `gui/src/routes/` |
| `ResourceConnectButton.tsx` + multi-profile picker | `gui/src/components/` |
| `session.open` / `session.close` audit events with `credential_source` | `gui/src-tauri/src/session/audit.rs` |
| Integration test against an OpenSSH server in Docker (testcontainers): one round-trip per source kind (`secret/password`, `secret/private_key`, `ssh-engine/ca`, `ssh-engine/otp`) | `gui/src-tauri/tests/` |

### Phase 4 — RDP session window + `secret` source — **Done** (Standard Security; NLA / CredSSP deferred to Phase 6)

| Deliverable | Location |
|---|---|
| `ironrdp` family of crates (`ironrdp-connector`, `ironrdp-pdu`, `ironrdp-graphics`) | [gui/src-tauri/Cargo.toml](../gui/src-tauri/Cargo.toml) |
| `gui/src-tauri/src/session/rdp.rs` | new file |
| `session_open_rdp` Tauri command + bitmap-stream channel | `gui/src-tauri/src/commands/session.rs` |
| `SessionRdpWindow.tsx` route — canvas, key/mouse capture | `gui/src/routes/` |
| Profile editor extended for RDP-compatible sources only | `gui/src/components/ConnectionProfileEditor.tsx` |
| TOFU cert-pin UI shared with SSH known_hosts | `gui/src/components/` |
| Integration test against a Windows Server 2019 / 2022 RDP server (manual; no testcontainer for Windows) | docs |

### Phase 5 — `ldap` credential source (operator-bind + LDAP-engine static / library) — **Done**

| Deliverable | Location |
|---|---|
| Credential resolver: `ldap` source — operator-bind mode (LDAP simple-bind via existing client), static-role mode (calls `ldap/static-cred/<role>`), library-set mode (calls `ldap/library/check-out/<set>` + paired check-in on `session.close`) | `gui/src-tauri/src/session/credential.rs` |
| Inline LDAP credential prompt for operator-bind mode | `gui/src/components/ConnectDialog.tsx` |
| Profile editor extended with the LDAP source panel | `gui/src/components/ConnectionProfileEditor.tsx` |
| Library check-in tied to session close; double-use guard via the LDAP engine's existing per-set Mutex | host |
| Integration tests: bind succeeds → SSH/RDP succeeds; bind fails → no session opened, audit shows `open_failed`; library check-out + session-close → check-in observed in LDAP audit | `gui/src-tauri/tests/` |

### Phase 6 — `pki` credential source (AD smartcard-style RDP) — **Done** (SSH+PKI as Phase 6; RDP+PKI CredSSP smartcard as Phase 6.5)

| Deliverable | Location |
|---|---|
| Credential resolver: `pki` source — calls `pki/issue/<role>`, wraps the issued cert + key as a synthetic smartcard for `ironrdp`'s CredSSP path | `gui/src-tauri/src/session/credential.rs` |
| SSH cert-auth path through `russh` for the niche x509-SSH case (best-effort, no first-class UX) | `gui/src-tauri/src/session/ssh.rs` |
| Profile editor extended with the PKI source panel + TTL field | `gui/src/components/ConnectionProfileEditor.tsx` |
| Cert zeroized on session close (`Zeroizing<Vec<u8>>`); manual revoke via existing `pki/revoke` if the operator wants it on the CRL | host |
| Manual integration test against an AD-joined Windows Server with a CA template-mapped issuer | docs |

### Phase 7 — Polish & per-type policy

| Deliverable | Location |
|---|---|
| `connect` block on `ResourceTypeDef` | [gui/src/lib/types.ts](../gui/src/lib/types.ts) |
| Settings page toggle: enable/disable Connect per resource type | [gui/src/routes/SettingsPage.tsx](../gui/src/routes/SettingsPage.tsx) |
| Recently-connected list per resource (last 10 sessions, op + timestamp) | resource detail page |
| Hot-key (`⌘K`) "Connect to…" command palette | new component |

### Phase 8 — Future / deferred

- Session recording (keystroke + bitmap capture; storage tier; replay viewer).
- SFTP file panel attached to an SSH session.
- Multi-hop via a designated bastion resource.
- Smartcard / certificate auth for RDP.
- RD Gateway / SSH ProxyJump support.
- VNC.

## Dependencies (planned)

| Crate / package | Purpose | Phase |
|---|---|---|
| `russh = "0.45"` | Pure-Rust SSH client | 2 |
| `russh-keys = "0.45"` | SSH key parsing + agent | 2 |
| `xterm` (npm) | Terminal renderer | 2 |
| `xterm-addon-fit` (npm) | Auto-resize | 2 |
| `ironrdp-connector` | RDP connection negotiation | 3 |
| `ironrdp-pdu` | RDP PDU codec | 3 |
| `ironrdp-graphics` | Bitmap codec | 3 |

No new C-linked deps. No OpenSSL. No `aws-lc-sys`. (rustls is already in tree; ironrdp uses it for CredSSP TLS.)

## Security Considerations

- **Credentials never reach JavaScript.** The GUI front-end never sees the SSH key bytes or the RDP password — it gets a session token and the host pulls the credential out of barrier-encrypted storage to feed the protocol library directly. The credential's only out-of-vault landing site is the SSH/RDP session protocol itself.
- **TOFU host-key / cert pinning** mirrors OpenSSH's known_hosts model. First connect prompts the operator with the fingerprint; pin is persisted on the resource record. Subsequent connects with a changed key warn (and refuse, by default) — operator can clear the pin if they expect a server reinstall.
- **Audit completeness.** Every Connect produces a paired `session.open` / `session.close` event. A missing close event is itself an audit signal. The credential bytes are never in the event — only the *source path* of the secret used.
- **Per-type opt-out** (`connect.enabled = false`) lets a regulated environment ship the resource layer without the launch surface — operators in those environments still authenticate with the credentials but through whatever PAM tool they're already using.
- **No clipboard handoff.** The credential never goes through `navigator.clipboard`. Window-side keyboard input is forwarded straight to the protocol channel — the operator's local clipboard is never populated by us with the session credential.
- **Window isolation.** Each session window is a separate Tauri WebviewWindow with its own isolated WebView context. A compromise of the resources list page can't reach into a running session window's memory.
- **Session credential lifetime.** Pulled into RAM on connect, cleared on disconnect. The host wraps it in `Zeroizing<Vec<u8>>` so a panic / crash dump doesn't preserve plaintext.
- **Refuse insecure-by-default.** SSH refuses `none` auth and the obsolete `ssh-rsa` host key. RDP refuses standard RDP encryption (no NLA) by default; operators can opt in per-resource for legacy hosts via an explicit `allow_legacy_rdp_auth = true` resource flag, logged at WARN every connect.
- **Bitmap data does NOT cross the audit boundary.** A real PAM product records video; we do not (Phase 5). This is documented so a SOC doesn't expect to find session video in audit logs and discover the gap during an incident.
- **Network egress allow-listing.** The Connect path opens an outbound TCP connection from the operator's workstation to the target. In environments that gate workstation egress, the operator's existing firewall rules apply unchanged — there's no proxy / tunnel built into v1.
- **Process isolation between sessions.** Each session lives on its own Tokio task; a panic in one doesn't take down the GUI host (we already use `catch_unwind` around the long-running task spawn pattern).

## Testing Plan

### Unit tests

- `os_type` field renders as `<select>` and persists the value (vitest, with the existing resource-page test scaffolding).
- Migration heuristic: "Ubuntu 22.04" → `linux`, "Windows Server 2022" → `windows`, "macOS Sequoia" → `macos`, unknown → `other`.
- TOFU pin store: first-connect persists; second-connect with same key passes; second-connect with changed key refuses; clear-pin allows new pin.
- Audit emitter shape, with HMAC redaction on identity fields.

### Integration tests

- **SSH**: spin up `linuxserver/openssh-server` via testcontainers, connect via the same code path the Tauri command uses, verify a `pwd` command round-trips through the channel.
- **SSH**: deliberately wrong key → `auth_failed` audit event with no `session.open` paired event.
- **SSH**: server changes host key mid-flow → `session.close` with `exit: host_key_changed`.
- **RDP**: out of CI (no Windows testcontainer); manual against a Windows Server 2019 VM with a documented checklist before each release. Smoke test in CI uses `ironrdp`'s own protocol-replay tests.

### Cucumber BDD scenarios

- Operator opens a Linux server resource, clicks Connect, picks the SSH key secret, sees the terminal, runs `whoami`, sees their target user.
- Operator opens a Windows server resource, clicks Connect, picks the password secret, sees the desktop, types into Notepad, sees the keystrokes appear.
- Operator opens a server resource without `os_type` set, sees a banner prompting them to set it, sets it to Linux, the Connect button appears.
- Admin disables Connect on the `server` resource type via Settings; the button disappears for every existing server resource.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" section.

## Notes on alternatives considered

- **Shell out to `ssh` / `mstsc.exe` / Microsoft Remote Desktop.** Considered and rejected: the credential would have to land on the operator's filesystem (SSH key file) or in `mstsc /v` arguments (ps-listable). The whole point of the feature is to avoid that landing.
- **Embed `xterm.js` + a serial PTY into a host shell rather than russh.** That's `tmux` over a remote shell, not an SSH client — gives away the key-handling, audit, and known_hosts hooks the in-process `russh` integration provides for free.
- **Use `webrdp` (RDP-in-browser)** rather than ironrdp + canvas. Adds a JavaScript RDP stack we'd have to audit, ships ~1.5 MiB of WASM, and routes credentials through the JS layer — the wrong shape for our security posture.
- **Make Connect a separate "remote-access" submenu rather than a button on the resource.** The button-on-resource shape is what every operator who's used a PAM product (CyberArk, Delinea, BeyondTrust, JumpCloud) expects; deviating raises the learning curve for no gain.
