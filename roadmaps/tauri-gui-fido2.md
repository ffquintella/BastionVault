# BastionVault Tauri GUI with FIDO2/YubiKey Support

## Goal

Build a cross-platform desktop GUI (Tauri v2 + React + TypeScript) that provides full vault management, user administration, FIDO2/YubiKey authentication, and machine auth (AppRole) dashboard. The GUI supports both an embedded local server for single-user desktop mode and remote connections to existing BastionVault instances.

## Status: Todo

## Architecture

### Dual Mode

| Mode | Description |
|------|-------------|
| **Embedded** | In-process `BastionVault` instance — no HTTP server, direct Rust calls, `FileBackend` at `~/.bastion_vault_gui/data/`, auto-init with single unseal key stored in OS keychain |
| **Remote** | Connects to an existing BastionVault server via the `Client` at `src/api/client.rs`, supports TLS and mTLS, multiple server profiles |

All Tauri commands branch on the active mode to dispatch through either the library API or the HTTP client, unified behind a common dispatch layer.

### Project Structure

```
gui/
├── src-tauri/                  # Tauri Rust backend
│   ├── Cargo.toml              # Depends on bastion_vault = { path = "../.." }
│   ├── tauri.conf.json
│   ├── capabilities/default.json
│   └── src/
│       ├── main.rs / lib.rs
│       ├── commands/           # Tauri invoke handlers
│       │   ├── connection.rs   # Embedded/remote mode switching
│       │   ├── auth.rs         # Login (userpass, token, fido2)
│       │   ├── secrets.rs      # KV read/write/delete/list
│       │   ├── system.rs       # Init, seal, unseal, status, mounts
│       │   ├── users.rs        # UserPass user CRUD
│       │   ├── approle.rs      # AppRole management
│       │   └── fido2.rs        # FIDO2 key registration/management
│       ├── embedded/           # In-process BastionVault lifecycle
│       ├── state.rs            # AppState (mode, vault, client, token)
│       ├── secure_store.rs     # OS keychain wrapper (keyring crate)
│       └── error.rs
├── src/                        # React frontend
│   ├── routes/                 # Page components
│   ├── components/             # Reusable UI
│   ├── hooks/                  # useVaultApi, useAuth, useWebAuthn
│   ├── lib/                    # api.ts (typed invoke wrappers), types.ts
│   └── stores/                 # Zustand state management
├── package.json
├── vite.config.ts
└── tailwind.config.js
```

### Frontend Stack

- React 19, TypeScript 5.5, Vite 6
- Tailwind CSS 4, Radix UI primitives
- Zustand 5 for state, @tanstack/react-query v5 for server data
- CodeMirror 6 for policy editor (HCL/JSON)
- Lucide React for icons

## FIDO2 / WebAuthn Server Module

A new credential backend at `src/modules/credential/fido2/` implementing the standard BastionVault module pattern (ref: `AppRoleModule`, `UserPassModule`).

### Dependencies

```toml
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
webauthn-rs-proto = "0.5"
```

### Module Files

```
src/modules/credential/fido2/
├── mod.rs              # Fido2Module, Fido2Backend (Module trait impl)
├── path_register.rs    # POST register/begin, POST register/complete
├── path_login.rs       # POST login/begin, POST login/complete
├── path_credentials.rs # LIST/GET/DELETE credentials/{user}/{id}
└── types.rs            # Serializable WebAuthn types
```

### API Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /v1/auth/fido2/config` | Admin | Set relying party ID and origin |
| `POST /v1/auth/fido2/register/begin` | Yes | Start WebAuthn registration ceremony |
| `POST /v1/auth/fido2/register/complete` | Yes | Complete registration, store credential |
| `POST /v1/auth/fido2/login/begin` | No | Start WebAuthn authentication challenge |
| `POST /v1/auth/fido2/login/complete` | No | Verify assertion, issue vault token |
| `LIST /v1/auth/fido2/credentials/{user}` | Yes | List registered security keys |
| `DELETE /v1/auth/fido2/credentials/{user}/{id}` | Yes | Remove a security key |

### Authentication Flow

1. **Registration** (authenticated, 2-step): Client calls `register/begin` → server returns `PublicKeyCredentialCreationOptions` → browser calls `navigator.credentials.create()` → client sends result to `register/complete` → server stores public key credential.
2. **Login** (unauthenticated, 2-step): Client calls `login/begin` → server returns `PublicKeyCredentialRequestOptions` → browser calls `navigator.credentials.get()` (user taps key) → client sends assertion to `login/complete` → server verifies and issues token with user's policies.
3. **Token issuance** follows the exact pattern from `userpass/path_login.rs`: construct `Auth` with lease, policies, metadata → token store creates client token.

### YubiKey Support

YubiKeys (5 series and later) implement FIDO2/CTAP2 and work as standard WebAuthn authenticators. No special handling beyond the standard WebAuthn API is required — the browser/OS handles USB HID communication with the key.

### Tauri WebAuthn Bridge

The Tauri webview provides `navigator.credentials` API. The frontend handles the browser-side WebAuthn ceremony while Tauri commands manage server-side begin/complete calls. For embedded mode, RP origin is `tauri://localhost` or `https://tauri.localhost`.

## GUI Screens

| Route | Purpose |
|-------|---------|
| `/connect` | Mode selector (embedded vs remote), server profile manager |
| `/login` | Tabbed login: Token, UserPass, FIDO2, AppRole |
| `/dashboard` | Seal status, mount overview, auth methods summary, token TTL |
| `/secrets/*` | Tree browser (lazy LIST) + key-value editor with masked values |
| `/users` | UserPass user list with create/edit/delete |
| `/approle` | AppRole list + detail: role-id copy, secret-id generation, usage stats |
| `/policies` | Policy list + HCL/JSON editor (CodeMirror) |
| `/fido2` | Registered keys table, "Register New Key" flow |
| `/mounts` | Secret engine management (enable/disable/move) |
| `/auth-methods` | Auth method enable/disable |
| `/settings` | Connection profiles, preferences |

## Embedded Mode Details

### Auto-Init (First Launch)

1. Create `FileBackend` at `~/.bastion_vault_gui/data/`
2. `BastionVault::new(backend, config)` with `BarrierType::Chacha20Poly1305`
3. `BastionVault::init(SealConfig { secret_shares: 1, secret_threshold: 1 })`
4. Store unseal key and root token in OS keychain via `keyring` crate
5. Auto-unseal

### Subsequent Launches

1. Instantiate `BastionVault::new(backend, config)`
2. Retrieve unseal key from OS keychain
3. `BastionVault::unseal(&[key])`

### Lifecycle

- Instance lives as long as the Tauri window
- `BastionVault::seal()` called on window close
- Data encrypted at rest by the barrier layer

## Security Considerations

| Concern | Approach |
|---------|----------|
| Token storage | OS keychain via `keyring` crate (macOS Keychain, Linux Secret Service, Windows Credential Manager) — never in plaintext files |
| TLS (remote mode) | `TLSConfigBuilder` from `src/api/client.rs`, CA certs in profile config, client cert keys in keychain |
| Embedded mode | No network exposure, all in-process Rust calls, data encrypted at rest |
| FIDO2 credentials | Server stores public keys in encrypted vault storage; private keys never leave the authenticator |
| WebAuthn challenges | Stored temporarily in vault storage, cleaned up after completion or timeout |

## Files Modified in Existing Codebase

| File | Change |
|------|--------|
| `Cargo.toml` | Add `gui/src-tauri` to workspace members, add `webauthn-rs` + `webauthn-rs-proto` dependencies |
| `src/modules/credential/mod.rs` | Add `pub mod fido2;` |
| `src/lib.rs` | Register `Fido2Module` in module initialization |
| `src/errors.rs` | Add FIDO2-specific error variants |

All other changes are new files: the `gui/` directory and `src/modules/credential/fido2/`.

## Implementation Phases

### Phase 1: GUI Scaffold
- Tauri v2 + React + Vite + Tailwind project in `gui/`
- Cargo workspace integration
- Basic routing shell

### Phase 2: Embedded Mode
- `state.rs`, `embedded/mod.rs`, `secure_store.rs`
- Auto-init, auto-unseal, seal on close

### Phase 3: Core Screens
- Login (userpass + token), Dashboard, Init wizard, Unseal form
- Tauri commands for connection, auth, system

### Phase 4: Secrets & Management
- Secrets tree browser + KV editor
- User management, policy editor (CodeMirror), mounts, auth methods

### Phase 5: AppRole Dashboard
- Role CRUD, role-id display with copy, secret-id generation
- Usage statistics and accessor management

### Phase 6: FIDO2 Server Module
- New credential backend at `src/modules/credential/fido2/`
- Registration and login paths with `webauthn-rs`
- Credential CRUD, module registration, integration tests

### Phase 7: FIDO2 GUI
- Key management page, browser WebAuthn integration
- FIDO2 login tab, registration flow

### Phase 8: Remote Mode
- Connection via `Client`, profile manager
- TLS configuration UI

### Phase 9: Polish & Packaging
- Error handling, loading states, responsive layout
- Tauri bundler config (.dmg, .msi, .AppImage)
- Cross-platform testing, CI/CD
