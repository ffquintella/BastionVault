# Feature: OpenID Connect (OIDC) Authentication

## Summary

Add an OIDC authentication backend that allows users to authenticate with BastionVault using any OpenID Connect-compliant identity provider (Okta, Azure AD, Keycloak, Google, Auth0, etc.). The backend supports Authorization Code Flow with PKCE, configurable claim-to-policy role mappings, and automatic token issuance.

## Status

**Done (core feature).** All four phases shipped: `src/modules/credential/oidc/` module registered as `oidc` auth kind, provider config + role CRUD, `auth_url` with PKCE + state storage, `callback` with ID-token verification + claim validation + metadata mapping, token renewal. 17 unit tests + 1 end-to-end core-integration test green; live-IdP test `#[ignore]`d behind `BVAULT_TEST_OIDC_DISCOVERY` + `BVAULT_TEST_OIDC_CLIENT_ID` env vars. GUI wire-up (a login option + post-callback token reception) is a separate follow-up deliverable.

**Phase 5 (IdP trust anchors, T493) — done with caveats.** `oidc_discovery_ca_pem` on `config` adds operator-supplied CA certificates to the built-in roots of the client used for discovery, JWKS and the token exchange (now in `crates/bv-auth-oidc/src/http_client.rs`). Validated on write, stored normalised, returned on read; proven by a loopback TLS handshake that fails without the missing intermediate and passes with it, plus a whole-vault write/read/clear test. Not yet run against the production IdP that prompted it. The GUI's Add/Edit SSO Provider dialog does not expose the field yet (it does not send it either, so a GUI edit keeps a value set through the API or CLI).

## Motivation

BastionVault currently supports token, userpass, approle, and certificate authentication. Enterprise environments require SSO integration with centralized identity providers. OIDC is the modern standard for federated authentication, supported by virtually all major IdPs. Without OIDC support, organizations must manage vault-specific credentials separately from their existing identity infrastructure, increasing operational overhead and security risk.

## Design

### Dependencies

- `openidconnect` crate -- handles OIDC discovery, PKCE, token exchange, ID token verification, and JWKS fetching.

### Module Structure

```
src/modules/credential/oidc/
    mod.rs             # OidcModule + OidcBackend + OidcBackendInner
    path_config.rs     # Provider configuration CRUD
    path_roles.rs      # Role CRUD (claim-to-policy mappings)
    path_auth_url.rs   # Generate authorization URL with PKCE
    path_callback.rs   # Handle callback: exchange code, verify ID token, issue vault token
```

Follows the same Module/Backend pattern as `userpass` and `approle`.

### Registration

- `src/modules/credential/mod.rs` -- add `pub mod oidc;`
- `src/lib.rs` (~line 126) -- instantiate and register `OidcModule`

### Endpoints

| Path | Operations | Auth Required | Purpose |
|------|-----------|---------------|---------|
| `config` | Read, Write | Yes | Get/set OIDC provider configuration |
| `role/(?P<name>[\w-]+)` | Read, Write, Delete | Yes | CRUD for OIDC roles |
| `role/?` | List | Yes | List all role names |
| `auth_url` | Write | No | Generate authorization URL with PKCE |
| `callback` | Write | No | Exchange code, verify token, issue vault token |

### Data Structures

**OidcConfig** (stored at `config`):
- `oidc_discovery_url` -- e.g., `https://accounts.google.com/.well-known/openid-configuration`
- `oidc_client_id`
- `oidc_client_secret` -- encrypted at rest, redacted on read
- `default_role`
- `allowed_redirect_uris` -- whitelist of valid callback URIs
- `oidc_scopes` -- defaults to `["openid", "profile", "email"]`
- `oidc_discovery_ca_pem` -- extra CA certificate(s), PEM, trusted for the
  IdP calls in addition to the built-in roots; empty by default, and empty in
  configs written before the field existed. See "Extra CA certificates for the
  IdP" below

**OidcRoleEntry** (stored at `role/<name>`):
- `bound_audiences` -- allowed `aud` claim values
- `bound_claims` -- map of claim_name to allowed values for validation
- `claim_mappings` -- map of OIDC claim to vault token metadata key. The target
  key may not be one of the reserved, backend-owned keys (`spiffe_id`,
  `username`, `entity_id`, `mount_path`, `namespace_*`, `approle_env_*`, ...):
  the value comes from the IdP, and those keys are read back as authorization
  input. Write is refused; a mapping on a role stored before that check is
  dropped at login with a `security` warning. See `docs/authentication.md`
  § Reserved Token Metadata
- `user_claim` -- claim used for display_name (default: `sub`)
- `groups_claim` -- claim containing group membership list
- `oidc_scopes` -- role-specific additional scopes
- `allowed_redirect_uris` -- role-specific redirect URI whitelist
- `policies` -- vault policies to attach to the token
- `token_params` -- TTL, max_ttl, period, etc.

**OidcAuthState** (stored at `state/<state_param>`, short-lived):
- `role_name`, `redirect_uri`, `nonce`, `code_verifier` (PKCE), `created_at`

### Authentication Flow

1. **Initiate**: Client calls `POST auth/oidc/auth_url` with `{role, redirect_uri}`.
   - Validates redirect_uri against whitelist.
   - Generates PKCE code_verifier + code_challenge.
   - Generates random nonce and state parameter.
   - Stores `OidcAuthState` in backend storage (5 min TTL).
   - Returns `{auth_url}` pointing to the IdP authorization endpoint.

2. **Authenticate**: User authenticates at the IdP in their browser and is redirected back with an authorization code.

3. **Complete**: Client calls `POST auth/oidc/callback` with `{state, code}`.
   - Loads and deletes `OidcAuthState` from storage (single-use).
   - Validates state has not expired.
   - Exchanges authorization code for tokens using the PKCE code_verifier.
   - Verifies ID token (signature via JWKS, issuer, audience, nonce, expiry).
   - Extracts claims from ID token.
   - Loads role, validates `bound_claims` and `bound_audiences`.
   - Maps claims to token metadata via `claim_mappings`.
   - Returns `Response { auth }` with role policies -- TokenStore issues the vault token.

### Extra CA certificates for the IdP (`oidc_discovery_ca_pem`)

The HTTP client that fetches the discovery document and JWKS and exchanges the
authorization code trusts only the built-in webpki (Mozilla) roots — not the
host's trust store. Two setups fail against it with
`oidc: discovery: ... invalid peer certificate: UnknownIssuer`:

- the IdP serves only its leaf certificate and omits the intermediate that
  issued it (browsers often hide this by fetching or caching the intermediate);
- the IdP's certificate chains to a private or corporate CA.

`oidc_discovery_ca_pem` (the field Vault uses for the same purpose) takes one or
more PEM `CERTIFICATE` blocks that are **added** to the built-in roots for that
mount's IdP calls. It never replaces them, and certificate and hostname
verification stay on. Paste the certificate that issued the IdP's leaf (the
missing intermediate) or the private root. The IdP's leaf itself does not
help: the write accepts it, but verification never uses a server's own
certificate as its anchor. To find the missing intermediate:

~~~bash
# What the IdP actually sends (one certificate = the intermediate is missing)
openssl s_client -connect idp.example.com:443 -servername idp.example.com -showcerts </dev/null
# The leaf names its issuer's download URL under "CA Issuers"
openssl s_client -connect idp.example.com:443 -servername idp.example.com </dev/null \
  | openssl x509 -noout -text | grep -A1 "Authority Information Access"
curl -o issuer.crt <CA Issuers URL>
openssl x509 -inform DER -in issuer.crt -out issuer.pem   # skip if already PEM
bvault write auth/oidc/config oidc_discovery_ca_pem=@issuer.pem
~~~

Rules, enforced on write (a refused write changes nothing):

- 1 to 8 `CERTIFICATE` blocks, at most 64 KiB of text, each an X.509
  certificate the TLS stack accepts as a trust anchor;
- a private-key block (any `... PRIVATE KEY` label) or any other PEM block is
  refused, and the error never quotes the input;
- text outside the blocks (comments, `openssl` banners) is dropped: the stored
  value is the certificate blocks alone, LF line endings, in input order;
- omitting the field keeps the stored value, an empty string clears it.

The value is public certificate material and is returned as stored on
`GET config`; the client secret stays redacted. The client is built per call,
so one mount's anchors never reach another mount or any other HTTP client. A
stored value that no longer parses fails the login explicitly instead of
falling back to a client without it.

### Token Renewal

The `login_renew` handler reloads the role to verify it still exists and policies haven't changed. If the role was deleted or policies differ, renewal fails.

### Redirect-URI hints (GUI, cluster-aware)

The Add/Edit SSO Provider dialog surfaces the callback URL(s) to register with the IdP via the `sso_admin_callback_hints` Tauri command:

- **Embedded (desktop) OIDC** — RFC 8252 loopback (`http://127.0.0.1/callback`, any port); the GUI binds a random loopback port per login and never uses a server-side callback.
- **Remote, single node** (discovery disabled or literal-URL profile) — one stable `https://<node>/v1/auth/<mount>/callback`.
- **Remote, clustered** — resolves the cluster's SRV records and probes each node's `/v1/sys/health` (reusing `bv_client::discovery::resolve` → `health::probe_all`), then returns **every** per-node callback URL (`nodes[]`) with live availability plus the `selected` node a login started now would complete on. All URLs must be registered with the IdP; because the OIDC transaction state (nonce/PKCE verifier/`redirect_uri`) is persisted through the replicated store (`req.storage_put` → Hiqlite Raft), any available node completes the callback — no load balancer required. The dialog renders availability dots, an "active" badge on the selected node, and "Copy all" / "Use all" affordances. The hint fetch is debounced (400 ms) because it performs DNS + health I/O.

## Implementation Phases

### Phase 1: Scaffolding
- Add `openidconnect` to `Cargo.toml`.
- Create module structure, bare Module + Backend structs.
- Register in `src/lib.rs`.
- Verify compilation.

### Phase 2: Config and Roles
- Implement `path_config.rs` -- config read/write to storage.
- Implement `path_roles.rs` -- role CRUD and list.

### Phase 3: Auth Flow
- Implement `path_auth_url.rs` -- authorization URL generation with PKCE.
- Implement `path_callback.rs` -- code exchange, ID token verification, claim validation, Auth construction.
- Wire all paths into `new_backend()`.

### Phase 4: Tests
- Unit tests for config/role CRUD.
- Integration tests with mocked IdP responses.

### Phase 5: IdP trust anchors (T493) — done with caveats
- `oidc_discovery_ca_pem` on `config`: validated, normalised, returned on read,
  added to the built-in roots of the discovery / JWKS / token-exchange client.
- Discovery errors carry their cause chain (the TLS error) instead of
  `Request failed`.
- Tests: validation and normalisation, read-old (config without the field),
  real loopback TLS handshakes (missing intermediate refused without the field
  and accepted with it; hostname mismatch still refused), whole-vault
  write/read/keep/clear.
- Not done: the GUI SSO dialog field; a run against the production IdP.

## Key Reference Files

- `src/modules/credential/userpass/mod.rs` -- Module/Backend pattern
- `src/modules/credential/userpass/path_login.rs` -- login handler returning Auth
- `src/modules/credential/approle/mod.rs` -- complex backend with async init
- `crates/bv-logical/src/path.rs` -- `new_path!` macro
- `crates/bv-logical/src/backend.rs` -- `new_logical_backend!` macro
