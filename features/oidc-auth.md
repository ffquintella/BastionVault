# Feature: OpenID Connect (OIDC) Authentication

## Summary

Add an OIDC authentication backend that allows users to authenticate with BastionVault using any OpenID Connect-compliant identity provider (Okta, Azure AD, Keycloak, Google, Auth0, etc.). The backend supports Authorization Code Flow with PKCE, configurable claim-to-policy role mappings, and automatic token issuance.

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

**OidcRoleEntry** (stored at `role/<name>`):
- `bound_audiences` -- allowed `aud` claim values
- `bound_claims` -- map of claim_name to allowed values for validation
- `claim_mappings` -- map of OIDC claim to vault token metadata key
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

### Token Renewal

The `login_renew` handler reloads the role to verify it still exists and policies haven't changed. If the role was deleted or policies differ, renewal fails.

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

## Key Reference Files

- `src/modules/credential/userpass/mod.rs` -- Module/Backend pattern
- `src/modules/credential/userpass/path_login.rs` -- login handler returning Auth
- `src/modules/credential/approle/mod.rs` -- complex backend with async init
- `src/logical/path.rs` -- `new_path!` macro
- `src/logical/backend.rs` -- `new_logical_backend!` macro
