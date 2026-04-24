# Feature: SAML 2.0 Authentication

## Summary

Add a SAML 2.0 authentication backend that allows users to authenticate with BastionVault via SP-initiated Single Sign-On. The backend supports configurable attribute-to-policy role mappings, XML signature verification, and integration with any SAML 2.0-compliant identity provider (Okta, Azure AD, ADFS, Keycloak, Shibboleth, etc.).

## Motivation

Many enterprise environments rely on SAML 2.0 as their primary federation protocol, particularly organizations with existing ADFS or legacy IdP infrastructure that has not adopted OIDC. Supporting SAML alongside OIDC ensures BastionVault can integrate with the full spectrum of enterprise identity systems without requiring organizations to change their IdP configuration.

## Design

### Dependencies

- `samael` crate -- SAML 2.0 library supporting AuthnRequest generation, Response parsing, XML signature verification, metadata parsing, and assertion extraction.

### Module Structure

```
src/modules/credential/saml/
    mod.rs             # SamlModule + SamlBackend + SamlBackendInner
    path_config.rs     # IdP configuration CRUD
    path_roles.rs      # Role CRUD (attribute-to-policy mappings)
    path_login.rs      # Generate SAML AuthnRequest, return SSO redirect URL
    path_callback.rs   # ACS: process SAML Response, verify signature, issue vault token
```

Follows the same Module/Backend pattern as `userpass` and `approle`.

### Registration

- `src/modules/credential/mod.rs` -- add `pub mod saml;`
- `src/lib.rs` (~line 126) -- instantiate and register `SamlModule`

### Endpoints

| Path | Operations | Auth Required | Purpose |
|------|-----------|---------------|---------|
| `config` | Read, Write | Yes | Get/set SAML IdP configuration |
| `role/(?P<name>[\w-]+)` | Read, Write, Delete | Yes | CRUD for SAML roles |
| `role/?` | List | Yes | List all role names |
| `login` | Write | No | Generate AuthnRequest, return SSO redirect URL |
| `callback` | Write | No | ACS: process SAML Response, issue vault token |

### Data Structures

**SamlConfig** (stored at `config`):
- `idp_metadata_url` -- URL to fetch IdP metadata XML
- `idp_metadata_xml` -- alternatively, raw metadata XML
- `entity_id` -- SP entity ID
- `acs_url` -- Assertion Consumer Service URL
- `idp_sso_url` -- derived from metadata or configured directly
- `idp_cert` -- IdP signing certificate (PEM), redacted on read
- `default_role`
- `allowed_redirect_uris`

**SamlRoleEntry** (stored at `role/<name>`):
- `bound_attributes` -- map of attribute_name to allowed values for validation
- `bound_subjects` -- allowed NameID values
- `bound_subjects_type` -- NameID format filter
- `attribute_mappings` -- map of SAML attribute to vault token metadata key
- `groups_attribute` -- SAML attribute containing group membership list
- `policies` -- vault policies to attach to the token
- `token_params` -- TTL, max_ttl, period, etc.

**SamlAuthState** (stored at `state/<relay_state>`, short-lived):
- `role_name`, `request_id`, `relay_state`, `created_at`

### Authentication Flow

1. **Initiate**: Client calls `POST auth/saml/login` with `{role}`.
   - Loads config and role.
   - Generates a SAML AuthnRequest XML with a unique request ID.
   - Stores `SamlAuthState` in backend storage keyed by relay_state (5 min TTL).
   - Base64-encodes and deflates the AuthnRequest.
   - Returns `{sso_url, relay_state}` with the IdP SSO endpoint URL and SAMLRequest parameter.

2. **Authenticate**: User is redirected to IdP, authenticates, and the IdP POSTs a SAML Response back to the ACS URL.

3. **Complete**: Client calls `POST auth/saml/callback` with `{saml_response, relay_state}`.
   - Loads and deletes `SamlAuthState` from storage (single-use).
   - Validates state has not expired.
   - Parses the SAML Response XML.
   - Verifies XML signature using IdP certificate from config.
   - Validates Issuer matches expected IdP entity ID.
   - Validates Destination matches ACS URL.
   - Validates InResponseTo matches the stored request_id.
   - Validates time conditions (NotBefore, NotOnOrAfter).
   - Extracts NameID and attributes from assertions.
   - Loads role, validates `bound_attributes` and `bound_subjects`.
   - Maps attributes to token metadata via `attribute_mappings`.
   - Returns `Response { auth }` with role policies -- TokenStore issues the vault token.

### Token Renewal

The `login_renew` handler reloads the role to verify it still exists and policies haven't changed. If the role was deleted or policies differ, renewal fails.

## Current State

Phases 1 + 2 are shipped under `src/modules/credential/saml/` —
`SamlModule` + `SamlBackend` register the `saml` auth kind, `config`
and `role/<name>` / `role/?` endpoints are wired with full field
validation, secret redaction (`idp_cert`, `idp_metadata_xml`) on
read, and `SamlRoleEntry::validate_assertion` ready for the Phase 3
callback to call. 13 unit tests + 1 end-to-end CRUD integration
test pass. Phase 3 (login, callback, XML-signature verification)
is deferred pending the XML-DSig crate decision —
`samael` pulls in `libxml2` + `libxmlsec1` C dependencies which
conflicts with the project's OpenSSL-free posture, and the
pure-Rust alternatives are not yet mature enough to rely on for a
security-critical verifier without significant hand-rolled glue.

## Implementation Phases

### Phase 1: Scaffolding -- Done
- Create module structure, bare Module + Backend structs.
- Register in `src/lib.rs` + `src/modules/credential/mod.rs`.
- Verify compilation.
- `samael` dep deferred to Phase 3 (crate decision pending).

### Phase 2: Config and Roles -- Done
- Implement `path_config.rs` -- config read/write, `idp_cert` and
  `idp_metadata_xml` redacted on read.
- Implement `path_roles.rs` -- role CRUD, list, and
  `validate_assertion` helper.

### Phase 3: Auth Flow -- Pending
- Implement `path_login.rs` -- AuthnRequest generation, relay state tracking.
- Implement `path_callback.rs` -- SAML Response parsing, signature verification, assertion extraction, Auth construction.
- Wire all paths into `new_backend()`.

### Phase 4: Tests
- Unit tests for config/role CRUD.
- Integration tests with mocked IdP SAML responses.

## Key Reference Files

- `src/modules/credential/userpass/mod.rs` -- Module/Backend pattern
- `src/modules/credential/userpass/path_login.rs` -- login handler returning Auth
- `src/modules/credential/approle/mod.rs` -- complex backend with async init
- `src/logical/path.rs` -- `new_path!` macro
- `src/logical/backend.rs` -- `new_logical_backend!` macro
