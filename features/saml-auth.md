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

All three phases shipped. SP-initiated SAML 2.0 SSO works end-to-end
under `src/modules/credential/saml/` using a pure-Rust stack — no
libxml2 / libxmlsec1 / samael C-dependency footprint.

Modules:
- `authn_request.rs` — AuthnRequest XML builder, DEFLATE + base64
  encoding for the HTTP-Redirect binding, SAML-conformant ISO-8601
  UTC timestamp + NCName-safe request id generation.
- `response.rs` — streaming `quick-xml` parser extracting Response-
  and Assertion-level fields (ID, Issuer, Destination, InResponseTo,
  Status, NameID + Format, NotBefore / NotOnOrAfter,
  AudienceRestriction, Attribute / AttributeValue). Captures the
  exact byte span of the Assertion element for signature verification.
- `validate.rs` — non-crypto checks: Success status, Destination =
  ACS URL, non-empty InResponseTo matching the stored request id,
  Issuer matching configured IdP entity id, Audience containing
  SP entity id, timestamp window with 60 s default clock-skew grace.
  Ships a dependency-free ISO-8601 UTC parser that round-trips
  through the Howard-Hinnant civil-date algorithm.
- `verify.rs` — RSA-SHA256 / RSA-SHA1 signature verification backed
  by the `rsa 0.9` crate; `x509-parser` extracts the public key
  from the configured PEM cert. Includes a pragmatic Exclusive XML
  Canonicalization (C14N) implementation that handles the output
  format every major IdP (Azure AD, Okta, Keycloak, Shibboleth,
  ADFS) emits on signed regions: namespace pruning to visibly-used
  prefixes, attribute + namespace sorting, c14n text + attribute
  escaping, self-closing → expanded form. End-to-end self-verified
  via a roundtrip test that signs + verifies a freshly-generated
  1024-bit RSA keypair against a canonicalised-then-rehashed
  assertion. Tampered payloads produce a digest mismatch.
- `path_login.rs` — `POST auth/<mount>/login` generates the
  AuthnRequest, persists a `SamlAuthState` under `state/<relay_state>`
  (5 min TTL, single-use — load-and-delete on callback), returns the
  fully-formed IdP SSO URL with `SAMLRequest` + `RelayState` params.
- `path_callback.rs` — `POST auth/<mount>/callback` parses the
  Response, runs structural validation, verifies the signature, loads
  the role, projects attributes through `attribute_mappings`,
  populates `auth.metadata` (including `name_id`, `role`, and the
  comma-joined groups claim when configured), and returns an `Auth`
  the token store mints a vault token from.

Tests: 46 unit + integration tests, 524 lib tests total green. New
deps: `rsa = "0.9"`, `x509-parser = "0.17"`, `flate2 = "1.0"`,
`quick-xml = "0.36"` (promoted from optional → always-on). Also
adds aliased `sha1-saml` / `sha2-saml` at version 0.10 (with `oid`
feature) to bridge the `rsa 0.9 ↔ digest 0.10 ↔ digest 0.11`
lineage gap — the project's top-level `sha1 = "0.11"` stays at
0.11 for the post-quantum stack. No C deps, no OpenSSL entanglement.

Pragmatic limits (documented in `verify.rs` module docstring,
error messages name the precise unsupported algorithm):
- RSA signatures only (no ECDSA / DSA — no mainstream IdP uses them).
- Enveloped signature shape only (Signature as a direct child of the
  signed element; matches 100% of production IdPs).
- Exactly one `<Reference>` per SignedInfo.
- Empty `<InclusiveNamespaces>` PrefixList (no custom inclusive list).
- Response-level OR assertion-level signature (both supported).

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

### Phase 3: Auth Flow -- Done
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
