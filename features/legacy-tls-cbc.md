# Feature: Legacy TLS 1.2 CBC client for OIDC providers (`bv-tls-legacy`)

## Summary

An opt-in, client-only, TLS 1.2-only TLS stack that speaks exactly four
ECDHE-RSA AES-CBC cipher suites, plus a minimal HTTP/1.1 client over it, so an
OIDC mount can reach an identity provider that offers nothing else. It is used
**only** by a mount whose config sets `oidc_discovery_legacy_tls = true`, and
only in a build with the `bv-auth-oidc/legacy-tls` cargo feature. It is never
an automatic fallback.

Task: T551. Related: S29 (`features/oidc-auth.md`).

## Status

**Phases 1–3 done; Phase 4 (live run against the production IdP) not done.**
See the phase table at the end.

## Motivation

An SSO test fails with `oidc: discovery: ... received fatal alert:
HandshakeFailure`. The IdP (TLS 1.2 only; TLS 1.3 answers alert 70) offers only
`TLS_ECDHE_RSA_WITH_AES_{128,256}_CBC_SHA`,
`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` and
`TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`, key exchange on secp256r1, no GCM or
ChaCha20. rustls deliberately implements no CBC suite, so the OIDC client
(`openidconnect` 4 over `reqwest` + rustls) can never connect, and the IdP
cannot be changed for now.

The only pure-Rust stack with CBC suites found (`purecrypto`, feature
`tls-legacy`) is an unaudited whole stack. We write a narrow client instead
and compose vetted primitives; we do not depend on it.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Where | New crate `crates/bv-tls-legacy`, Tier 0, `publish = ["uox-bastionvault"]` | Depends on no workspace crate (not even `bv-errors`: it has its own error type), so the dependency direction stays upward and `bv-auth-oidc` (Tier 3) can use it. |
| Role | Client only | Nothing in the vault needs to *serve* CBC. A server half exists only under `#[cfg(test)]`. |
| Versions | TLS 1.2 only (`0x0303`) | TLS ≤ 1.1 has no explicit IV discipline guarantees we want and is refused explicitly. TLS 1.3 is what rustls is for. |
| Key exchange | ECDHE-RSA on secp256r1 only | The target uses P-256. P-384 was considered "if cheap": it is little code but another curve of attack surface nobody needs today, so it is out. No static RSA, no (EC)DH static, no DHE. |
| Suites | `C028` AES256-CBC-SHA384, `C027` AES128-CBC-SHA256, `C014` AES256-CBC-SHA, `C013` AES128-CBC-SHA, in that order | Exactly the four the IdP offers. PRF SHA-384 for `C028`, SHA-256 for the others (RFC 5246 §5, RFC 5289). |
| Extensions sent | `server_name` (DNS names only; RFC 6066 forbids IP literals), `supported_groups` = {secp256r1}, `ec_point_formats` = {uncompressed}, `signature_algorithms`, `extended_master_secret`, `renegotiation_info` (empty) | Minimum for interop + the two RFC 7627 / RFC 5746 safety extensions. No session ticket, ALPN, status request, heartbeat, compression. |
| EMS | Used when the server echoes it; otherwise the RFC 5246 master secret | The brief; RFC 7627 lets a client proceed without it. With no resumption and no renegotiation, the triple-handshake attack has no second handshake to splice. Whether EMS was used is exposed (`ConnectionInfo`). |
| Renegotiation | Never. A `HelloRequest` or any handshake record after `Finished` is a fatal error | RFC 5746 secure-renegotiation extension is still sent and checked (must be empty in ServerHello). |
| Resumption | None: empty session id, no tickets; a server session id is ignored | Removes a whole class of state. |
| Client certificates | Not supported; a `CertificateRequest` is a fatal error with a clear message | Narrowest state machine. Revisit only if a real IdP sends one. |
| Primitives | RustCrypto: `aes` 0.9 (`zeroize`), `cbc` 0.2, `hmac` 0.13, `sha1` 0.11, `sha2` 0.11, `p256` 0.14 (`ecdh`), `subtle`, `zeroize`; `getrandom` 0.4 for randomness | Pure Rust, all already in `Cargo.lock` at these versions (no new crate enters the graph), and the same majors the rest of the workspace uses. No primitive is hand-written; the crate only composes them (PRF = HMAC iteration per RFC 5246 §5). |
| Certificates | `rustls-webpki` 0.103 (`ring` provider) + `webpki-roots`, plus the mount's `oidc_discovery_ca_pem` anchors | The same verifier rustls uses: chain to an anchor, `serverAuth` EKU, validity at now, hostname/IP SAN. The ServerKeyExchange signature is verified with `EndEntityCert::verify_signature`. Verification cannot be turned off: there is no API for it. `ring` because both providers are already enabled on `rustls-webpki` in the OIDC graph and `ring` has no C toolchain dependency. |
| No OpenSSL / aws-lc in production | `cargo tree -i openssl-sys` stays empty; `aws-lc-rs` is a **dev**-dependency only (test server RSA keygen/signing, as `bv-engine-idp` does) | AGENTS.md §7. |
| HTTP | Own minimal HTTP/1.1 client: `GET`/`POST` only, `Connection: close`, no redirects, `Content-Length`, `chunked` and close-delimited bodies, header and body size caps, connect/handshake/header/body timeouts | Mirrors the existing reqwest settings (no redirects, bounded time). A close-delimited body requires `close_notify` (truncation defence). |
| OIDC integration | `bv-auth-oidc` implements `openidconnect::AsyncHttpClient` (oauth2 5) over the legacy client and selects it per mount | Discovery, JWKS and the token exchange all go through the selected client for that mount only; other mounts keep reqwest/rustls. |
| Cargo feature | `bv-auth-oidc/legacy-tls`, default **off**; forwarded as `oidc_legacy_tls` by `bastion_vault`; **on by default** in `bvault-cli` and the GUI host | The CBC code is compiled into the default server/CLI build (and so every `make` target, the container image and the packages) but is inert until a mount sets the field; `--no-default-features` drops it. The desktop app carries it so an admin can opt a provider in for the embedded vault from the SSO dialog (an explicit product decision); compiling it in changes nothing until a mount sets the field. |
| Config field | `oidc_discovery_legacy_tls` (bool, default `false`) on the existing `auth/<mount>/config` | No new route (the field rides the existing path, so v1/v2 consistency is unchanged). A config written before the field existed reads as `false`. |
| Field on, feature off | Refused on write (`... requires a build with the oidc_legacy_tls feature`) and refused at use (a config written by a build with the feature, read by one without) | No silent fallback to rustls and no silent downgrade from it (AGENTS.md §7). |
| Observability | A `warn` (target `security`) each time a mount's OIDC call builds the legacy client, naming the mount's issuer URL and that TLS 1.2 CBC is in use; `oidc_legacy_tls_available` on the config read says whether the build has the client | The backend does not see its own mount path (the router strips it), so the issuer URL is what identifies the mount in the log. No secret, key or handshake value is logged anywhere in the crate (it has no logging dependency at all). Code-exchange transport errors now carry their cause chain (never the body). |
| GUI | SSO provider dialog: "Use legacy TLS 1.2 (CBC) for this provider" switch, always sent (`false` included), with a warning and a distinct compiled-out state (from `oidc_legacy_tls_available = false` or the vault's refusal); "Legacy TLS 1.2" badge in the provider list | Embedded and remote mode use the same logical request; a remote vault answers from its own build, so a remote server without the feature refuses `true` with its explicit error and the dialog shows the compiled-out state. Turning the switch off is always allowed. |

## Threat model

**Assets on this channel.** Integrity of the discovery document and JWKS (a
substituted JWKS lets an attacker mint ID tokens the vault accepts: full authn
bypass for that mount); the authorization code, PKCE verifier and
`client_secret` sent in the token request; the ID/access tokens received.

**Attacker.** An active network attacker between the vault and the IdP. A
co-resident (same host / cache) attacker is out of scope, as it is for the
rest of the vault's TLS.

| Threat | Mitigation |
|---|---|
| Certificate substitution / wrong host | `rustls-webpki` chain + `serverAuth` + time + DNS/IP SAN check, anchors = webpki roots ∪ mount CA PEM. No skip switch exists. |
| Forged key exchange | ServerKeyExchange signature over `client_random ‖ server_random ‖ params`, RSA PKCS#1 v1.5 or PSS with SHA-256/384/512, ≥ 2048-bit keys (webpki algorithm set). An algorithm we did not offer, or a non-RSA algorithm, is refused. |
| Version / suite downgrade | Only TLS 1.2 and four suites are offered; ServerHello must match exactly; both `Finished` messages cover the whole transcript (constant-time compare). |
| Invalid-curve / bad point | Only `named_curve` secp256r1, uncompressed 65-byte points, decoded and on-curve checked by `p256::PublicKey::from_sec1_bytes` (identity refused). |
| CBC padding oracle (Lucky13 class) on records the **client** decrypts | See "Record layer" below: constant-time padding check over a fixed window, MAC computed with record-length-only work, constant-time MAC extraction and comparison, one undifferentiated `bad_record_mac` error and alert. |
| Truncation | `Content-Length` and `chunked` bodies are length-checked; a close-delimited body requires `close_notify`; TCP EOF without `close_notify` mid-record or mid-body is an error. |
| Renegotiation / triple handshake | No renegotiation, no resumption, RFC 5746 extension checked, EMS when offered. |
| BEAST, POODLE, CRIME, SWEET32, FREAK, Logjam, ROBOT, Raccoon, Heartbleed | Not applicable by construction: TLS 1.2 explicit per-record random IV; full TLS padding check; null compression only; AES (128-bit block); no export/DHE/static-RSA/static-DH; no heartbeat. |
| Resource exhaustion | Ciphertext ≤ 2^14 + 2048, plaintext ≤ 2^14, handshake message ≤ 64 KiB, ≤ 10 certificates, bounded empty-record run, response headers ≤ 64 KiB / 100 lines, body ≤ 1 MiB, timeouts on connect / handshake / headers / body. |
| Secret retention | Pre-master secret, master secret, key block, MAC and encryption keys are `Zeroizing`; the AES key schedule zeroizes on drop (`aes/zeroize`, already on in the graph). HMAC internal states are **not** zeroized: turning on `digest/zeroize` would change the feature set of a crate the whole workspace shares. |

**Residual risk accepted (stated, not hidden).**

1. *Lucky13-class timing on the client.* The countermeasure equalises the
   number of hash compression calls per record (Go / s2n style) and picks the
   MAC out of the record with a constant-address scan, but it is not the
   formally constant-time digest of BoringSSL/OpenSSL: one data-dependent
   branch selects whether a single dummy compression runs, and cache effects
   are not modelled. Exploiting it needs an active MITM, timing at
   sub-microsecond resolution, and many sessions carrying the *same* plaintext
   at the same offset; every failed guess kills the connection, and the
   secrets the client decrypts (codes, tokens) are single-use per login.
2. *The IdP's own CBC implementation.* The token request carries the same
   `client_secret` on every login. If the IdP's server-side CBC decryption is
   itself Lucky13-vulnerable, an attacker who can trigger many logins could
   recover it. We cannot fix the server; prefer a public (PKCE-only) client
   for such an IdP or rotate the secret, and move off CBC when the IdP allows.
3. The crate is new, unaudited code. It is small, client-only, test-covered
   (known-answer vectors, loopback, negative tests, OpenSSL interop) and off
   by default; an independent review before wide use is recommended.

## Record layer (the risky part)

MAC-then-encrypt, RFC 5246 §6.2.3.2. Write: `IV(16, fresh from getrandom) ‖
AES-CBC(plaintext ‖ HMAC(seq ‖ type ‖ 0x0303 ‖ len ‖ plaintext) ‖ padding)`,
minimal padding, 64-bit sequence numbers (separate read/write, reset at
ChangeCipherSpec, overflow refused).

Read (`record.rs`, `Decryptor::open`):

1. Length must be a multiple of 16 and ≥ 16 + round_up(mac_len + 1, 16), and
   ≤ 2^14 + 2048 — else `bad_record_mac` (same error as below).
2. CBC-decrypt in place with the explicit IV.
3. Padding check in constant time over the last `min(256, len)` bytes;
   validity of `pad_len + 1 + mac_len ≤ len` folded into the same mask. A bad
   padding is treated as zero-length padding (RFC 5246 §6.2.3.2).
4. MAC over `seq ‖ header(len = n) ‖ plaintext[..n]` where `n` is secret,
   then the remaining bytes are fed to the same running hash and finalised
   too, so the inner hash always consumes `13 + len − mac_len` bytes; one
   dummy compression equalises the 1-vs-2 finalisation blocks.
5. The received MAC is extracted by scanning every candidate offset (no
   secret-dependent address), compared with `subtle::ConstantTimeEq`, and
   AND-ed with the padding mask.
6. Any failure: `TlsError::BadRecordMac` (one variant, one message) and a fatal
   `bad_record_mac` (20) alert.

## API

```rust
// crates/bv-tls-legacy
pub struct TrustAnchors;                       // webpki roots + extra DER/PEM certs
pub struct ClientConfig { handshake_timeout, .. }
pub async fn connect<IO: AsyncRead + AsyncWrite + Unpin>(
    io: IO, server_name: ServerName<'static>, trust: &TrustAnchors, cfg: &ClientConfig,
) -> Result<LegacyTlsStream<IO>, TlsError>;   // LegacyTlsStream: AsyncRead + AsyncWrite
pub mod http {
    pub struct HttpLimits { .. }               // timeouts + size caps
    pub async fn send(req: http::Request<Vec<u8>>, trust: &TrustAnchors, limits: &HttpLimits)
        -> Result<http::Response<Vec<u8>>, HttpError>;
}
```

`bv-auth-oidc` wraps `http::send` in an `openidconnect::AsyncHttpClient`.

## Operator surface

```bash
# Build with the feature (default builds do not contain the CBC code)
cargo build --release -p bvault-cli --features oidc_legacy_tls

# Opt the one mount in
bvault write auth/oidc/config oidc_discovery_legacy_tls=true
```

In a build without the feature the write above is refused. The GUI's SSO
provider dialog (Settings → SSO providers → Edit) has the matching switch; the
desktop app's embedded vault carries the feature by default, a remote vault
answers from its own build.

## Tests

- PRF known-answer vectors (TLS 1.2 PRF SHA-256 and SHA-384, the widely
  published IETF TLS-WG vectors), master-secret / EMS / key-block derivation
  against values computed by an independent implementation (Python `hmac`).
- Loopback handshakes + HTTP exchange against the `#[cfg(test)]` server half
  for all four suites, with and without EMS.
- Negative: bad MAC, bad padding (indistinguishable error and alert), short /
  misaligned / oversized records, truncated record, untrusted chain, wrong
  hostname, bad ServerKeyExchange signature, tampered server `Finished`, TLS 1.1
  ServerHello, suite not offered, unsolicited extension, non-empty
  renegotiation_info, renegotiation attempt after the handshake,
  `CertificateRequest`, server closing mid-handshake, handshake timeout,
  close-delimited body without `close_notify`, oversized body/header, bad
  chunked framing.
- Interop with `openssl s_server -tls1_2 -cipher ECDHE-RSA-AES256-SHA` (and
  the other three), skipped cleanly when `openssl` is absent or lacks the
  suite (LibreSSL).
- `#[ignore]`d live fetch of a discovery document from
  `BV_TLS_LEGACY_LIVE_URL` (no host committed).
- `bv-auth-oidc`: the field routes discovery through the legacy client (it
  fails against a rustls-only server with the legacy client's error, while the
  default path succeeds against it); field on + feature off is refused;
  config read-old/write-new.

- GUI: `OidcLegacyTlsToggle.test.tsx`, `SsoProviderModal.test.tsx` (payload
  incl. explicit `false`, persisted value, compiled-out state),
  `SsoTestModal.test.tsx` (vault TLS error shown verbatim); GUI host
  `sso_admin.rs` unit tests for read-back and the explicit `false`.

Run the feature-on tests with `make test-oidc-legacy-tls`.

## Implementation phases

| Phase | Scope | Status |
|---|---|---|
| 1 | This spec, threat model, tracking rows (S121, T551) | Done |
| 2 | `bv-tls-legacy`: record layer, handshake, webpki verification, stream, HTTP client, tests | Done |
| 3 | `bv-auth-oidc` wiring behind `legacy-tls`, `oidc_discovery_legacy_tls` field, feature forwarding, docs | Done |
| 3b | GUI: SSO dialog switch + warning + compiled-out state, provider-list badge, Tauri host read/write of the field, `oidc_legacy_tls` on by default in the desktop build | Done (not clicked through in a running app) |
| 4 | Manual run against the production IdP (`BV_TLS_LEGACY_LIVE_URL`) | Not done — needs the operator's network |
| 5 | Independent security review of `record.rs` and `handshake.rs` | Not done |

## What is not implemented

Tolerating warning-level alerts: every alert but `close_notify` is fatal, so a
server that answers SNI with a *warning* `unrecognized_name` is refused with
that alert named (relax only if a real IdP needs it). P-384 and other curves;
ECDSA server certificates (ECDHE-ECDSA suites);
client certificates; resumption; renegotiation; ALPN; OCSP stapling and
revocation checks (same as the rustls path today); HTTP proxies; redirects;
any server-side use.
