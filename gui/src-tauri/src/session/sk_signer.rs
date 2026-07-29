//! CTAP2-backed SSH signer for FIDO2 security keys
//! (`features/connect-mfa-and-fido2-ssh.md`).
//!
//! OpenSSH's `sk-` key types keep the private half inside a hardware
//! authenticator. Signing is a CTAP2 `getAssertion` in disguise:
//!
//!   * the **relying-party id** is the OpenSSH *application* string
//!     (`ssh:` by default),
//!   * the **client-data hash** is `SHA-256` of the buffer SSH wants signed
//!     — where a browser would put `SHA-256(clientDataJSON)`,
//!   * the authenticator signs `authData || clientDataHash` as always, and
//!     the SSH verifier on the far end reconstructs exactly that from
//!     `SHA-256(application) || flags || counter || SHA-256(signed_data)`.
//!
//! That last point is why [`build_sk_signature_blob`] refuses an `authData`
//! carrying extension or attested-credential data: the target reconstructs a
//! fixed 37-byte prefix, so anything longer produces a signature that is
//! cryptographically fine and still fails to verify. Better to say so here
//! than to ship a confusing rejection from sshd.
//!
//! The wire format is PROTOCOL.u2f, and is byte-identical to what `russh`'s
//! own ssh-agent client emits for `sk-` keys (`keys::agent::client::
//! write_signature`) — [`build_sk_signature_blob`]'s tests pin the layout.

use std::sync::Arc;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

use authenticator::authenticatorservice::{AuthenticatorService, SignArgs};
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, PublicKeyCredentialDescriptor, Transport,
    UserVerificationRequirement,
};
use authenticator::statecallback::StateCallback;
use authenticator::StatusUpdate;
use russh::keys::agent::AgentIdentity;
use russh::Signer;
use russh::keys::ssh_key::HashAlg;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};

use crate::commands::fido2_native::handle_status_updates;

/// OpenSSH security-key algorithm names (PROTOCOL.u2f).
pub const ALG_SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
pub const ALG_SK_ECDSA_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";

/// How long to wait for the operator to touch the key. Deliberately shorter
/// than a typical sshd `LoginGraceTime` (120s) so a missing touch surfaces as
/// our own "no touch registered" message rather than as an opaque connection
/// reset from the target.
pub const TOUCH_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug)]
pub enum SkSignError {
    /// russh's channel to the session task went away.
    Send(russh::SendError),
    /// The authenticator, the transport, or the operator.
    Ctap(String),
    /// The assertion came back in a shape we cannot turn into an SSH
    /// signature.
    Encoding(String),
}

impl std::fmt::Display for SkSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Send(_) => write!(f, "ssh session closed while waiting for the security key"),
            Self::Ctap(e) => write!(f, "security key: {e}"),
            Self::Encoding(e) => write!(f, "security-key signature: {e}"),
        }
    }
}

impl std::error::Error for SkSignError {}

impl From<russh::SendError> for SkSignError {
    fn from(e: russh::SendError) -> Self {
        Self::Send(e)
    }
}

/// Everything needed to drive one operator's enrolled security key.
#[derive(Debug, Clone)]
pub struct SecurityKeyIdentity {
    /// `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com`.
    pub algorithm: String,
    /// OpenSSH application string == CTAP relying-party id.
    pub application: String,
    /// CTAP credential id (v1 enrols non-discoverable credentials, so the
    /// allow-list is mandatory).
    pub credential_id: Vec<u8>,
}

/// A `russh::auth::Signer` that delegates to a USB security key.
pub struct SecurityKeySigner {
    identity: SecurityKeyIdentity,
    app: AppHandle,
    /// Shared with `AppState` so the GUI's PIN prompt can answer a
    /// PIN-protected authenticator, exactly as the FIDO2 login flow does.
    pin_slot: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>,
}

impl SecurityKeySigner {
    pub fn new(
        identity: SecurityKeyIdentity,
        app: AppHandle,
        pin_slot: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>,
    ) -> Self {
        Self { identity, app, pin_slot }
    }
}

impl Signer for SecurityKeySigner {
    type Error = SkSignError;

    async fn auth_sign(
        &mut self,
        _key: &AgentIdentity,
        _hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        // PROTOCOL.u2f: the SSH signed data takes the place of WebAuthn's
        // clientDataJSON, so its hash is the clientDataHash we hand CTAP.
        let client_data_hash: [u8; 32] = Sha256::digest(&to_sign).into();

        let assertion =
            get_assertion(&self.identity, client_data_hash, self.app.clone(), self.pin_slot.clone())
                .await?;

        let blob = build_sk_signature_blob(
            &self.identity.algorithm,
            &assertion.signature,
            assertion.flags,
            assertion.counter,
        )
        .map_err(SkSignError::Encoding)?;

        // russh expects the to-sign buffer with the signature appended, not
        // the signature alone — it writes `buffer[i..]` as the packet tail.
        // Returning just the blob produces a silently malformed
        // SSH_MSG_USERAUTH_REQUEST.
        let mut out = to_sign;
        out.extend_from_slice(&blob);
        Ok(out)
    }
}

/// The three fields of a CTAP assertion that matter for an SSH signature.
#[derive(Debug, Clone)]
pub struct SkAssertion {
    pub signature: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
}

/// Run one `getAssertion` against the operator's enrolled key.
///
/// Blocking CTAP work happens on a blocking thread; the status channel drives
/// the same `fido2-status` events the login flow emits, so the existing
/// "touch your key" / PIN UI works unchanged.
async fn get_assertion(
    identity: &SecurityKeyIdentity,
    client_data_hash: [u8; 32],
    app: AppHandle,
    pin_slot: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<String>>>>,
) -> Result<SkAssertion, SkSignError> {
    let sign_args = SignArgs {
        client_data_hash,
        // CTAP2 needs an origin string; for an SSH credential the application
        // *is* the origin. The authenticator only hashes `relying_party_id`,
        // so this field never reaches the signature.
        origin: identity.application.clone(),
        relying_party_id: identity.application.clone(),
        allow_list: vec![PublicKeyCredentialDescriptor {
            id: identity.credential_id.clone(),
            transports: vec![Transport::USB],
        }],
        // `preferred`, not `required`: plenty of enrolled keys have no PIN
        // set, and demanding UV would lock those operators out of a flow that
        // already requires physical possession and a touch.
        user_verification_req: UserVerificationRequirement::Preferred,
        user_presence_req: true,
        extensions: AuthenticationExtensionsClientInputs::default(),
        pin: None,
        use_ctap1_fallback: false,
    };

    let (pin_tx, pin_rx) = channel::<String>();
    if let Ok(mut guard) = pin_slot.lock() {
        *guard = Some(pin_tx);
    }

    let handle = app.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<SkAssertion, SkSignError> {
        let mut service = AuthenticatorService::new()
            .map_err(|e| SkSignError::Ctap(format!("failed to init authenticator: {e:?}")))?;
        service.add_detected_transports();

        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let (result_tx, result_rx) = channel();

        let status_handle = handle.clone();
        std::thread::spawn(move || {
            handle_status_updates(status_rx, status_handle, pin_rx);
        });

        let callback = StateCallback::new(Box::new(move |rv| {
            let _ = result_tx.send(rv);
        }));

        let _ = handle.emit("fido2-status", "insert-key");

        service
            .sign(TOUCH_TIMEOUT_MS, sign_args, status_tx, callback)
            .map_err(|e| SkSignError::Ctap(format!("{e:?}")))?;

        let sign_result = match result_rx.recv_timeout(Duration::from_millis(TOUCH_TIMEOUT_MS + 5_000))
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(SkSignError::Ctap(format!("{e:?}"))),
            Err(RecvTimeoutError::Timeout) => {
                return Err(SkSignError::Ctap(
                    "no touch registered on the security key within 30s".into(),
                ))
            }
            Err(e) => return Err(SkSignError::Ctap(format!("channel error: {e}"))),
        };

        let assertion = sign_result.assertion;

        // The far end reconstructs authData as exactly
        // `SHA-256(application) || flags || counter` — 37 bytes, nothing
        // more. If the authenticator returned attested-credential data or an
        // extensions block, the message it actually signed is longer than
        // what the verifier will hash, and the signature cannot verify. Fail
        // here, where we can say why.
        if assertion.auth_data.credential_data.is_some() {
            return Err(SkSignError::Encoding(
                "authenticator returned attested-credential data in an assertion; \
                 the SSH signature could not be verified by the target"
                    .into(),
            ));
        }
        if assertion.auth_data.to_vec().len() != 37 {
            return Err(SkSignError::Encoding(format!(
                "authenticator returned {} bytes of authData; OpenSSH security-key \
                 signatures require exactly 37 (rpIdHash || flags || counter) with no \
                 extensions block",
                assertion.auth_data.to_vec().len()
            )));
        }

        Ok(SkAssertion {
            signature: assertion.signature,
            flags: assertion.auth_data.flags.bits(),
            counter: assertion.auth_data.counter,
        })
    })
    .await
    .map_err(|e| SkSignError::Ctap(format!("task join error: {e}")))?;

    if let Ok(mut guard) = pin_slot.lock() {
        let _ = guard.take();
    }
    let _ = app.emit("fido2-status", "processing");

    result
}

// ── PROTOCOL.u2f signature encoding ────────────────────────────────

/// Append an SSH `string` (uint32 length + bytes).
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build the `signature` field of an `SSH_MSG_USERAUTH_REQUEST` for a `sk-`
/// key.
///
/// Layout (PROTOCOL.u2f), all inside one outer SSH string:
///
/// ```text
/// uint32  len(alg) + len(sig) + 8 + 5
/// string  alg        "sk-ssh-ed25519@openssh.com"
/// string  sig        raw 64 bytes (Ed25519) | mpint r ‖ mpint s (ECDSA)
/// byte    flags      from authData
/// uint32  counter    from authData
/// ```
///
/// `raw_signature` is what CTAP returned: 64 raw bytes for Ed25519, a DER
/// `SEQUENCE { INTEGER r, INTEGER s }` for ES256 (which this function
/// re-encodes into the mpint pair SSH expects).
pub fn build_sk_signature_blob(
    algorithm: &str,
    raw_signature: &[u8],
    flags: u8,
    counter: u32,
) -> Result<Vec<u8>, String> {
    let inner_sig: Vec<u8> = match algorithm {
        ALG_SK_ED25519 => {
            if raw_signature.len() != 64 {
                return Err(format!(
                    "expected a 64-byte Ed25519 signature, got {}",
                    raw_signature.len()
                ));
            }
            raw_signature.to_vec()
        }
        ALG_SK_ECDSA_P256 => der_ecdsa_to_mpint_pair(raw_signature)?,
        other => return Err(format!("unsupported security-key algorithm `{other}`")),
    };

    let inner_len = 4 + algorithm.len() + 4 + inner_sig.len() + 1 + 4;
    let mut out = Vec::with_capacity(4 + inner_len);
    out.extend_from_slice(&(inner_len as u32).to_be_bytes());
    put_string(&mut out, algorithm.as_bytes());
    put_string(&mut out, &inner_sig);
    out.push(flags);
    out.extend_from_slice(&counter.to_be_bytes());
    Ok(out)
}

/// Convert a DER `SEQUENCE { INTEGER r, INTEGER s }` into SSH's `mpint r ‖
/// mpint s`.
///
/// A DER INTEGER's content octets are already minimal big-endian two's
/// complement — the exact value encoding of an SSH mpint — so each integer's
/// body is copied through unchanged behind a length prefix.
fn der_ecdsa_to_mpint_pair(der: &[u8]) -> Result<Vec<u8>, String> {
    let mut p = DerReader { buf: der, pos: 0 };
    let seq = p.read_tlv(0x30)?;
    let mut inner = DerReader { buf: seq, pos: 0 };
    let r = inner.read_tlv(0x02)?;
    let s = inner.read_tlv(0x02)?;
    if inner.pos != inner.buf.len() {
        return Err("trailing bytes after ECDSA (r, s)".into());
    }
    if p.pos != p.buf.len() {
        return Err("trailing bytes after ECDSA SEQUENCE".into());
    }

    let mut out = Vec::with_capacity(r.len() + s.len() + 8);
    put_string(&mut out, r);
    put_string(&mut out, s);
    Ok(out)
}

// ── OpenSSH public-key derivation ──────────────────────────────────

/// Build the `authorized_keys` line for an enrolled Ed25519 security key.
///
/// Blob layout (PROTOCOL.u2f):
///
/// ```text
/// string  "sk-ssh-ed25519@openssh.com"
/// string  public key      (32 raw bytes, from the COSE OKP `x`)
/// string  application
/// ```
///
/// The application is *inside the public key*, which is why a key registered
/// under one application cannot be used under another: the target hashes the
/// application it read from `authorized_keys` and compares against what the
/// authenticator signed.
pub fn sk_ed25519_public_key(
    raw_public: &[u8],
    application: &str,
    comment: &str,
) -> Result<String, String> {
    if raw_public.len() != 32 {
        return Err(format!(
            "expected a 32-byte Ed25519 public key from the authenticator, got {}",
            raw_public.len()
        ));
    }
    let mut blob = Vec::new();
    put_string(&mut blob, ALG_SK_ED25519.as_bytes());
    put_string(&mut blob, raw_public);
    put_string(&mut blob, application.as_bytes());
    Ok(authorized_keys_line(ALG_SK_ED25519, &blob, comment))
}

/// Build the `authorized_keys` line for an enrolled NIST P-256 security key.
///
/// ```text
/// string  "sk-ecdsa-sha2-nistp256@openssh.com"
/// string  "nistp256"
/// string  public key      (SEC1 uncompressed point: 0x04 ‖ X ‖ Y)
/// string  application
/// ```
pub fn sk_ecdsa_p256_public_key(
    sec1_point: &[u8],
    application: &str,
    comment: &str,
) -> Result<String, String> {
    if sec1_point.len() != 65 || sec1_point.first() != Some(&0x04) {
        return Err(format!(
            "expected a 65-byte uncompressed SEC1 P-256 point from the authenticator, \
             got {} bytes starting {:#04x}",
            sec1_point.len(),
            sec1_point.first().copied().unwrap_or(0)
        ));
    }
    let mut blob = Vec::new();
    put_string(&mut blob, ALG_SK_ECDSA_P256.as_bytes());
    put_string(&mut blob, b"nistp256");
    put_string(&mut blob, sec1_point);
    put_string(&mut blob, application.as_bytes());
    Ok(authorized_keys_line(ALG_SK_ECDSA_P256, &blob, comment))
}

fn authorized_keys_line(algorithm: &str, blob: &[u8], comment: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let encoded = STANDARD.encode(blob);
    let comment = comment.trim();
    if comment.is_empty() {
        format!("{algorithm} {encoded}")
    } else {
        format!("{algorithm} {encoded} {comment}")
    }
}

struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    /// Read one DER TLV of the expected tag and return its contents.
    ///
    /// Only definite-length forms are accepted, and lengths above four octets
    /// are refused — an ECDSA signature has no legitimate reason to be that
    /// large, and accepting them invites integer trouble for no gain.
    fn read_tlv(&mut self, expect_tag: u8) -> Result<&'a [u8], String> {
        let tag = *self.buf.get(self.pos).ok_or("truncated DER: missing tag")?;
        if tag != expect_tag {
            return Err(format!("DER tag {tag:#04x}, expected {expect_tag:#04x}"));
        }
        self.pos += 1;

        let first = *self.buf.get(self.pos).ok_or("truncated DER: missing length")?;
        self.pos += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err("unsupported DER length form".into());
            }
            let bytes =
                self.buf.get(self.pos..self.pos + n).ok_or("truncated DER: short length")?;
            self.pos += n;
            bytes.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize)
        };

        let body = self.buf.get(self.pos..self.pos + len).ok_or("truncated DER: short body")?;
        self.pos += len;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    #[test]
    fn ed25519_blob_matches_protocol_u2f_layout() {
        let sig = vec![0xABu8; 64];
        let blob = build_sk_signature_blob(ALG_SK_ED25519, &sig, 0x05, 42).unwrap();

        let alg = ALG_SK_ED25519.as_bytes();
        let expected_inner = 4 + alg.len() + 4 + 64 + 1 + 4;

        // Outer length, then alg string, then sig string, then flags+counter.
        assert_eq!(&blob[0..4], &be32(expected_inner as u32));
        assert_eq!(&blob[4..8], &be32(alg.len() as u32));
        assert_eq!(&blob[8..8 + alg.len()], alg);

        let mut o = 8 + alg.len();
        assert_eq!(&blob[o..o + 4], &be32(64));
        o += 4;
        assert_eq!(&blob[o..o + 64], &sig[..]);
        o += 64;
        assert_eq!(blob[o], 0x05);
        assert_eq!(&blob[o + 1..o + 5], &be32(42));

        // And the whole thing is exactly the declared length.
        assert_eq!(blob.len(), 4 + expected_inner);
    }

    #[test]
    fn ed25519_rejects_a_wrong_length_signature() {
        // A 71-byte DER blob is what an ES256 key returns — catching the
        // mismatch here beats shipping it to sshd.
        let err = build_sk_signature_blob(ALG_SK_ED25519, &[0u8; 71], 1, 0).unwrap_err();
        assert!(err.contains("64-byte Ed25519"), "{err}");
    }

    #[test]
    fn unsupported_algorithm_is_refused() {
        let err = build_sk_signature_blob("ssh-ed25519", &[0u8; 64], 1, 0).unwrap_err();
        assert!(err.contains("unsupported security-key algorithm"), "{err}");
    }

    /// DER: SEQUENCE { INTEGER 0x01F2, INTEGER 0x00FF03 }
    fn sample_der() -> Vec<u8> {
        let r = [0x02u8, 0x02, 0x01, 0xF2];
        // 0xFF03 needs the leading 0x00 to stay positive — exactly the case
        // an mpint has to preserve.
        let s = [0x02u8, 0x03, 0x00, 0xFF, 0x03];
        let mut body = Vec::new();
        body.extend_from_slice(&r);
        body.extend_from_slice(&s);
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn ecdsa_der_becomes_an_mpint_pair() {
        let pair = der_ecdsa_to_mpint_pair(&sample_der()).unwrap();
        // mpint r = 0x01F2 (2 bytes), mpint s = 0x00FF03 (3 bytes, sign byte
        // preserved).
        let mut expected = Vec::new();
        expected.extend_from_slice(&be32(2));
        expected.extend_from_slice(&[0x01, 0xF2]);
        expected.extend_from_slice(&be32(3));
        expected.extend_from_slice(&[0x00, 0xFF, 0x03]);
        assert_eq!(pair, expected);
    }

    #[test]
    fn ecdsa_blob_wraps_the_mpint_pair() {
        let blob = build_sk_signature_blob(ALG_SK_ECDSA_P256, &sample_der(), 0x01, 7).unwrap();
        let alg = ALG_SK_ECDSA_P256.as_bytes();
        let inner_sig_len = 4 + 2 + 4 + 3;
        let expected_inner = 4 + alg.len() + 4 + inner_sig_len + 1 + 4;
        assert_eq!(&blob[0..4], &be32(expected_inner as u32));
        assert_eq!(blob.len(), 4 + expected_inner);
        // flags + counter land at the tail.
        assert_eq!(blob[blob.len() - 5], 0x01);
        assert_eq!(&blob[blob.len() - 4..], &be32(7));
    }

    #[test]
    fn der_parser_rejects_malformed_input() {
        // Not a SEQUENCE.
        assert!(der_ecdsa_to_mpint_pair(&[0x31, 0x00]).is_err());
        // Truncated body.
        assert!(der_ecdsa_to_mpint_pair(&[0x30, 0x10, 0x02]).is_err());
        // Empty.
        assert!(der_ecdsa_to_mpint_pair(&[]).is_err());
        // SEQUENCE holding one INTEGER instead of two.
        assert!(der_ecdsa_to_mpint_pair(&[0x30, 0x03, 0x02, 0x01, 0x05]).is_err());
        // Trailing garbage after the SEQUENCE.
        let mut extra = sample_der();
        extra.push(0x00);
        assert!(der_ecdsa_to_mpint_pair(&extra).is_err());
    }

    #[test]
    fn ed25519_public_key_parses_as_openssh() {
        // The authoritative check: what we emit must round-trip through the
        // same parser russh uses at connect time, and keep the application
        // string we put in it.
        let line = sk_ed25519_public_key(&[0x11u8; 32], "ssh:", "alice@laptop").unwrap();
        assert!(line.starts_with(ALG_SK_ED25519));
        assert!(line.ends_with("alice@laptop"));

        let parsed = russh::keys::ssh_key::PublicKey::from_openssh(&line).unwrap();
        assert_eq!(parsed.algorithm().as_str(), ALG_SK_ED25519);
        let sk = parsed.key_data().sk_ed25519().expect("parses as an sk-ed25519 key");
        assert_eq!(sk.public_key().as_ref(), &[0x11u8; 32]);
        assert_eq!(sk.application(), "ssh:");
    }

    #[test]
    fn ed25519_public_key_carries_a_scoped_application() {
        let line = sk_ed25519_public_key(&[0x22u8; 32], "ssh:prod-bastion", "").unwrap();
        // No comment ⇒ two fields only.
        assert_eq!(line.split_whitespace().count(), 2);
        let parsed = russh::keys::ssh_key::PublicKey::from_openssh(&line).unwrap();
        assert_eq!(
            parsed.key_data().sk_ed25519().unwrap().application(),
            "ssh:prod-bastion"
        );
    }

    #[test]
    fn ed25519_public_key_rejects_a_wrong_length_key() {
        let err = sk_ed25519_public_key(&[0u8; 31], "ssh:", "").unwrap_err();
        assert!(err.contains("32-byte Ed25519 public key"), "{err}");
    }

    #[test]
    fn ecdsa_public_key_parses_as_openssh() {
        // A syntactically valid uncompressed point. `ssh-key` does not verify
        // that it is on the curve at parse time, which is what we want here:
        // this test pins the *encoding*, not the maths.
        let mut point = vec![0x04u8];
        point.extend_from_slice(&[0x33u8; 64]);
        let line = sk_ecdsa_p256_public_key(&point, "ssh:", "alice@laptop").unwrap();
        assert!(line.starts_with(ALG_SK_ECDSA_P256));

        let parsed = russh::keys::ssh_key::PublicKey::from_openssh(&line).unwrap();
        assert_eq!(parsed.algorithm().as_str(), ALG_SK_ECDSA_P256);
    }

    #[test]
    fn ecdsa_public_key_rejects_a_compressed_or_short_point() {
        // Compressed point (0x02 prefix, 33 bytes).
        let mut compressed = vec![0x02u8];
        compressed.extend_from_slice(&[0x44u8; 32]);
        assert!(sk_ecdsa_p256_public_key(&compressed, "ssh:", "").is_err());

        // Right prefix, wrong length.
        let mut short = vec![0x04u8];
        short.extend_from_slice(&[0x44u8; 32]);
        assert!(sk_ecdsa_p256_public_key(&short, "ssh:", "").is_err());

        assert!(sk_ecdsa_p256_public_key(&[], "ssh:", "").is_err());
    }

    #[test]
    fn der_parser_handles_a_realistic_p256_signature() {
        // Both integers 32 bytes with the high bit set, so DER pads each with
        // a leading zero — the 72-byte worst case.
        let mut body = Vec::new();
        for _ in 0..2 {
            body.push(0x02);
            body.push(33);
            body.push(0x00);
            body.extend_from_slice(&[0x80u8; 32]);
        }
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);

        let pair = der_ecdsa_to_mpint_pair(&der).unwrap();
        assert_eq!(pair.len(), (4 + 33) * 2);
        assert_eq!(&pair[0..4], &be32(33));
        assert_eq!(pair[4], 0x00);
    }
}
