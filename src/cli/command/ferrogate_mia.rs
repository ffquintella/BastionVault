//! Client side of the FerroGate MIA helper API + DPoP proof construction,
//! used by the `bvault ferrogate` subcommands.
//!
//! The MIA (Machine Identity Agent) exposes a local Unix-domain socket
//! (`/run/ferrogate/mia.sock` by default) speaking a length-delimited CBOR
//! request/response protocol: a 4-byte big-endian length prefix followed by a
//! CBOR body. We send a [`HelperReq`] and receive a [`HelperResp`] carrying a
//! short-lived, DPoP-bound child token. This module re-declares that wire
//! schema (mirroring `mia::helper::proto`) and speaks it over a blocking
//! `std` socket — the CLI has no async runtime.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

/// Default MIA helper socket path on Linux.
pub const DEFAULT_MIA_SOCKET: &str = "/run/ferrogate/mia.sock";

/// Largest frame we will read or write (matches the MIA's `MAX_FRAME_LEN`).
const MAX_FRAME_LEN: usize = 64 * 1024;

/// A token request to the MIA. Mirrors `mia::helper::proto::HelperReq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperReq {
    pub audience: String,
    pub dpop_jkt: String,
    pub ttl_secs: u32,
}

/// A minted child token. Mirrors `mia::helper::proto::ChildToken`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildToken {
    pub jws: String,
    pub exp: i64,
}

/// Refusal opcodes. Mirrors `mia::helper::proto::ErrorCode`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    PermissionDenied,
    NoHostSvid,
    CrlStale,
    MalformedRequest,
    RateLimited,
    Internal,
}

/// The MIA's reply. Mirrors `mia::helper::proto::HelperResp` (externally tagged).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HelperResp {
    Token(ChildToken),
    Error { code: ErrorCode, retry_after: Option<u32> },
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// An ephemeral DPoP key (RFC 9449). The CLI generates one per invocation,
/// tells the MIA its thumbprint so the minted token is bound to it, then signs
/// a DPoP proof per HTTP request with the private half.
pub struct DpopKey {
    signing: SigningKey,
    /// base64url of the Ed25519 public key `x` coordinate (the JWK `x`).
    x_b64url: String,
}

impl DpopKey {
    /// Generate a fresh Ed25519 DPoP key.
    pub fn generate() -> Self {
        let seed: [u8; 32] = rand::random();
        let signing = SigningKey::from_bytes(&seed);
        let x_b64url = b64(signing.verifying_key().as_bytes());
        Self { signing, x_b64url }
    }

    /// RFC 7638 JWK thumbprint (`cnf.jkt`) — must equal the value the MIA
    /// embeds in the child token's `cnf`.
    pub fn jkt(&self) -> String {
        ferro_child_verify::jwk_thumbprint_ed25519(&self.x_b64url)
    }

    /// Build a DPoP proof JWS binding this request to `(htm, htu)`.
    pub fn proof(&self, htm: &str, htu: &str) -> String {
        let jti: [u8; 16] = rand::random();
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": { "kty": "OKP", "crv": "Ed25519", "x": self.x_b64url },
        });
        let claims = serde_json::json!({
            "jti": hex::encode(jti),
            "htm": htm,
            "htu": htu,
            "iat": now_unix(),
        });
        let h = b64(&serde_json::to_vec(&header).unwrap());
        let p = b64(&serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.signing.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64(&sig.to_bytes()))
    }
}

/// Request a child token from the MIA for `audience`, bound to `dpop_jkt`.
pub fn request_child_token(
    socket_path: &str,
    audience: &str,
    dpop_jkt: &str,
    ttl_secs: u32,
) -> Result<ChildToken, String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        format!("ferrogate_mia_unavailable: cannot connect to the MIA helper socket at {socket_path}: {e}")
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let req = HelperReq { audience: audience.to_string(), dpop_jkt: dpop_jkt.to_string(), ttl_secs };
    let mut body = Vec::with_capacity(256);
    ciborium::into_writer(&req, &mut body).map_err(|e| format!("cbor encode: {e}"))?;
    let len = u32::try_from(body.len()).map_err(|_| "request too large".to_string())?;
    stream.write_all(&len.to_be_bytes()).map_err(|e| format!("write: {e}"))?;
    stream.write_all(&body).map_err(|e| format!("write: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| format!("read: {e}"))?;
    let rlen = u32::from_be_bytes(len_buf) as usize;
    if rlen > MAX_FRAME_LEN {
        return Err(format!("MIA response frame too large: {rlen} bytes"));
    }
    let mut rbody = vec![0u8; rlen];
    stream.read_exact(&mut rbody).map_err(|e| format!("read: {e}"))?;
    let resp: HelperResp = ciborium::from_reader(&rbody[..]).map_err(|e| format!("cbor decode: {e}"))?;

    match resp {
        HelperResp::Token(t) => Ok(t),
        HelperResp::Error { code, retry_after } => {
            let hint = retry_after.map(|s| format!(" (retry after {s}s)")).unwrap_or_default();
            Err(format!("MIA refused to mint a token: {code:?}{hint}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferro_child_verify::{verify_dpop_proof, DpopExpectation};

    #[test]
    fn dpop_proof_verifies_against_ferrogate_verifier() {
        // The CLI's DPoP proof + thumbprint must satisfy the same verifier the
        // server uses (ferro-child-verify), or login would always fail.
        let key = DpopKey::generate();
        let jkt = key.jkt();
        let htu = "https://vault.example.com";
        let proof = key.proof("POST", htu);
        let expect = DpopExpectation { htm: "POST", htu, max_age_secs: 300 };
        let ok = verify_dpop_proof(&proof, &expect, now_unix(), 60).expect("DPoP proof verifies");
        assert_eq!(ok.jkt, jkt, "proof thumbprint must equal jkt()");
    }

    #[test]
    fn helper_frames_roundtrip_cbor() {
        // Lock the wire format against mia::helper::proto.
        let req = HelperReq {
            audience: "https://vault.example.com".into(),
            dpop_jkt: "abc".into(),
            ttl_secs: 300,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let back: HelperReq = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(back.audience, req.audience);

        let resp = HelperResp::Token(ChildToken { jws: "a.b.c".into(), exp: 42 });
        let mut rbuf = Vec::new();
        ciborium::into_writer(&resp, &mut rbuf).unwrap();
        let rback: HelperResp = ciborium::from_reader(&rbuf[..]).unwrap();
        assert!(matches!(rback, HelperResp::Token(t) if t.exp == 42));
    }
}

/// Decode (without verifying) the claims segment of a compact JWS and return
/// the requested string field — used by `whoami` to read the local SPIFFE id
/// from a freshly minted token.
pub fn jws_claim_str(jws: &str, field: &str) -> Option<String> {
    let seg = jws.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(seg).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get(field)?.as_str().map(str::to_string)
}
