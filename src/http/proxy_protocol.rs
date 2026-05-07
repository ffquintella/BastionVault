//! HAProxy PROXY-protocol v1 + v2 acceptor (skeleton — not yet wired
//! into the actix-web listener).
//!
//! Wave 2 / Phase 1.5 of the Packaging & Distribution roadmap.
//!
//! ## Status
//!
//! This module ships the **parser** for both PROXY-protocol versions,
//! sufficient to extract the original client `(SocketAddr, SocketAddr)`
//! pair from the leading bytes of a TCP connection. What it does NOT
//! yet do is intercept the connection before actix-web's
//! `request_on_connect_handler` runs — that requires either:
//!
//! 1. a custom `actix_server::ServerBuilder::bind_uri` that wraps the
//!    `TcpListener` accept loop, or
//! 2. a small reverse-proxy "shim" listener that accepts PROXY headers
//!    and forwards plain TCP to actix-web on a localhost port.
//!
//! Both options are non-trivial and out of scope for the parser-only
//! Phase 1.5 deliverable. The `BASTIONVAULT_PROXY_PROTOCOL` env var is
//! parsed and validated, and a future PR will wire the parser into the
//! listener once the design choice between (1) and (2) is settled. In
//! the interim, deployments behind an L4 LB can still get correct
//! client IPs via `BASTIONVAULT_TRUSTED_PROXIES` + `X-Forwarded-For`,
//! which IS wired in this phase.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// `BASTIONVAULT_PROXY_PROTOCOL` config — `off` (default), `v1`, `v2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyProtocolMode {
    #[default]
    Off,
    V1,
    V2,
}

impl ProxyProtocolMode {
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("BASTIONVAULT_PROXY_PROTOCOL") {
            Ok(v) => v.parse(),
            Err(_) => Ok(Self::Off),
        }
    }
}

impl std::str::FromStr for ProxyProtocolMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" | "0" | "false" | "no" => Ok(Self::Off),
            "v1" | "1" => Ok(Self::V1),
            "v2" | "2" => Ok(Self::V2),
            other => Err(format!(
                "invalid BASTIONVAULT_PROXY_PROTOCOL `{other}`; expected off|v1|v2"
            )),
        }
    }
}

/// Successfully parsed PROXY header. `None` for `LOCAL` connections
/// that the protocol allows (health checks, etc.) — the listener
/// should fall back to the socket peer in that case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHeader {
    Tcp { client: SocketAddr, server: SocketAddr },
    Local,
    Unknown,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyParseError {
    #[error("PROXY header truncated")]
    Truncated,
    #[error("not a PROXY-protocol header")]
    NotProxy,
    #[error("malformed PROXY-protocol header: {0}")]
    Malformed(&'static str),
}

const V1_PREFIX: &[u8] = b"PROXY ";
const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Try to parse a v1 ASCII header. Returns `Ok(Some((header, len)))` on
/// success (caller advances `len` bytes past the CRLF), `Ok(None)` if
/// the buffer doesn't start with the v1 prefix, or `Err` if the buffer
/// starts with the prefix but is malformed / truncated.
pub fn parse_v1(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyParseError> {
    if !buf.starts_with(V1_PREFIX) {
        return Ok(None);
    }
    // v1 ends in CRLF; the spec caps total length at 107 bytes.
    let max = buf.len().min(108);
    let crlf = buf[..max]
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(ProxyParseError::Truncated)?;
    let line = std::str::from_utf8(&buf[V1_PREFIX.len()..crlf])
        .map_err(|_| ProxyParseError::Malformed("non-utf8"))?;
    let total = crlf + 2;

    // Forms: "TCP4 src dst sport dport", "TCP6 ...", "UNKNOWN ...".
    let mut parts = line.split_whitespace();
    let proto = parts.next().ok_or(ProxyParseError::Malformed("no proto"))?;
    if proto == "UNKNOWN" {
        return Ok(Some((ProxyHeader::Unknown, total)));
    }

    let src = parts.next().ok_or(ProxyParseError::Malformed("no src"))?;
    let dst = parts.next().ok_or(ProxyParseError::Malformed("no dst"))?;
    let sport: u16 = parts
        .next()
        .ok_or(ProxyParseError::Malformed("no sport"))?
        .parse()
        .map_err(|_| ProxyParseError::Malformed("bad sport"))?;
    let dport: u16 = parts
        .next()
        .ok_or(ProxyParseError::Malformed("no dport"))?
        .parse()
        .map_err(|_| ProxyParseError::Malformed("bad dport"))?;

    let (client, server) = match proto {
        "TCP4" => {
            let s: Ipv4Addr = src.parse().map_err(|_| ProxyParseError::Malformed("bad v4 src"))?;
            let d: Ipv4Addr = dst.parse().map_err(|_| ProxyParseError::Malformed("bad v4 dst"))?;
            (
                SocketAddr::V4(SocketAddrV4::new(s, sport)),
                SocketAddr::V4(SocketAddrV4::new(d, dport)),
            )
        }
        "TCP6" => {
            let s: Ipv6Addr = src.parse().map_err(|_| ProxyParseError::Malformed("bad v6 src"))?;
            let d: Ipv6Addr = dst.parse().map_err(|_| ProxyParseError::Malformed("bad v6 dst"))?;
            (
                SocketAddr::V6(SocketAddrV6::new(s, sport, 0, 0)),
                SocketAddr::V6(SocketAddrV6::new(d, dport, 0, 0)),
            )
        }
        _ => return Err(ProxyParseError::Malformed("unknown proto")),
    };

    Ok(Some((ProxyHeader::Tcp { client, server }, total)))
}

/// Try to parse a v2 binary header. Returns `Ok(Some(..))` on success,
/// `Ok(None)` if the buffer doesn't start with the v2 signature.
pub fn parse_v2(buf: &[u8]) -> Result<Option<(ProxyHeader, usize)>, ProxyParseError> {
    if buf.len() < 16 {
        if buf.starts_with(&V2_SIG[..buf.len().min(V2_SIG.len())]) {
            return Err(ProxyParseError::Truncated);
        }
        return Ok(None);
    }
    if buf[..12] != V2_SIG {
        return Ok(None);
    }

    let ver_cmd = buf[12];
    if ver_cmd >> 4 != 0x2 {
        return Err(ProxyParseError::Malformed("not v2"));
    }
    let cmd = ver_cmd & 0x0F;
    let fam = buf[13];
    let len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total = 16 + len;
    if buf.len() < total {
        return Err(ProxyParseError::Truncated);
    }
    let body = &buf[16..total];

    // cmd: 0=LOCAL, 1=PROXY. fam: 0x11=TCPv4, 0x21=TCPv6, others=UNSPEC.
    if cmd == 0 {
        return Ok(Some((ProxyHeader::Local, total)));
    }
    let header = match fam {
        0x11 if body.len() >= 12 => {
            let s = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let d = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
            let sp = u16::from_be_bytes([body[8], body[9]]);
            let dp = u16::from_be_bytes([body[10], body[11]]);
            ProxyHeader::Tcp {
                client: SocketAddr::V4(SocketAddrV4::new(s, sp)),
                server: SocketAddr::V4(SocketAddrV4::new(d, dp)),
            }
        }
        0x21 if body.len() >= 36 => {
            let mut sb = [0u8; 16];
            sb.copy_from_slice(&body[..16]);
            let mut db = [0u8; 16];
            db.copy_from_slice(&body[16..32]);
            let sp = u16::from_be_bytes([body[32], body[33]]);
            let dp = u16::from_be_bytes([body[34], body[35]]);
            ProxyHeader::Tcp {
                client: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(sb), sp, 0, 0)),
                server: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(db), dp, 0, 0)),
            }
        }
        _ => ProxyHeader::Unknown,
    };
    Ok(Some((header, total)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses_off_v1_v2() {
        assert_eq!("off".parse::<ProxyProtocolMode>().unwrap(), ProxyProtocolMode::Off);
        assert_eq!("v1".parse::<ProxyProtocolMode>().unwrap(), ProxyProtocolMode::V1);
        assert_eq!("V2".parse::<ProxyProtocolMode>().unwrap(), ProxyProtocolMode::V2);
        assert!("nope".parse::<ProxyProtocolMode>().is_err());
    }

    #[test]
    fn v1_tcp4_round_trip() {
        let raw = b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 5678\r\nHELO";
        let (hdr, n) = parse_v1(raw).unwrap().unwrap();
        assert_eq!(n, raw.len() - 4); // ate the header + CRLF, left "HELO"
        assert_eq!(
            hdr,
            ProxyHeader::Tcp {
                client: "192.0.2.1:1234".parse().unwrap(),
                server: "198.51.100.2:5678".parse().unwrap(),
            }
        );
    }

    #[test]
    fn v1_unknown_is_recognised() {
        let raw = b"PROXY UNKNOWN\r\n";
        let (hdr, _) = parse_v1(raw).unwrap().unwrap();
        assert_eq!(hdr, ProxyHeader::Unknown);
    }

    #[test]
    fn v1_truncated_errors() {
        let raw = b"PROXY TCP4 192.0.2.1 198.51.100.2 1234 5678";
        let err = parse_v1(raw).unwrap_err();
        matches!(err, ProxyParseError::Truncated);
    }

    #[test]
    fn v1_returns_none_when_not_v1() {
        let raw = b"GET / HTTP/1.1\r\n";
        assert!(parse_v1(raw).unwrap().is_none());
    }

    #[test]
    fn v2_tcp4_round_trip() {
        // Construct a v2 PROXY (cmd=1) TCPv4 (fam=0x11) header.
        let mut buf = V2_SIG.to_vec();
        buf.push(0x21); // ver=2, cmd=1 (PROXY)
        buf.push(0x11); // fam=TCPv4
        buf.extend_from_slice(&12u16.to_be_bytes()); // body len
        buf.extend_from_slice(&[192, 0, 2, 1]);
        buf.extend_from_slice(&[198, 51, 100, 2]);
        buf.extend_from_slice(&1234u16.to_be_bytes());
        buf.extend_from_slice(&5678u16.to_be_bytes());

        let (hdr, n) = parse_v2(&buf).unwrap().unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(
            hdr,
            ProxyHeader::Tcp {
                client: "192.0.2.1:1234".parse().unwrap(),
                server: "198.51.100.2:5678".parse().unwrap(),
            }
        );
    }

    #[test]
    fn v2_local_is_recognised() {
        let mut buf = V2_SIG.to_vec();
        buf.push(0x20); // ver=2, cmd=0 (LOCAL)
        buf.push(0x00);
        buf.extend_from_slice(&0u16.to_be_bytes());
        let (hdr, _) = parse_v2(&buf).unwrap().unwrap();
        assert_eq!(hdr, ProxyHeader::Local);
    }
}
