//! The four cipher suites this client speaks, and nothing else.

/// An ECDHE-RSA AES-CBC cipher suite (RFC 4492 / RFC 5289), TLS 1.2 only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    /// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` (0xC028), PRF SHA-384.
    EcdheRsaAes256CbcSha384,
    /// `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` (0xC027), PRF SHA-256.
    EcdheRsaAes128CbcSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` (0xC014), PRF SHA-256.
    EcdheRsaAes256CbcSha,
    /// `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` (0xC013), PRF SHA-256.
    EcdheRsaAes128CbcSha,
}

/// The suites offered in the ClientHello, in preference order.
pub(crate) const OFFERED: [CipherSuite; 4] = [
    CipherSuite::EcdheRsaAes256CbcSha384,
    CipherSuite::EcdheRsaAes128CbcSha256,
    CipherSuite::EcdheRsaAes256CbcSha,
    CipherSuite::EcdheRsaAes128CbcSha,
];

/// The record MAC of a suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MacAlg {
    Sha1,
    Sha256,
    Sha384,
}

impl MacAlg {
    pub(crate) const fn len(self) -> usize {
        match self {
            MacAlg::Sha1 => 20,
            MacAlg::Sha256 => 32,
            MacAlg::Sha384 => 48,
        }
    }
}

/// The PRF / handshake hash of a suite (RFC 5246 §5: SHA-256 unless the
/// suite says otherwise; RFC 5289 says SHA-384 for the `_SHA384` suite).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrfHash {
    Sha256,
    Sha384,
}

impl CipherSuite {
    /// The IANA code point.
    pub const fn id(self) -> u16 {
        match self {
            CipherSuite::EcdheRsaAes256CbcSha384 => 0xC028,
            CipherSuite::EcdheRsaAes128CbcSha256 => 0xC027,
            CipherSuite::EcdheRsaAes256CbcSha => 0xC014,
            CipherSuite::EcdheRsaAes128CbcSha => 0xC013,
        }
    }

    /// The IANA name, for logs and diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            CipherSuite::EcdheRsaAes256CbcSha384 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            CipherSuite::EcdheRsaAes128CbcSha256 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            CipherSuite::EcdheRsaAes256CbcSha => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            CipherSuite::EcdheRsaAes128CbcSha => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        }
    }

    /// The suite with code point `id`, if it is one this client offers.
    pub fn from_id(id: u16) -> Option<Self> {
        OFFERED.into_iter().find(|s| s.id() == id)
    }

    pub(crate) const fn mac(self) -> MacAlg {
        match self {
            CipherSuite::EcdheRsaAes256CbcSha384 => MacAlg::Sha384,
            CipherSuite::EcdheRsaAes128CbcSha256 => MacAlg::Sha256,
            CipherSuite::EcdheRsaAes256CbcSha | CipherSuite::EcdheRsaAes128CbcSha => MacAlg::Sha1,
        }
    }

    /// AES key length in bytes.
    pub(crate) const fn enc_key_len(self) -> usize {
        match self {
            CipherSuite::EcdheRsaAes256CbcSha384 | CipherSuite::EcdheRsaAes256CbcSha => 32,
            CipherSuite::EcdheRsaAes128CbcSha256 | CipherSuite::EcdheRsaAes128CbcSha => 16,
        }
    }

    pub(crate) const fn prf(self) -> PrfHash {
        match self {
            CipherSuite::EcdheRsaAes256CbcSha384 => PrfHash::Sha384,
            _ => PrfHash::Sha256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_points_and_parameters_match_the_rfcs() {
        let table = [
            (0xC028, 48, 32, PrfHash::Sha384),
            (0xC027, 32, 16, PrfHash::Sha256),
            (0xC014, 20, 32, PrfHash::Sha256),
            (0xC013, 20, 16, PrfHash::Sha256),
        ];
        for (suite, (id, mac_len, key_len, prf)) in OFFERED.into_iter().zip(table) {
            assert_eq!(suite.id(), id);
            assert_eq!(suite.mac().len(), mac_len);
            assert_eq!(suite.enc_key_len(), key_len);
            assert_eq!(suite.prf(), prf);
            assert_eq!(CipherSuite::from_id(id), Some(suite));
        }
        // GCM, ChaCha20 and static-RSA CBC suites are not this client's.
        for other in [0xC02F, 0xCCA8, 0x002F, 0x0035, 0x00FF] {
            assert_eq!(CipherSuite::from_id(other), None);
        }
    }
}
