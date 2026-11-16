//! Host-side logic of the reference Linux helper `bv-idp-host`
//! (`src/bin/bv-idp-host.rs`): the `AuthorizedPrincipalsCommand` decision
//! made from a verified deny feed, and the NSS entries an identity
//! certificate implies. Pure functions, so they are tested here.

use ssh_key::{Certificate, HashAlg, PublicKey};

use crate::{
    entitlement::model::validate_environment_name,
    posix::model::{validate_entity_id, validate_login},
    provider::ssh::{EXT_GID, EXT_UID},
    revoke::feed::DenyFeed,
};

/// The parts of `bv:<entity_id>:<login>:uid=<uid>:env=<environment>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyIdParts {
    pub entity_id: String,
    pub login: String,
    pub uid: u32,
    pub environment: String,
}

/// Parse an identity key id; anything else (another CA's key id, extra
/// fields, a malformed part) is `None`.
pub fn parse_key_id(key_id: &str) -> Option<KeyIdParts> {
    let mut parts = key_id.split(':');
    if parts.next()? != "bv" {
        return None;
    }
    let entity_id = parts.next()?;
    let login = parts.next()?;
    let uid_text = parts.next()?.strip_prefix("uid=")?;
    let environment = parts.next()?.strip_prefix("env=")?;
    if parts.next().is_some() || uid_text.is_empty() || !uid_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let uid = uid_text.parse().ok()?;
    validate_entity_id(entity_id).ok()?;
    validate_login(login).ok()?;
    validate_environment_name(environment).ok()?;
    Some(KeyIdParts { entity_id: entity_id.into(), login: login.into(), uid, environment: environment.into() })
}

/// Why the helper printed no principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDeny {
    KeyId,
    Environment,
    Account,
    Serial,
    IdentityRevoked,
    CertificateRevoked,
}

/// How a host is set up.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostPolicy<'a> {
    /// The environment this host belongs to; a certificate for another is refused.
    pub environment: Option<&'a str>,
    /// One local account every identity logs in as. `None`: each identity
    /// logs in as its own login only.
    pub shared_account: Option<&'a str>,
}

/// sshd's `%u %s %i` (local user, serial in decimal, key id) to the one
/// principal to print. `feed` must already be verified and fresh.
pub fn authorized_principal(
    feed: &DenyFeed,
    policy: &HostPolicy<'_>,
    user: &str,
    serial: &str,
    key_id: &str,
) -> Result<String, HostDeny> {
    let parts = parse_key_id(key_id).ok_or(HostDeny::KeyId)?;
    if policy.environment.is_some_and(|env| env != parts.environment) {
        return Err(HostDeny::Environment);
    }
    let account_ok = match policy.shared_account {
        Some(account) => user == account,
        None => user == parts.login,
    };
    if !account_ok {
        return Err(HostDeny::Account);
    }
    if serial.is_empty() || !serial.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HostDeny::Serial);
    }
    let serial: u64 = serial.parse().map_err(|_| HostDeny::Serial)?;
    if feed.denies(&parts.entity_id, &parts.login, parts.uid) {
        return Err(HostDeny::IdentityRevoked);
    }
    if feed.revokes_serial(serial) {
        return Err(HostDeny::CertificateRevoked);
    }
    Ok(parts.login)
}

/// The identity a certificate carries, once it is proven to come from the
/// trusted CA and to be valid now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertIdentity {
    pub login: String,
    pub uid: u32,
    pub gid: u32,
    pub environment: String,
}

pub fn certificate_identity(cert: &str, trusted_ca: &PublicKey, now: u64) -> Result<CertIdentity, String> {
    let cert = Certificate::from_openssh(cert.trim()).map_err(|e| format!("not an OpenSSH certificate: {e}"))?;
    let fingerprint = trusted_ca.fingerprint(HashAlg::Sha256);
    cert.validate_at(now, [&fingerprint]).map_err(|_| "not signed by the trusted CA, or not valid now".to_string())?;
    let parts = parse_key_id(cert.key_id()).ok_or("key id is not an identity key id")?;
    if cert.valid_principals() != [parts.login.clone()] {
        return Err("principals are not exactly the key id's login".into());
    }
    let ext = |name: &str| -> Result<u32, String> {
        cert.extensions()
            .get(name)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("extension {name} is missing or not a number"))
    };
    let (uid, gid) = (ext(EXT_UID)?, ext(EXT_GID)?);
    if uid != parts.uid {
        return Err("uid extension disagrees with the key id".into());
    }
    Ok(CertIdentity { login: parts.login, uid, gid, environment: parts.environment })
}

/// `libnss-extrausers` lines (`passwd`, `group`) for an identity.
pub fn nss_entries(id: &CertIdentity, home_base: &str, shell: &str) -> (String, String) {
    let home = format!("{}/{}", home_base.trim_end_matches('/'), id.login);
    let passwd = format!("{}:x:{}:{}::{}:{}", id.login, id.uid, id.gid, home, shell);
    let group = format!("{}:x:{}:", id.login, id.gid);
    (passwd, group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revoke::feed::{DeniedIdentity, FEED_FORMAT, FEED_FORMAT_VERSION};

    fn feed(identities: Vec<DeniedIdentity>, serials: &[u64]) -> DenyFeed {
        let mut revoked_serials: Vec<String> = serials.iter().map(|s| format!("{s:016x}")).collect();
        revoked_serials.sort();
        DenyFeed {
            format: FEED_FORMAT.into(),
            format_version: FEED_FORMAT_VERSION,
            feed_version: 1,
            generated_at: 0,
            identities,
            revoked_serials,
        }
    }

    const KID: &str = "bv:e-alice:alice:uid=80017:env=prod";

    #[test]
    fn key_ids_parse_strictly() {
        let p = parse_key_id(KID).unwrap();
        assert_eq!(
            (p.entity_id.as_str(), p.login.as_str(), p.uid, p.environment.as_str()),
            ("e-alice", "alice", 80017, "prod")
        );
        for bad in [
            "",
            "vault-idp-alice",
            "bv:e-alice:alice:uid=80017",
            "bv:e-alice:alice:uid=80017:env=prod:x",
            "bv:e-alice:alice:uid=-1:env=prod",
            "bv:e-alice:alice:uid=+5:env=prod",
            "bv:e-alice:Root:uid=5:env=prod",
            "bv:e/alice:alice:uid=5:env=prod",
            "bv:e-alice:alice:gid=5:env=prod",
            "bv:e-alice:alice:uid=99999999999:env=prod",
        ] {
            assert_eq!(parse_key_id(bad), None, "{bad}");
        }
    }

    #[test]
    fn principal_decision() {
        let clean = feed(vec![], &[]);
        let own = HostPolicy { environment: Some("prod"), shared_account: None };
        assert_eq!(authorized_principal(&clean, &own, "alice", "42", KID), Ok("alice".into()));
        assert_eq!(authorized_principal(&clean, &own, "bob", "42", KID), Err(HostDeny::Account));
        let dev = HostPolicy { environment: Some("dev"), shared_account: None };
        assert_eq!(authorized_principal(&clean, &dev, "alice", "42", KID), Err(HostDeny::Environment));
        let shared = HostPolicy { environment: None, shared_account: Some("ops") };
        assert_eq!(authorized_principal(&clean, &shared, "ops", "42", KID), Ok("alice".into()));
        assert_eq!(authorized_principal(&clean, &shared, "alice", "42", KID), Err(HostDeny::Account));
        assert_eq!(authorized_principal(&clean, &own, "alice", "0x2a", KID), Err(HostDeny::Serial));
        assert_eq!(authorized_principal(&clean, &own, "alice", "42", "other-ca-id"), Err(HostDeny::KeyId));

        let revoked = feed(vec![], &[42, 7]);
        assert_eq!(authorized_principal(&revoked, &own, "alice", "42", KID), Err(HostDeny::CertificateRevoked));
        assert_eq!(authorized_principal(&revoked, &own, "alice", "43", KID), Ok("alice".into()));
        for denied in [
            DeniedIdentity {
                entity_id: "e-alice".into(),
                login: "x".into(),
                uid: 1,
                state: "disabled".into(),
                since: None,
            },
            DeniedIdentity {
                entity_id: "e-x".into(),
                login: "alice".into(),
                uid: 1,
                state: "removed".into(),
                since: None,
            },
            DeniedIdentity {
                entity_id: "e-x".into(),
                login: "x".into(),
                uid: 80017,
                state: "removed".into(),
                since: None,
            },
        ] {
            let f = feed(vec![denied], &[]);
            assert_eq!(authorized_principal(&f, &own, "alice", "42", KID), Err(HostDeny::IdentityRevoked));
        }
    }

    #[test]
    fn nss_lines() {
        let id = CertIdentity { login: "alice".into(), uid: 80017, gid: 80017, environment: "prod".into() };
        let (p, g) = nss_entries(&id, "/home/", "/bin/bash");
        assert_eq!(p, "alice:x:80017:80017::/home/alice:/bin/bash");
        assert_eq!(g, "alice:x:80017:");
    }
}
