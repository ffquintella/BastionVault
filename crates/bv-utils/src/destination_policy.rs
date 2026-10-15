//! Where a brokered session may dial (`features/mcp-brokered-sessions.md`
//! §11): the vault's own egress allow-list for agent sessions.
//!
//! The vault dials targets from its own network position, which is often
//! privileged — the cloud metadata service, its own listener, internal admin
//! UIs. The target comes from the resource record, never from the model, but
//! a resource record is ordinary metadata, so the dial itself is checked:
//!
//! 1. **Resolve once.** A host name is resolved exactly once per dial, and
//!    **every** address in the answer is checked. One refused address refuses
//!    the whole answer, so a mixed answer cannot be used to smuggle a refused
//!    address past the check.
//! 2. **Dial the checked address.** [`DestinationPolicy::resolve_and_check`]
//!    returns a [`CheckedTarget`] holding the checked socket addresses, which
//!    is the only thing an executor dials. Nothing re-resolves the name, which
//!    is what stops DNS rebinding between check and connect.
//! 3. **Always denied**, whatever the allow-list says ([`AlwaysDenied`]):
//!    loopback, link-local (including the `169.254.169.254` metadata
//!    address), multicast, unspecified (and the rest of `0.0.0.0/8`),
//!    broadcast, the IPv4-compatible block `::/96`, the vault's own listener
//!    addresses and the cluster's node addresses. No configuration key can
//!    re-allow these.
//! 4. Everything else must fall inside the allow-list, which defaults to
//!    [`DEFAULT_ALLOWED_TARGET_CIDRS`] (RFC 1918 plus IPv6 unique-local).
//!
//! IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to IPv4 before
//! either check, in addresses *and* in allow-list entries, so
//! `::ffff:127.0.0.1` is loopback and `::ffff:10.0.0.0/104` means `10.0.0.0/8`.
//!
//! The parser lives here, in a crate the server config (`bv-core`), the
//! runtime `sys/mcp/config` handler (`bv-kernel`) and the session executors
//! can all reach, so the three agree on what a valid entry is and on what
//! "overlaps an always-denied class" means.
//!
//! **Tests.** In-process test targets listen on loopback, which nothing may
//! re-allow, so a test needs a way past rule 3. That seam
//! ([`DestinationPolicy::permit_for_tests`]) is compiled only under
//! `cfg(test)`; no production constructor and no configuration key can reach
//! it.

use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use ipnetwork::{IpNetwork, Ipv4Network};

/// The allow-list a deployment gets when neither the server config nor the
/// runtime configuration sets one: RFC 1918 plus IPv6 unique-local. Public
/// addresses and CGNAT (`100.64.0.0/10`) need an explicit entry. Confirmed by
/// the owner on 2026-10-14.
pub const DEFAULT_ALLOWED_TARGET_CIDRS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];

/// The stable refusal code every destination refusal carries.
pub const DESTINATION_REFUSED_CODE: &str = "mcp_session_destination_refused";

/// An address class no configuration can allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlwaysDenied {
    Loopback,
    LinkLocal,
    Multicast,
    /// `0.0.0.0/8` ("this network", which on some systems reaches the local
    /// host), `::`, and the deprecated IPv4-compatible block `::/96`.
    Unspecified,
    Broadcast,
    /// One of this vault's own listener addresses.
    VaultListener,
    /// One of the configured cluster node addresses.
    ClusterNode,
}

impl AlwaysDenied {
    /// Every class, in the order an operator-facing listing shows them
    /// (`sys/mcp/config` reports these as read-only).
    pub const ALL: [AlwaysDenied; 7] = [
        Self::Loopback,
        Self::LinkLocal,
        Self::Multicast,
        Self::Unspecified,
        Self::Broadcast,
        Self::VaultListener,
        Self::ClusterNode,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Multicast => "multicast",
            Self::Unspecified => "unspecified",
            Self::Broadcast => "broadcast",
            Self::VaultListener => "vault-listener",
            Self::ClusterNode => "cluster-node",
        }
    }
}

impl fmt::Display for AlwaysDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The fixed always-denied networks, in classification order: a more
/// specific class must come before a broader one that contains it (`::1` is
/// loopback, not part of `::/96`).
const ALWAYS_DENIED_NETS: &[(&str, AlwaysDenied)] = &[
    ("127.0.0.0/8", AlwaysDenied::Loopback),
    ("::1/128", AlwaysDenied::Loopback),
    ("169.254.0.0/16", AlwaysDenied::LinkLocal),
    ("fe80::/10", AlwaysDenied::LinkLocal),
    ("224.0.0.0/4", AlwaysDenied::Multicast),
    ("ff00::/8", AlwaysDenied::Multicast),
    ("0.0.0.0/8", AlwaysDenied::Unspecified),
    ("::/96", AlwaysDenied::Unspecified),
    ("255.255.255.255/32", AlwaysDenied::Broadcast),
];

fn always_denied_nets() -> impl Iterator<Item = (IpNetwork, AlwaysDenied)> {
    ALWAYS_DENIED_NETS.iter().map(|(cidr, class)| {
        (IpNetwork::from_str(cidr).expect("the always-denied table is a list of valid CIDR literals"), *class)
    })
}

/// `::ffff:a.b.c.d` → `a.b.c.d`; every other address unchanged. Only the
/// IPv4-*mapped* form is folded: the IPv4-*compatible* form (`::a.b.c.d`) is
/// deprecated and denied outright as part of `::/96`, and folding it would
/// turn `::1` into `0.0.0.1`.
pub fn normalize_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The fixed (address-class) half of rule 3: which always-denied class, if
/// any, `addr` falls in. Does not know the vault's own or the cluster's
/// addresses; [`DestinationPolicy::check`] adds those.
pub fn always_denied_class(addr: IpAddr) -> Option<AlwaysDenied> {
    let addr = normalize_ip(addr);
    always_denied_nets().find(|(net, _)| net.contains(addr)).map(|(_, class)| class)
}

/// An allow-list entry that is not a CIDR. Names the entry, so the operator
/// can find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTargetCidr {
    pub entry: String,
    pub reason: String,
}

impl fmt::Display for InvalidTargetCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "allowed_target_cidrs entry {:?} is not a valid CIDR: {}", self.entry, self.reason)
    }
}

impl std::error::Error for InvalidTargetCidr {}

/// A parsed, normalized allow-list. Built only by [`parse_target_cidrs`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetCidrs {
    nets: Vec<IpNetwork>,
}

impl TargetCidrs {
    pub fn networks(&self) -> &[IpNetwork] {
        &self.nets
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    fn contains(&self, addr: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(addr))
    }
}

/// What a valid allow-list parsed to, plus the warnings it earns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTargetCidrs {
    pub cidrs: TargetCidrs,
    /// One line per entry that overlaps an always-denied class. The entry is
    /// accepted, and the overlapping addresses stay denied.
    pub warnings: Vec<String>,
}

/// `::ffff:0:0/96` and narrower, rewritten as the IPv4 network it maps, so
/// an entry written in the mapped form matches the normalized address.
fn normalize_net(net: IpNetwork) -> IpNetwork {
    if let IpNetwork::V6(v6) = net {
        if v6.prefix() >= 96 {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                if let Ok(n) = Ipv4Network::new(v4, v6.prefix() - 96) {
                    return IpNetwork::V4(n);
                }
            }
        }
    }
    net
}

/// Parse one allow-list entry. Strict on purpose — this is a security
/// allow-list, so an entry has exactly one reading:
///
/// * it must carry a prefix length (`10.0.0.5/32` for one host): a bare
///   address is refused rather than guessed at;
/// * it must not have host bits set (`10.0.0.1/8` is refused, naming
///   `10.0.0.0/8`), because that is how a typo looks.
pub fn parse_target_cidr(entry: &str) -> Result<IpNetwork, InvalidTargetCidr> {
    let invalid = |reason: String| InvalidTargetCidr { entry: entry.to_string(), reason };
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(invalid("the entry is empty".into()));
    }
    let Some((addr_part, prefix_part)) = trimmed.split_once('/') else {
        return Err(invalid(format!(
            "it has no /prefix-length; write {trimmed}/32 (IPv4) or {trimmed}/128 (IPv6) for one host"
        )));
    };
    let addr =
        IpAddr::from_str(addr_part.trim()).map_err(|e| invalid(format!("{addr_part:?} is not an IP address ({e})")))?;
    let prefix: u8 =
        prefix_part.trim().parse().map_err(|_| invalid(format!("{prefix_part:?} is not a prefix length")))?;
    let net = IpNetwork::new(addr, prefix).map_err(|e| invalid(e.to_string()))?;
    if net.network() != addr {
        return Err(invalid(format!("it has host bits set; did you mean {}/{}?", net.network(), prefix)));
    }
    Ok(normalize_net(net))
}

/// Do two networks share any address?
fn overlaps(a: &IpNetwork, b: &IpNetwork) -> bool {
    match (a, b) {
        (IpNetwork::V4(_), IpNetwork::V4(_)) | (IpNetwork::V6(_), IpNetwork::V6(_)) => {
            a.contains(b.network()) || b.contains(a.network())
        }
        _ => false,
    }
}

/// Parse a whole allow-list. The first invalid entry refuses the list,
/// naming that entry; nothing is dropped silently. An empty list is valid
/// and allows no destination at all.
pub fn parse_target_cidrs<S: AsRef<str>>(entries: &[S]) -> Result<ParsedTargetCidrs, InvalidTargetCidr> {
    let mut nets = Vec::with_capacity(entries.len());
    let mut warnings = Vec::new();
    for entry in entries {
        let entry = entry.as_ref();
        let net = parse_target_cidr(entry)?;
        for (denied, class) in always_denied_nets() {
            if overlaps(&net, &denied) {
                warnings.push(format!(
                    "allowed_target_cidrs entry {:?} overlaps the always-denied {} range {}; addresses in that range stay denied",
                    entry.trim(),
                    class,
                    denied
                ));
            }
        }
        if !nets.contains(&net) {
            nets.push(net);
        }
    }
    Ok(ParsedTargetCidrs { cidrs: TargetCidrs { nets }, warnings })
}

/// The built-in allow-list, parsed.
pub fn default_target_cidrs() -> TargetCidrs {
    parse_target_cidrs(DEFAULT_ALLOWED_TARGET_CIDRS).expect("the default allow-list is valid").cidrs
}

/// Which layer an effective allow-list came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCidrSource {
    /// `sys/mcp/config.brokered_sessions_allowed_target_cidrs`.
    Runtime,
    /// `mcp.brokered_sessions.allowed_target_cidrs` in the server config
    /// (reported as `hcl`, the spec's and the operator's name for that layer,
    /// although a JSON config file sets it the same way).
    ServerConfig,
    /// Neither sets one: [`DEFAULT_ALLOWED_TARGET_CIDRS`].
    Default,
}

impl TargetCidrSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::ServerConfig => "hcl",
            Self::Default => "default",
        }
    }
}

/// The allow-list in force: the runtime value when it is set, else the
/// server config's, else the default. A set list **replaces** the layer
/// below it; it is never merged with it. `Some(&[])` is a set, empty list,
/// which allows no destination.
pub fn effective_target_cidr_entries<'a>(
    runtime: Option<&'a [String]>,
    server_config: Option<&'a [String]>,
) -> (Vec<String>, TargetCidrSource) {
    if let Some(list) = runtime {
        return (list.to_vec(), TargetCidrSource::Runtime);
    }
    if let Some(list) = server_config {
        return (list.to_vec(), TargetCidrSource::ServerConfig);
    }
    (DEFAULT_ALLOWED_TARGET_CIDRS.iter().map(|s| s.to_string()).collect(), TargetCidrSource::Default)
}

/// Why a dial was refused. Every variant reports
/// [`DESTINATION_REFUSED_CODE`]; the message names the address and the rule,
/// never anything from the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationRefusal {
    AlwaysDenied {
        addr: IpAddr,
        class: AlwaysDenied,
    },
    NotAllowed {
        addr: IpAddr,
    },
    /// The name resolved to nothing.
    NoAddresses {
        host: String,
    },
    /// The name could not be resolved.
    Unresolvable {
        host: String,
        reason: String,
    },
}

impl DestinationRefusal {
    pub fn code(&self) -> &'static str {
        DESTINATION_REFUSED_CODE
    }
}

impl fmt::Display for DestinationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlwaysDenied { addr, class } => write!(
                f,
                "{DESTINATION_REFUSED_CODE}: {addr} is a {class} address, which brokered sessions may never dial"
            ),
            Self::NotAllowed { addr } => write!(
                f,
                "{DESTINATION_REFUSED_CODE}: {addr} is outside the brokered-session destination allow-list (allowed_target_cidrs)"
            ),
            Self::NoAddresses { host } => write!(f, "{DESTINATION_REFUSED_CODE}: {host:?} resolved to no address"),
            Self::Unresolvable { host, reason } => {
                write!(f, "{DESTINATION_REFUSED_CODE}: {host:?} could not be resolved: {reason}")
            }
        }
    }
}

impl std::error::Error for DestinationRefusal {}

/// One DNS lookup. Injected so a test can answer with a fixed (for example
/// mixed allowed/refused) set; production uses [`SystemResolver`].
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

/// The platform resolver (`getaddrinfo` through `std`). **Blocking**: an
/// async executor calls [`DestinationPolicy::resolve_and_check`] from a
/// blocking task.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// Socket addresses that passed the policy. The only thing an executor may
/// dial; it cannot be built outside this module, so holding one proves the
/// check ran. Every address in it is normalized and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedTarget {
    addrs: Vec<SocketAddr>,
}

impl CheckedTarget {
    /// The checked addresses, in resolver order. Never empty.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// The address to dial first.
    pub fn primary(&self) -> SocketAddr {
        self.addrs[0]
    }
}

/// The destination policy one dial is checked against. Production code
/// builds it with [`DestinationPolicy::new`], which always applies the
/// always-denied classes.
#[derive(Debug, Clone)]
pub struct DestinationPolicy {
    allowed: TargetCidrs,
    vault_listeners: HashSet<IpAddr>,
    cluster_nodes: HashSet<IpAddr>,
    #[cfg(test)]
    test_permits: Vec<IpNetwork>,
}

impl DestinationPolicy {
    /// `vault_listeners` are this vault's own listener addresses — when a
    /// listener binds an unspecified address, the caller passes every address
    /// of the host's interfaces. `cluster_nodes` are the resolved addresses of
    /// the configured cluster nodes. Both are denied whatever `allowed` says.
    pub fn new(
        allowed: TargetCidrs,
        vault_listeners: impl IntoIterator<Item = IpAddr>,
        cluster_nodes: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            allowed,
            vault_listeners: vault_listeners.into_iter().map(normalize_ip).collect(),
            cluster_nodes: cluster_nodes.into_iter().map(normalize_ip).collect(),
            #[cfg(test)]
            test_permits: Vec::new(),
        }
    }

    /// **Test-only.** Lets addresses inside `net` past the always-denied
    /// classes (an in-process target listens on loopback). Compiled only
    /// under `cfg(test)`; a release build has neither this method nor the
    /// field it sets.
    #[cfg(test)]
    pub fn permit_for_tests(mut self, net: IpNetwork) -> Self {
        self.test_permits.push(normalize_net(net));
        self
    }

    #[cfg(test)]
    fn test_permitted(&self, addr: IpAddr) -> bool {
        self.test_permits.iter().any(|n| n.contains(addr))
    }

    #[cfg(not(test))]
    fn test_permitted(&self, _addr: IpAddr) -> bool {
        false
    }

    /// Check one address. Returns the normalized address on success.
    pub fn check(&self, addr: IpAddr) -> Result<IpAddr, DestinationRefusal> {
        let addr = normalize_ip(addr);
        if self.test_permitted(addr) {
            return Ok(addr);
        }
        if let Some(class) = always_denied_class(addr) {
            return Err(DestinationRefusal::AlwaysDenied { addr, class });
        }
        if self.vault_listeners.contains(&addr) {
            return Err(DestinationRefusal::AlwaysDenied { addr, class: AlwaysDenied::VaultListener });
        }
        if self.cluster_nodes.contains(&addr) {
            return Err(DestinationRefusal::AlwaysDenied { addr, class: AlwaysDenied::ClusterNode });
        }
        if !self.allowed.contains(addr) {
            return Err(DestinationRefusal::NotAllowed { addr });
        }
        Ok(addr)
    }

    /// Resolve `host` once and check every address in the answer. An IP
    /// literal (bare, or an IPv6 literal in brackets) is not sent to the
    /// resolver. Any refused address refuses the whole answer.
    pub fn resolve_and_check(
        &self,
        resolver: &dyn Resolver,
        host: &str,
        port: u16,
    ) -> Result<CheckedTarget, DestinationRefusal> {
        let literal = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
        let resolved: Vec<SocketAddr> = match IpAddr::from_str(literal) {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => resolver
                .resolve(host, port)
                .map_err(|e| DestinationRefusal::Unresolvable { host: host.to_string(), reason: e.to_string() })?,
        };
        if resolved.is_empty() {
            return Err(DestinationRefusal::NoAddresses { host: host.to_string() });
        }
        let mut addrs = Vec::with_capacity(resolved.len());
        for sa in resolved {
            let ip = self.check(sa.ip())?;
            let checked = SocketAddr::new(ip, sa.port());
            if !addrs.contains(&checked) {
                addrs.push(checked);
            }
        }
        Ok(CheckedTarget { addrs })
    }
}

/// A single address or a CIDR block, the form an OpenSSH certificate's
/// `source-address` critical option takes. Looser than
/// [`parse_target_cidr`] on purpose: this names the vault's own egress
/// addresses, not an allow-list.
pub fn is_address_or_cidr(entry: &str) -> bool {
    let entry = entry.trim();
    !entry.is_empty() && IpNetwork::from_str(entry).is_ok()
}

/// `true` when `addr` is an IPv4 or IPv6 unspecified address: what a listener
/// bound to "every interface" reports, and therefore the signal for a caller
/// to enumerate the host's interface addresses into
/// [`DestinationPolicy::new`]'s `vault_listeners`.
pub fn is_unspecified_bind(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6 == Ipv6Addr::UNSPECIFIED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn policy(entries: &[&str]) -> DestinationPolicy {
        DestinationPolicy::new(parse_target_cidrs(entries).unwrap().cidrs, [], [])
    }

    struct FixedResolver(Vec<SocketAddr>);

    impl Resolver for FixedResolver {
        fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }
    }

    /// Panics if the policy ever consults it: IP literals must not resolve.
    struct NoResolver;

    impl Resolver for NoResolver {
        fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            panic!("resolver consulted for {host:?}");
        }
    }

    #[test]
    fn default_allows_rfc1918_and_unique_local_only() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        for ok in ["10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.10.20", "fd12:3456::1", "fc00::1"] {
            assert_eq!(p.check(ip(ok)), Ok(ip(ok)), "{ok}");
        }
        for refused in ["8.8.8.8", "100.64.0.1", "172.32.0.1", "2001:db8::1", "11.0.0.1"] {
            assert_eq!(p.check(ip(refused)), Err(DestinationRefusal::NotAllowed { addr: ip(refused) }), "{refused}");
        }
    }

    #[test]
    fn always_denied_classes_are_refused_with_their_class() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        for (addr, class) in [
            ("127.0.0.1", AlwaysDenied::Loopback),
            ("127.8.9.10", AlwaysDenied::Loopback),
            ("::1", AlwaysDenied::Loopback),
            ("169.254.169.254", AlwaysDenied::LinkLocal),
            ("169.254.1.1", AlwaysDenied::LinkLocal),
            ("fe80::1", AlwaysDenied::LinkLocal),
            ("224.0.0.1", AlwaysDenied::Multicast),
            ("239.255.255.250", AlwaysDenied::Multicast),
            ("ff02::1", AlwaysDenied::Multicast),
            ("0.0.0.0", AlwaysDenied::Unspecified),
            ("0.1.2.3", AlwaysDenied::Unspecified),
            ("::", AlwaysDenied::Unspecified),
            ("::7f00:1", AlwaysDenied::Unspecified),
            ("255.255.255.255", AlwaysDenied::Broadcast),
        ] {
            assert_eq!(p.check(ip(addr)), Err(DestinationRefusal::AlwaysDenied { addr: ip(addr), class }), "{addr}");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_is_normalized_before_both_checks() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        assert_eq!(
            p.check(ip("::ffff:127.0.0.1")),
            Err(DestinationRefusal::AlwaysDenied { addr: ip("127.0.0.1"), class: AlwaysDenied::Loopback })
        );
        assert_eq!(
            p.check(ip("::ffff:169.254.169.254")),
            Err(DestinationRefusal::AlwaysDenied { addr: ip("169.254.169.254"), class: AlwaysDenied::LinkLocal })
        );
        // Allowed in its IPv4 form, so allowed in its mapped form.
        assert_eq!(p.check(ip("::ffff:10.0.0.7")), Ok(ip("10.0.0.7")));
        // A mapped-form allow-list entry means the IPv4 network.
        let mapped = policy(&["::ffff:203.0.113.0/120"]);
        assert_eq!(mapped.check(ip("203.0.113.9")), Ok(ip("203.0.113.9")));
    }

    /// Rule 3 holds against the operator: every always-denied class stays
    /// denied when an entry lists it explicitly, or lists everything.
    #[test]
    fn explicitly_listed_always_denied_ranges_stay_denied() {
        let p = policy(&["0.0.0.0/0", "::/0", "127.0.0.0/8", "169.254.169.254/32", "::ffff:127.0.0.1/128"]);
        for addr in ["127.0.0.1", "::1", "169.254.169.254", "::ffff:127.0.0.1", "224.0.0.1", "0.0.0.0", "fe80::1"] {
            assert!(matches!(p.check(ip(addr)), Err(DestinationRefusal::AlwaysDenied { .. })), "{addr}");
        }
        // ... while ordinary addresses are now allowed.
        assert_eq!(p.check(ip("8.8.8.8")), Ok(ip("8.8.8.8")));
    }

    #[test]
    fn vault_listener_and_cluster_node_addresses_are_always_denied() {
        let p = DestinationPolicy::new(
            parse_target_cidrs(&["0.0.0.0/0"]).unwrap().cidrs,
            [ip("10.0.0.5")],
            [ip("::ffff:10.0.0.6")],
        );
        assert_eq!(
            p.check(ip("10.0.0.5")),
            Err(DestinationRefusal::AlwaysDenied { addr: ip("10.0.0.5"), class: AlwaysDenied::VaultListener })
        );
        assert_eq!(
            p.check(ip("::ffff:10.0.0.5")),
            Err(DestinationRefusal::AlwaysDenied { addr: ip("10.0.0.5"), class: AlwaysDenied::VaultListener })
        );
        assert_eq!(
            p.check(ip("10.0.0.6")),
            Err(DestinationRefusal::AlwaysDenied { addr: ip("10.0.0.6"), class: AlwaysDenied::ClusterNode })
        );
        assert_eq!(p.check(ip("10.0.0.7")), Ok(ip("10.0.0.7")));
        assert!(is_unspecified_bind(ip("0.0.0.0")) && is_unspecified_bind(ip("::")));
        assert!(!is_unspecified_bind(ip("10.0.0.5")));
    }

    #[test]
    fn address_or_cidr_accepts_both_forms_only() {
        for ok in ["203.0.113.7", "203.0.113.0/24", "2001:db8::1", "2001:db8::/32", " 10.0.0.1 "] {
            assert!(is_address_or_cidr(ok), "{ok}");
        }
        for bad in ["", "host.example", "10.0.0.0/40", "10.0.0.1-10.0.0.9"] {
            assert!(!is_address_or_cidr(bad), "{bad}");
        }
    }

    #[test]
    fn an_empty_allow_list_allows_nothing() {
        let p = policy(&[]);
        assert_eq!(p.check(ip("10.0.0.1")), Err(DestinationRefusal::NotAllowed { addr: ip("10.0.0.1") }));
    }

    #[test]
    fn malformed_entries_are_refused_naming_the_entry() {
        for (entry, needle) in [
            ("", "empty"),
            ("   ", "empty"),
            ("10.0.0.5", "no /prefix-length"),
            ("not-an-ip/8", "not an IP address"),
            ("10.0.0.0/33", "prefix"),
            ("10.0.0.0/abc", "not a prefix length"),
            ("10.0.0.1/8", "host bits"),
            ("2001:db8::1/32", "host bits"),
            ("10.0.0.0/-1", "not a prefix length"),
            ("fc00::/129", "prefix"),
        ] {
            let err = parse_target_cidrs(&["10.0.0.0/8", entry]).unwrap_err();
            assert_eq!(err.entry, entry, "{entry:?}");
            assert!(err.reason.contains(needle), "{entry:?}: {}", err.reason);
            assert!(err.to_string().contains(&format!("{entry:?}")), "the message names the entry");
        }
        let err = parse_target_cidrs(&["10.0.0.1/8"]).unwrap_err();
        assert!(err.reason.contains("10.0.0.0/8"), "the host-bits refusal names the network: {}", err.reason);
    }

    #[test]
    fn overlapping_entries_are_accepted_with_a_warning_and_have_no_effect() {
        let parsed = parse_target_cidrs(&["10.0.0.0/8", "127.0.0.0/8", "169.254.169.254/32"]).unwrap();
        assert_eq!(parsed.cidrs.networks().len(), 3);
        assert_eq!(parsed.warnings.len(), 2, "{:?}", parsed.warnings);
        assert!(parsed.warnings[0].contains("\"127.0.0.0/8\"") && parsed.warnings[0].contains("loopback"));
        assert!(parsed.warnings[1].contains("169.254.169.254/32") && parsed.warnings[1].contains("link-local"));
        assert!(parse_target_cidrs(DEFAULT_ALLOWED_TARGET_CIDRS).unwrap().warnings.is_empty());
        // `0.0.0.0/0` overlaps every IPv4 class.
        let all = parse_target_cidrs(&["0.0.0.0/0"]).unwrap();
        assert_eq!(all.warnings.len(), 5, "{:?}", all.warnings);
    }

    #[test]
    fn effective_list_prefers_runtime_then_server_config_then_default() {
        let runtime = vec!["10.1.0.0/16".to_string()];
        let hcl = vec!["10.2.0.0/16".to_string()];
        let empty: Vec<String> = Vec::new();
        assert_eq!(
            effective_target_cidr_entries(Some(runtime.as_slice()), Some(hcl.as_slice())),
            (runtime.clone(), TargetCidrSource::Runtime)
        );
        assert_eq!(
            effective_target_cidr_entries(None, Some(hcl.as_slice())),
            (hcl.clone(), TargetCidrSource::ServerConfig)
        );
        let (default, source) = effective_target_cidr_entries(None, None);
        assert_eq!(source, TargetCidrSource::Default);
        assert_eq!(default, DEFAULT_ALLOWED_TARGET_CIDRS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // An empty list replaces the layer below it: it does not fall through.
        assert_eq!(
            effective_target_cidr_entries(Some(empty.as_slice()), Some(hcl.as_slice())),
            (empty.clone(), TargetCidrSource::Runtime)
        );
        // The names `sys/mcp/config` reports for each layer.
        let names: Vec<&str> =
            [TargetCidrSource::Runtime, TargetCidrSource::ServerConfig, TargetCidrSource::Default]
                .iter()
                .map(|s| s.as_str())
                .collect();
        assert_eq!(names, ["runtime", "hcl", "default"]);
        let classes: Vec<&str> = AlwaysDenied::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            classes,
            ["loopback", "link-local", "multicast", "unspecified", "broadcast", "vault-listener", "cluster-node"]
        );
    }

    #[test]
    fn a_mixed_dns_answer_is_refused_as_a_whole() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        let mixed = FixedResolver(vec!["10.0.0.9:22".parse().unwrap(), "169.254.169.254:22".parse().unwrap()]);
        assert_eq!(
            p.resolve_and_check(&mixed, "web-01.internal", 22),
            Err(DestinationRefusal::AlwaysDenied { addr: ip("169.254.169.254"), class: AlwaysDenied::LinkLocal })
        );
        let outside = FixedResolver(vec!["10.0.0.9:22".parse().unwrap(), "8.8.8.8:22".parse().unwrap()]);
        assert!(matches!(
            p.resolve_and_check(&outside, "web-01.internal", 22),
            Err(DestinationRefusal::NotAllowed { .. })
        ));
    }

    #[test]
    fn a_clean_answer_yields_exactly_the_checked_normalized_addresses() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        let answer = FixedResolver(vec![
            "[::ffff:10.0.0.9]:22".parse().unwrap(),
            "10.0.0.9:22".parse().unwrap(),
            "[fd00::9]:22".parse().unwrap(),
        ]);
        let target = p.resolve_and_check(&answer, "web-01.internal", 22).unwrap();
        assert_eq!(target.addrs(), &["10.0.0.9:22".parse().unwrap(), "[fd00::9]:22".parse().unwrap()]);
        assert_eq!(target.primary(), "10.0.0.9:22".parse().unwrap());
    }

    #[test]
    fn empty_and_failed_resolution_are_refused() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        assert_eq!(
            p.resolve_and_check(&FixedResolver(vec![]), "nothing.internal", 22),
            Err(DestinationRefusal::NoAddresses { host: "nothing.internal".into() })
        );
        struct Failing;
        impl Resolver for Failing {
            fn resolve(&self, _: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
                Err(std::io::Error::other("NXDOMAIN"))
            }
        }
        let err = p.resolve_and_check(&Failing, "gone.internal", 22).unwrap_err();
        assert!(matches!(err, DestinationRefusal::Unresolvable { .. }));
        assert_eq!(err.code(), DESTINATION_REFUSED_CODE);
        assert!(err.to_string().starts_with(DESTINATION_REFUSED_CODE));
    }

    #[test]
    fn ip_literals_are_checked_without_a_lookup() {
        let p = DestinationPolicy::new(default_target_cidrs(), [], []);
        assert_eq!(p.resolve_and_check(&NoResolver, "10.0.0.3", 22).unwrap().primary(), "10.0.0.3:22".parse().unwrap());
        assert_eq!(
            p.resolve_and_check(&NoResolver, "[fd00::3]", 22).unwrap().primary(),
            "[fd00::3]:22".parse().unwrap()
        );
        assert!(matches!(
            p.resolve_and_check(&NoResolver, "[::ffff:127.0.0.1]", 22),
            Err(DestinationRefusal::AlwaysDenied { class: AlwaysDenied::Loopback, .. })
        ));
    }

    /// The test seam is the only way past rule 3, and it is test-only: the
    /// same loopback address is refused by every policy built through the
    /// production constructor, whatever allow-list it was given.
    #[test]
    fn only_the_test_seam_admits_loopback() {
        let wide = || parse_target_cidrs(&["0.0.0.0/0", "::/0", "127.0.0.0/8"]).unwrap().cidrs;
        assert!(DestinationPolicy::new(wide(), [], []).check(ip("127.0.0.1")).is_err());
        let seamed =
            DestinationPolicy::new(wide(), [], []).permit_for_tests(IpNetwork::from_str("127.0.0.0/8").unwrap());
        assert_eq!(seamed.check(ip("127.0.0.1")), Ok(ip("127.0.0.1")));
        assert!(seamed.check(ip("169.254.169.254")).is_err(), "the seam admits only what it names");
    }
}
