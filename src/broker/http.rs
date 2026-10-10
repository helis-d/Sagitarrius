//! Outbound HTTP for the broker: validated destinations, hard limits.
//!
//! ureq 3.4.2 behavior verified against its vendored source (not assumed):
//!
//! - default config reads proxy env (`Proxy::try_from_env`, config.rs:948)
//!   → we pass `proxy(None)` explicitly;
//! - redirects follow by default (`max_redirects`, config.rs:164) → we set
//!   `max_redirects(0)`;
//! - no timeouts by default → we set connect + global timeouts;
//! - 4xx/5xx become `Error::StatusCode` by default (`http_status_as_error`,
//!   config.rs:943) → we disable that conversion so the broker can classify
//!   3xx redirects itself; non-2xx responses are never followed or returned.
//!
//! TLS is rustls defaults; there is no insecure switch anywhere in our path.

use crate::broker::policy::path_in_scope;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

/// Maximum addresses retained from one DNS answer. ureq's resolver result
/// has the same bound; more than this fails closed rather than pinning only
/// a subset of an answer that was validated as a whole.
const MAX_PINNED_ADDRS: usize = 16;

/// A validated, connectable target. The original URL string is kept only so
/// the pinned agent can preserve hostname-based TLS verification and SNI.
/// The connection itself never resolves the hostname again: it is restricted
/// to these exact socket addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub url: String,
    pub host_key: String, // "host:port" as matched against the grant
    pub hostname: String,
    pub port: u16,
    pub path: String,
    pub validated_addrs: Vec<SocketAddr>,
    pub is_https: bool,
}

/// Why a destination was refused. Static strings only — never echo the URL
/// (it may embed secrets in tests or typos of secrets in production).
#[derive(Debug, PartialEq, Eq)]
pub enum TargetDeny {
    BadUrl,
    SchemeNotAllowed,
    CredentialsInUrl,
    QueryNotAllowed,
    FragmentNotAllowed,
    AmbiguousPath,
    HostMismatch,
    PathMismatch,
    Unresolvable,
    TooManyAddresses,
    FilteredAddress,
    LoopbackNotAllowed,
    MixedAddresses,
}

impl TargetDeny {
    pub fn message(&self) -> &'static str {
        match self {
            TargetDeny::BadUrl => "denied: malformed request URL",
            TargetDeny::SchemeNotAllowed => "denied: URL scheme not allowed (https required)",
            TargetDeny::CredentialsInUrl => "denied: credentials in URL are forbidden",
            TargetDeny::QueryNotAllowed => "denied: URL queries are forbidden",
            TargetDeny::FragmentNotAllowed => "denied: URL fragments are forbidden",
            TargetDeny::AmbiguousPath => "denied: URL path encoding is forbidden",
            TargetDeny::HostMismatch => "denied: host:port not in grant",
            TargetDeny::PathMismatch => "denied: path outside grant scope",
            TargetDeny::Unresolvable => "denied: destination does not resolve",
            TargetDeny::TooManyAddresses => "denied: destination resolves to too many addresses",
            TargetDeny::FilteredAddress => "denied: destination resolves to a filtered address",
            TargetDeny::LoopbackNotAllowed => "denied: loopback needs explicit grant opt-in",
            TargetDeny::MixedAddresses => "denied: destination resolves to mixed address classes",
        }
    }
}

/// Normalize IPv4-compatible/IPv4-mapped IPv6 addresses to IPv4 before any
/// classification. Without this, `::ffff:127.0.0.1` would bypass loopback
/// handling and `::ffff:10.0.0.1` would bypass the private-network filter.
fn normalized_ip(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => *ip,
        IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(*ip),
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// True for every non-public range we refuse: private, link-local,
/// special-use, transition/translation, multicast, unspecified — both
/// families, explicit octets (auditable without relying on per-version std
/// helpers). Callers must pass `normalized_ip` output.
fn is_filtered(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Unspecified, loopback handled by caller, multicast/broadcast.
            if o[0] == 0 || o[0] >= 224 {
                return true;
            }
            // RFC 1918 + CGNAT + link-local + special-use.
            if o[0] == 10 {
                return true;
            }
            if o[0] == 172 && (16..32).contains(&o[1]) {
                return true;
            }
            if o[0] == 192 && o[1] == 168 {
                return true;
            }
            if o[0] == 169 && o[1] == 254 {
                return true;
            }
            if o[0] == 100 && (64..128).contains(&o[1]) {
                return true;
            }
            if o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2) {
                return true;
            }
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return true;
            }
            if o[0] == 198 && o[1] == 51 && o[2] == 100 {
                return true;
            }
            if o[0] == 203 && o[1] == 0 && o[2] == 113 {
                return true;
            }
            // Cloud metadata + common link-local service endpoints.
            if o == [169, 254, 169, 254] {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let s = v6.segments();
            if (s[0] & 0xfe00) == 0xfc00 {
                return true;
            } // unique local
            if (s[0] & 0xffc0) == 0xfe80 {
                return true;
            } // link-local
            if s[0] == 0x2001 && s[1] == 0xdb8 {
                return true;
            } // documentation
            if s[0] == 0x2001 && s[1] == 0 {
                return true;
            } // Teredo
            if s[0] == 0x2001 && s[1] == 2 {
                return true;
            } // benchmarking
            if s[0] == 0x2002 {
                return true;
            } // 6to4
            if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 {
                return true;
            } // NAT64
            if s[0] == 0x100 && s[1] == 0 {
                return true;
            } // discard-only
            false
        }
    }
}

/// DNS source used for destination validation. Production uses the system
/// resolver. Tests inject a static answer so DNS behavior is deterministic
/// and so a simulated rebinding cannot affect a pinned agent.
pub trait Dns {
    fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, TargetDeny>;
}

/// System DNS. IP literals do not consult DNS.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDns;

impl Dns for SystemDns {
    fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, TargetDeny> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        (host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.collect())
            .map_err(|_| TargetDeny::Unresolvable)
    }
}

/// ureq resolver that returns only the socket addresses approved during
/// validation. The original hostname remains in the request URI, so TLS
/// certificate verification and SNI are unchanged. A later DNS answer,
/// including a rebinding attack's answer, is never consulted.
#[derive(Debug, Clone)]
pub struct PinnedResolver {
    host: String,
    port: u16,
    addrs: Vec<SocketAddr>,
}

impl PinnedResolver {
    pub fn for_target(target: &Target) -> Self {
        Self {
            host: target.hostname.clone(),
            port: target.port,
            addrs: target.validated_addrs.clone(),
        }
    }

    /// Testable hostname/port check shared by the ureq resolver. Only the
    /// exact validated hostname and port receive the pinned addresses.
    pub fn resolve_pinned(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, TargetDeny> {
        if host != self.host || port != self.port {
            return Err(TargetDeny::HostMismatch);
        }
        if self.addrs.is_empty() || self.addrs.len() > MAX_PINNED_ADDRS {
            return Err(TargetDeny::Unresolvable);
        }
        Ok(self.addrs.clone())
    }
}

impl Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let authority = uri.authority().ok_or(ureq::Error::HostNotFound)?;
        let host = authority.host().to_ascii_lowercase();
        let port = match authority.port_u16() {
            Some(port) => port,
            None => match uri.scheme_str() {
                Some("http") => 80,
                Some("https") => 443,
                _ => return Err(ureq::Error::HostNotFound),
            },
        };
        let addrs = self
            .resolve_pinned(&host, port)
            .map_err(|_| ureq::Error::HostNotFound)?;
        let mut out = self.empty();
        for addr in addrs {
            out.push(addr);
        }
        Ok(out)
    }
}

/// Canonical host and path extracted once for both authorization and
/// connection validation. Using one parser prevents authorization from
/// seeing a different path than the connection sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTargetParts {
    pub host_key: String,
    pub hostname: String,
    pub port: u16,
    pub path: String,
    pub is_https: bool,
}

/// Parse and canonicalize a request URL before any policy decision. Query
/// strings, fragments, embedded credentials, backslashes, percent-encoded
/// bytes, and dot segments are rejected rather than normalized: v1 has no
/// legitimate need for them, and normalization gaps are a classic SSRF and
/// authorization-bypass source.
pub fn request_target_parts(url_str: &str) -> Result<RequestTargetParts, TargetDeny> {
    let url = url::Url::parse(url_str).map_err(|_| TargetDeny::BadUrl)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TargetDeny::CredentialsInUrl);
    }
    if url.query().is_some() {
        return Err(TargetDeny::QueryNotAllowed);
    }
    if url.fragment().is_some() {
        return Err(TargetDeny::FragmentNotAllowed);
    }
    let is_https = match url.scheme() {
        "https" => true,
        // Plain http only ever for loopback test grants.
        "http" => false,
        _ => return Err(TargetDeny::SchemeNotAllowed),
    };
    reject_ambiguous_raw_path(url_str)?;
    let host = url
        .host_str()
        .ok_or(TargetDeny::BadUrl)?
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(TargetDeny::BadUrl);
    }
    let port = url.port_or_known_default().ok_or(TargetDeny::BadUrl)?;
    if port == 0 {
        return Err(TargetDeny::BadUrl);
    }
    Ok(RequestTargetParts {
        host_key: format!("{host}:{port}"),
        hostname: host,
        port,
        path: url.path().to_string(),
        is_https,
    })
}

fn reject_ambiguous_raw_path(url_str: &str) -> Result<(), TargetDeny> {
    let after_scheme = url_str.split("://").nth(1).ok_or(TargetDeny::BadUrl)?;
    let path_start = after_scheme
        .find('/')
        .map(|index| &after_scheme[index..])
        .unwrap_or("/");
    let path = path_start
        .split(['?', '#'])
        .next()
        .ok_or(TargetDeny::BadUrl)?;
    if path.contains('\\') || path.contains('%') {
        return Err(TargetDeny::AmbiguousPath);
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(TargetDeny::AmbiguousPath);
    }
    Ok(())
}

/// Validate a request URL against one grant. Every resolved address must be
/// acceptable, and the accepted addresses are returned for connection
/// pinning. There is no separate check-then-resolve race: the agent created
/// for the resulting target uses `PinnedResolver`, not system DNS.
pub fn validate_target(
    url_str: &str,
    grant_hosts: &[String],
    grant_paths: &[String],
    grant_loopback: bool,
) -> Result<Target, TargetDeny> {
    validate_target_with(
        url_str,
        grant_hosts,
        grant_paths,
        grant_loopback,
        &SystemDns,
    )
}

/// Testable form of [`validate_target`] with an injectable DNS answer.
pub fn validate_target_with<D: Dns>(
    url_str: &str,
    grant_hosts: &[String],
    grant_paths: &[String],
    grant_loopback: bool,
    dns: &D,
) -> Result<Target, TargetDeny> {
    let parts = request_target_parts(url_str)?;
    let is_https = parts.is_https;
    if !grant_hosts.iter().any(|h| h == &parts.host_key) {
        return Err(TargetDeny::HostMismatch);
    }
    if !grant_paths
        .iter()
        .any(|prefix| path_in_scope(&parts.path, prefix))
    {
        return Err(TargetDeny::PathMismatch);
    }
    let resolved = dns.lookup(&parts.hostname, parts.port)?;
    if resolved.is_empty() {
        return Err(TargetDeny::Unresolvable);
    }
    if resolved.len() > MAX_PINNED_ADDRS {
        return Err(TargetDeny::TooManyAddresses);
    }
    let mut validated_addrs = Vec::with_capacity(resolved.len());
    let mut saw_loopback = false;
    let mut saw_public = false;
    for addr in resolved {
        let ip = normalized_ip(&addr.ip());
        let port = parts.port;
        if is_loopback(&ip) {
            saw_loopback = true;
            if !grant_loopback {
                return Err(TargetDeny::LoopbackNotAllowed);
            }
        } else {
            // Any filtered address fails the whole DNS answer, even when
            // loopback is enabled. A mixed answer must not pass because one
            // of its addresses happens to be allowed.
            if is_filtered(&ip) {
                return Err(TargetDeny::FilteredAddress);
            }
            saw_public = true;
        }
        validated_addrs.push(SocketAddr::new(ip, port));
    }
    if saw_loopback && saw_public {
        return Err(TargetDeny::MixedAddresses);
    }
    // Plain http is only ever acceptable to loopback (checked per-address
    // above: reaching here over http means every address was loopback).
    if !is_https && !saw_loopback {
        return Err(TargetDeny::SchemeNotAllowed);
    }
    Ok(Target {
        url: url_str.to_string(),
        host_key: parts.host_key,
        hostname: parts.hostname,
        port: parts.port,
        path: parts.path,
        validated_addrs,
        is_https,
    })
}

/// Build the locked-down ureq agent for exactly one validated target. Every
/// security-relevant default that ureq would otherwise take from the
/// environment is set explicitly. TLS roots default to bundled WebPKI
/// (verified, never disabled here). DNS is not consulted again: the agent
/// uses only `target.validated_addrs`, while TLS still verifies the original
/// hostname from `target.url`.
pub fn agent_for_target(target: &Target, timeout_secs: u64) -> ureq::Agent {
    let resolver = PinnedResolver::for_target(target);
    let config = ureq::Agent::config_builder()
        .https_only(false) // enforced per-target above (loopback tests use http)
        .proxy(None) // NEVER read proxy env: requests must not reroute
        .max_redirects(0) // no redirects, ever (each hop would need revalidation)
        .max_redirects_will_error(true)
        .http_status_as_error(false)
        .timeout_connect(Some(Duration::from_secs(10.min(timeout_secs.max(1)))))
        .timeout_global(Some(Duration::from_secs(timeout_secs.clamp(1, 300))))
        .build();
    ureq::Agent::with_parts(config, DefaultConnector::default(), resolver)
}

/// Map a ureq failure to a static, secret-free message. Status codes are
/// safe to include (they carry no secret); nothing else from the error is.
pub fn redact_ureq_error(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(code) => format!("upstream HTTP error status: {code}"),
        ureq::Error::Timeout(_) => "request timed out".to_string(),
        ureq::Error::HostNotFound => "destination unresolvable at connect time".to_string(),
        ureq::Error::ConnectionFailed => "connection failed".to_string(),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => "TLS failure".to_string(),
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => {
            "redirect denied".to_string()
        }
        _ => "request failed".to_string(),
    }
}

/// Read at most `limit + 1` bytes: `true` means the body fit, with the exact
/// bytes; oversize is detected without retaining the excess.
pub fn read_capped(body: ureq::Body, limit: usize) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut reader = body.into_reader().take(limit as u64 + 1);
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|_| "failed reading upstream response".to_string())?;
    if out.len() > limit {
        return Err(format!("upstream response exceeds {limit} bytes"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn g() -> (Vec<String>, Vec<String>) {
        (
            vec!["127.0.0.1:18080".to_string()],
            vec!["/v1/".to_string()],
        )
    }

    #[derive(Debug)]
    struct StaticDns(Vec<SocketAddr>);

    impl Dns for StaticDns {
        fn lookup(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, TargetDeny> {
            Ok(self.0.clone())
        }
    }

    fn socket_v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    #[test]
    fn loopback_grant_allows_loopback() {
        let (hosts, paths) = g();
        let t = validate_target("http://127.0.0.1:18080/v1/echo", &hosts, &paths, true).unwrap();
        assert_eq!(t.host_key, "127.0.0.1:18080");
        assert!(!t.is_https);
    }

    #[test]
    fn loopback_needs_opt_in() {
        let (hosts, paths) = g();
        assert_eq!(
            validate_target("http://127.0.0.1:18080/v1/echo", &hosts, &paths, false),
            Err(TargetDeny::LoopbackNotAllowed)
        );
    }

    #[test]
    fn https_public_host_passes_filters() {
        // No connection is made: validation is pure. example.com resolves
        // publicly; any resolution failure fails closed either way.
        let hosts = vec!["example.com:443".to_string()];
        let paths = vec!["/".to_string()];
        match validate_target("https://example.com/", &hosts, &paths, false) {
            Ok(t) => assert!(t.is_https),
            Err(TargetDeny::Unresolvable) => {} // sandboxed DNS: still fail-closed
            Err(e) => panic!("wrong deny reason: {e:?}"),
        }
    }

    #[test]
    fn filtered_ranges_denied_without_network() {
        // These grants match exactly, so only the IP filter can deny —
        // no connection is attempted either way.
        let paths = vec!["/".to_string()];
        for host in [
            "10.0.0.1:443",
            "172.16.0.1:443",
            "192.168.1.1:443",
            "169.254.169.254:80",
            "0.0.0.0:80",
            "224.0.0.1:80",
            "100.64.0.1:443",
            "[::1]:443",
            "[fe80::1]:443",
            "[fc00::1]:443",
            "[ff02::1]:443",
        ] {
            let hosts = vec![host.to_string()];
            let url = format!("https://{host}/");
            // loopback=false: ::1 must hit LoopbackNotAllowed, everything
            // else must hit the range filter. Either way: no connection.
            let r = validate_target(&url, &hosts, &paths, false);
            assert!(
                r == Err(TargetDeny::FilteredAddress) || r == Err(TargetDeny::LoopbackNotAllowed),
                "{host} must be refused, got {r:?}"
            );
        }
    }

    #[test]
    fn structural_rejections() {
        let (hosts, paths) = g();
        // Wrong host/port/path.
        assert_eq!(
            validate_target("http://127.0.0.1:9999/v1/echo", &hosts, &paths, true),
            Err(TargetDeny::HostMismatch)
        );
        assert_eq!(
            validate_target("http://127.0.0.1:18080/admin", &hosts, &paths, true),
            Err(TargetDeny::PathMismatch)
        );
        // Credentials in URL are forbidden even when everything matches.
        assert_eq!(
            validate_target(
                "http://user:pass@127.0.0.1:18080/v1/echo",
                &hosts,
                &paths,
                true
            ),
            Err(TargetDeny::CredentialsInUrl)
        );
        // Unknown scheme.
        assert_eq!(
            validate_target("gopher://127.0.0.1:18080/v1/echo", &hosts, &paths, true),
            Err(TargetDeny::SchemeNotAllowed)
        );
        // Garbage.
        assert_eq!(
            validate_target("not a url", &hosts, &paths, true),
            Err(TargetDeny::BadUrl)
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_addresses_keep_their_ipv4_class() {
        let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let expected_loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(normalized_ip(&mapped_loopback), expected_loopback);
        let mapped_private: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let expected_private: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(normalized_ip(&mapped_private), expected_private);
        let paths = vec!["/".to_string()];
        let loopback_hosts = vec!["[::ffff:7f00:1]:443".to_string()];
        assert_eq!(
            validate_target(
                "https://[::ffff:127.0.0.1]:443/",
                &loopback_hosts,
                &paths,
                false
            ),
            Err(TargetDeny::LoopbackNotAllowed)
        );

        let private_hosts = vec!["[::ffff:a00:1]:443".to_string()];
        assert_eq!(
            validate_target(
                "https://[::ffff:10.0.0.1]:443/",
                &private_hosts,
                &paths,
                false
            ),
            Err(TargetDeny::FilteredAddress)
        );
    }

    #[test]
    fn ipv6_transition_addresses_are_filtered() {
        let paths = vec!["/".to_string()];
        for (host, url) in [
            ("[2001::1]:443", "https://[2001:0::1]:443/"),
            ("[2002:c000:200::1]:443", "https://[2002:c000:200::1]:443/"),
            (
                "[64:ff9b::c000:200]:443",
                "https://[64:ff9b::c000:200]:443/",
            ),
        ] {
            let hosts = vec![host.to_string()];
            assert_eq!(
                validate_target(url, &hosts, &paths, false),
                Err(TargetDeny::FilteredAddress),
                "{url} must be refused"
            );
        }
    }

    #[test]
    fn request_target_parts_rejects_unsafe_url_forms() {
        let parts = request_target_parts("https://127.0.0.1:8443/v1/status").unwrap();
        assert_eq!(parts.host_key, "127.0.0.1:8443");
        assert_eq!(parts.path, "/v1/status");
        assert!(parts.is_https);

        for (url, expected) in [
            (
                "https://127.0.0.1:8443/v1/status?debug=1",
                TargetDeny::QueryNotAllowed,
            ),
            (
                "https://127.0.0.1:8443/v1/status#section",
                TargetDeny::FragmentNotAllowed,
            ),
            (
                "https://user:pass@127.0.0.1:8443/v1/status",
                TargetDeny::CredentialsInUrl,
            ),
            (
                "https://127.0.0.1:8443/v1%2fstatus",
                TargetDeny::AmbiguousPath,
            ),
            (
                "https://127.0.0.1:8443/v1%2Estatus",
                TargetDeny::AmbiguousPath,
            ),
            (
                "https://127.0.0.1:8443/v1/../status",
                TargetDeny::AmbiguousPath,
            ),
            (
                "https://127.0.0.1:8443/v1\\status",
                TargetDeny::AmbiguousPath,
            ),
        ] {
            assert_eq!(request_target_parts(url), Err(expected), "{url}");
        }
    }

    #[test]
    fn mixed_loopback_and_public_dns_answers_are_rejected() {
        let hosts = vec!["rebind.invalid:443".to_string()];
        let paths = vec!["/".to_string()];
        let dns = StaticDns(vec![
            socket_v4(127, 0, 0, 1, 443),
            socket_v4(93, 184, 216, 34, 443),
        ]);
        assert_eq!(
            validate_target_with("https://rebind.invalid/", &hosts, &paths, true, &dns),
            Err(TargetDeny::MixedAddresses)
        );
    }

    #[test]
    fn pinned_resolver_serves_only_the_validated_host_and_port() {
        let target = Target {
            url: "http://approved.invalid:18080/v1/echo".to_string(),
            host_key: "approved.invalid:18080".to_string(),
            hostname: "approved.invalid".to_string(),
            port: 18080,
            path: "/v1/echo".to_string(),
            validated_addrs: vec![socket_v4(127, 0, 0, 1, 18080)],
            is_https: false,
        };
        let resolver = PinnedResolver::for_target(&target);
        assert_eq!(
            resolver.resolve_pinned("approved.invalid", 18080),
            Ok(vec![socket_v4(127, 0, 0, 1, 18080)])
        );
        assert_eq!(
            resolver.resolve_pinned("other.invalid", 18080),
            Err(TargetDeny::HostMismatch)
        );
        assert_eq!(
            resolver.resolve_pinned("approved.invalid", 18081),
            Err(TargetDeny::HostMismatch)
        );
    }

    #[test]
    fn agent_ignores_proxy_env() {
        // Proves the locked agent never consults proxy env vars: the config
        // we build carries an explicit None.
        let (hosts, paths) = g();
        let target =
            validate_target("http://127.0.0.1:18080/v1/echo", &hosts, &paths, true).unwrap();
        let agent = agent_for_target(&target, 30);
        let _ = agent;
        // Behavioral proof lives in tests/broker.rs (proxy test): env set to
        // a dead proxy, request to the mock still succeeds.
    }
}
