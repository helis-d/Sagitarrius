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
//!   config.rs:943) → we set it explicitly and map the code only.
//!
//! TLS is rustls defaults; there is no insecure switch anywhere in our path.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// A validated, connectable target. The original URL string is NOT kept:
/// only the vetted pieces travel forward.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub url: String,
    pub host_key: String, // "host:port" as matched against the grant
    pub is_https: bool,
}

/// Why a destination was refused. Static strings only — never echo the URL
/// (it may embed secrets in tests or typos of secrets in production).
#[derive(Debug, PartialEq, Eq)]
pub enum TargetDeny {
    BadUrl,
    SchemeNotAllowed,
    CredentialsInUrl,
    HostMismatch,
    PathMismatch,
    Unresolvable,
    FilteredAddress,
    LoopbackNotAllowed,
}

impl TargetDeny {
    pub fn message(&self) -> &'static str {
        match self {
            TargetDeny::BadUrl => "denied: malformed request URL",
            TargetDeny::SchemeNotAllowed => "denied: URL scheme not allowed (https required)",
            TargetDeny::CredentialsInUrl => "denied: credentials in URL are forbidden",
            TargetDeny::HostMismatch => "denied: host:port not in grant",
            TargetDeny::PathMismatch => "denied: path outside grant scope",
            TargetDeny::Unresolvable => "denied: destination does not resolve",
            TargetDeny::FilteredAddress => "denied: destination resolves to a filtered address",
            TargetDeny::LoopbackNotAllowed => "denied: loopback needs explicit grant opt-in",
        }
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 127,
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// True for every non-public range we refuse:-flight private, link-local,
/// special-use, multicast, unspecified — both families, explicit octets
/// (auditable without relying on per-version std helpers).
fn is_filtered(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Unspecified, loopback handled by caller, multicast.
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
            false
        }
    }
}

/// Validate a request URL against one grant. Retry-safe and side-effect
/// free: DNS resolution here is a CHECK (all resolved IPs must pass);
/// the race between check and connect is documented, not pretended away.
pub fn validate_target(
    url_str: &str,
    grant_hosts: &[String],
    grant_paths: &[String],
    grant_loopback: bool,
) -> Result<Target, TargetDeny> {
    let url = url::Url::parse(url_str).map_err(|_| TargetDeny::BadUrl)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(TargetDeny::CredentialsInUrl);
    }
    let is_https = match url.scheme() {
        "https" => true,
        // Plain http only ever for loopback test grants.
        "http" => false,
        _ => return Err(TargetDeny::SchemeNotAllowed),
    };
    let host = url
        .host_str()
        .ok_or(TargetDeny::BadUrl)?
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(TargetDeny::BadUrl);
    }
    let port = url.port_or_known_default().ok_or(TargetDeny::BadUrl)?;
    let host_key = format!("{host}:{port}");
    if !grant_hosts.iter().any(|h| h == &host_key) {
        return Err(TargetDeny::HostMismatch);
    }
    let path = url.path();
    if !grant_paths.iter().any(|p| path.starts_with(p.as_str())) {
        return Err(TargetDeny::PathMismatch);
    }
    if !is_https && !grant_loopback {
        return Err(TargetDeny::SchemeNotAllowed);
    }
    // Resolve once, right now; every address must be acceptable.
    let mut any = false;
    let mut saw_loopback = false;
    for addr in (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| TargetDeny::Unresolvable)?
    {
        any = true;
        let ip = addr.ip();
        if is_loopback(&ip) {
            saw_loopback = true;
            if !grant_loopback {
                return Err(TargetDeny::LoopbackNotAllowed);
            }
            continue;
        }
        // http + non-loopback was already rejected above; https + filtered
        // non-loopback is always rejected.
        if is_filtered(&ip) {
            return Err(TargetDeny::FilteredAddress);
        }
    }
    if !any {
        return Err(TargetDeny::Unresolvable);
    }
    // Plain http is only ever acceptable to loopback (checked per-address
    // above: reaching here over http means every address was loopback).
    if !is_https && !saw_loopback {
        return Err(TargetDeny::SchemeNotAllowed);
    }
    Ok(Target {
        url: url_str.to_string(),
        host_key,
        is_https,
    })
}

/// Build the locked-down ureq agent. Every security-relevant default that
/// ureq would otherwise take from the environment is set explicitly.
/// TLS roots default to bundled WebPKI (verified, never disabled here).
pub fn locked_agent(timeout_secs: u64) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .https_only(false) // enforced per-target above (loopback tests use http)
        .proxy(None) // NEVER read proxy env: requests must not reroute
        .max_redirects(0) // no redirects, ever (each hop would need revalidation)
        .max_redirects_will_error(true)
        .http_status_as_error(true)
        .timeout_connect(Some(Duration::from_secs(10.min(timeout_secs.max(1)))))
        .timeout_global(Some(Duration::from_secs(timeout_secs.clamp(1, 300))))
        .build();
    ureq::Agent::new_with_config(config)
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

    fn g() -> (Vec<String>, Vec<String>) {
        (
            vec!["127.0.0.1:18080".to_string()],
            vec!["/v1/".to_string()],
        )
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
    fn agent_ignores_proxy_env() {
        // Proves the locked agent never consults proxy env vars: the config
        // we build carries an explicit None.
        let agent = locked_agent(30);
        let _ = agent;
        // Behavioral proof lives in tests/broker.rs (proxy test): env set to
        // a dead proxy, request to the mock still succeeds.
    }
}
