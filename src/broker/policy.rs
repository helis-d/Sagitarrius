//! Default-deny authorization policy: pure matcher, no I/O, no network.
//!
//! Policy files are operator-written JSON (see `example_policy`
//! in tests). Unknown fields anywhere are rejected at load: an
//! ambiguous policy must never silently grant access.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub credential: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>, // exact "host:port"
    #[serde(default)]
    pub paths: Vec<String>, // path prefixes, e.g. "/v1/"
    #[serde(default)]
    pub headers: BTreeMap<String, String>, // fixed pairs, always sent
    #[serde(default)]
    pub allow_body: bool,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub allow_response_fields: Vec<String>,
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub loopback: bool, // allow 127/8 + ::1 (tests only; warned)
    #[serde(default = "default_credential_use")]
    pub credential_use: String, // "bearer" is the only v1 value
}

fn default_max_body() -> usize {
    4096
}
fn default_max_response() -> usize {
    65536
}
fn default_timeout() -> u64 {
    30
}
fn default_credential_use() -> String {
    "bearer".to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum DenyReason {
    UnknownGrant,
    CredentialMismatch,
    MethodNotAllowed,
    HostNotAllowed,
    PathNotAllowed,
    CredentialUseUnsupported,
}

/// Authorize (credential, method, host, path) against the policy.
/// Returns the matching grant or the exact reason. First match wins;
/// overlapping grants do not widen each other (each request matches at
/// most one grant: the grant id is part of the request).
pub fn authorize<'p>(
    policy: &'p Policy,
    grant_id: &str,
    credential: &str,
    method: &str,
    host: &str,
    path: &str,
) -> Result<&'p Grant, DenyReason> {
    let grant = policy
        .grants
        .iter()
        .find(|g| g.id == grant_id)
        .ok_or(DenyReason::UnknownGrant)?;
    if grant.credential != credential {
        return Err(DenyReason::CredentialMismatch);
    }
    if grant.credential_use != "bearer" {
        return Err(DenyReason::CredentialUseUnsupported);
    }
    if !grant.methods.iter().any(|m| m == method) {
        return Err(DenyReason::MethodNotAllowed);
    }
    if !grant.hosts.iter().any(|h| h == host) {
        return Err(DenyReason::HostNotAllowed);
    }
    if !grant.paths.iter().any(|p| path.starts_with(p.as_str())) {
        return Err(DenyReason::PathNotAllowed);
    }
    Ok(grant)
}

/// Load + validate a policy file. Fails closed on any structural problem.
pub fn load_policy(bytes: &[u8]) -> Result<Policy, String> {
    if bytes.len() > 1024 * 1024 {
        return Err("policy file too large (max 1 MiB)".to_string());
    }
    let policy: Policy =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid policy file: {e}"))?;
    if policy.version != 1 {
        return Err(format!("unsupported policy version: {}", policy.version));
    }
    for grant in &policy.grants {
        validate_grant(grant)?;
    }
    Ok(policy)
}

fn validate_grant(grant: &Grant) -> Result<(), String> {
    let bad = |what: &str| format!("grant {:?}: invalid {what}", grant.id);
    if grant.id.is_empty() || grant.credential.is_empty() {
        return Err(bad("grant/credential must not be empty"));
    }
    if grant.methods.is_empty() || grant.hosts.is_empty() || grant.paths.is_empty() {
        return Err(bad("methods/hosts/paths must not be empty"));
    }
    for host in &grant.hosts {
        // Exact "host:port" shape; deeper checks happen per-request.
        if !host.contains(':') || host.starts_with(':') || host.ends_with(':') {
            return Err(bad("host (expected host:port)"));
        }
        if host.contains(char::is_whitespace) {
            return Err(bad("host (whitespace forbidden)"));
        }
    }
    for path in &grant.paths {
        if !path.starts_with('/') {
            return Err(bad("path (must start with /)"));
        }
    }
    if grant.allow_response_fields.is_empty() {
        return Err(bad("allow_response_fields (must not be empty)"));
    }
    // Header names/values become HTTP headers verbatim: anything outside
    // visible ASCII (or containing controls) would panic the HTTP stack at
    // send time, so it is rejected at policy load instead.
    for (k, v) in &grant.headers {
        let name_ok = !k.is_empty()
            && k.len() <= 256
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let value_ok = v.len() <= 4096 && v.bytes().all(|b| (0x20..0x7f).contains(&b));
        if !name_ok || !value_ok {
            return Err(bad("headers (visible-ASCII names/values only)"));
        }
    }
    if grant.max_body_bytes == 0 || grant.max_body_bytes > 1024 * 1024 {
        return Err(bad("max_body_bytes (1..1MiB)"));
    }
    if grant.max_response_bytes == 0 || grant.max_response_bytes > 16 * 1024 * 1024 {
        return Err(bad("max_response_bytes (1..16MiB)"));
    }
    if grant.timeout_secs == 0 || grant.timeout_secs > 300 {
        return Err(bad("timeout_secs (1..300)"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn example_policy() -> Policy {
        Policy {
            version: 1,
            grants: vec![Grant {
                id: "weather-test".to_string(),
                credential: "TEST_WEATHER_KEY".to_string(),
                methods: vec!["GET".to_string()],
                hosts: vec!["127.0.0.1:18080".to_string()],
                paths: vec!["/v1/".to_string()],
                headers: BTreeMap::from([("X-Test".to_string(), "1".to_string())]),
                allow_body: false,
                max_body_bytes: 4096,
                allow_response_fields: vec!["status".to_string(), "echo".to_string()],
                max_response_bytes: 65536,
                timeout_secs: 30,
                loopback: true,
                credential_use: "bearer".to_string(),
            }],
        }
    }

    #[test]
    fn happy_path_matches() {
        let p = example_policy();
        let g = authorize(
            &p,
            "weather-test",
            "TEST_WEATHER_KEY",
            "GET",
            "127.0.0.1:18080",
            "/v1/echo",
        )
        .unwrap();
        assert_eq!(g.id, "weather-test");
    }

    #[test]
    fn each_mismatch_has_its_reason() {
        let p = example_policy();
        let base = (
            "weather-test",
            "TEST_WEATHER_KEY",
            "GET",
            "127.0.0.1:18080",
            "/v1/echo",
        );
        assert_eq!(
            authorize(&p, "nope", base.1, base.2, base.3, base.4),
            Err(DenyReason::UnknownGrant)
        );
        assert_eq!(
            authorize(&p, base.0, "OTHER", base.2, base.3, base.4),
            Err(DenyReason::CredentialMismatch)
        );
        assert_eq!(
            authorize(&p, base.0, base.1, "POST", base.3, base.4),
            Err(DenyReason::MethodNotAllowed)
        );
        assert_eq!(
            authorize(&p, base.0, base.1, base.2, "evil.example:443", base.4),
            Err(DenyReason::HostNotAllowed)
        );
        assert_eq!(
            authorize(&p, base.0, base.1, base.2, base.3, "/admin"),
            Err(DenyReason::PathNotAllowed)
        );
    }

    #[test]
    fn corrupt_policy_fails_closed() {
        assert!(load_policy(b"not json").is_err());
        assert!(load_policy(b"{\"version\":99,\"grants\":[]}").is_err());
        // Unknown fields are rejected, not ignored.
        assert!(load_policy(br#"{"version":1,"grants":[],"future_flag":true}"#).is_err());
        assert!(load_policy(
            br#"{"version":1,"grants":[{"id":"g","credential":"c","methods":["GET"],"hosts":["h:1"],"paths":["/"],"mystery":1}]}"#
        )
        .is_err());
        // Empty matchers grant nothing.
        assert!(load_policy(br#"{"version":1,"grants":[{"id":"g","credential":"c","methods":[],"hosts":["h:1"],"paths":["/"]}]}"#).is_err());
        // Empty response allowlist.
        assert!(load_policy(br#"{"version":1,"grants":[{"id":"g","credential":"c","methods":["GET"],"hosts":["h:1"],"paths":["/"],"allow_response_fields":[]}]}"#).is_err());
        // Oversized file.
        assert!(load_policy(&vec![b'x'; 2 * 1024 * 1024]).is_err());
    }

    #[test]
    fn header_charset_enforced_at_load() {
        let mut p = example_policy();
        p.grants[0]
            .headers
            .insert("X-Evil".to_string(), "a\nb".to_string());
        assert!(validate_grant(&p.grants[0]).is_err());
        let mut p = example_policy();
        p.grants[0].headers.clear();
        p.grants[0]
            .headers
            .insert("Bad Name".to_string(), "v".to_string());
        assert!(validate_grant(&p.grants[0]).is_err());
    }

    #[test]
    fn unsupported_credential_use_denied() {
        let mut p = example_policy();
        p.grants[0].credential_use = "basic".to_string();
        assert_eq!(
            authorize(
                &p,
                "weather-test",
                "TEST_WEATHER_KEY",
                "GET",
                "127.0.0.1:18080",
                "/v1/echo"
            ),
            Err(DenyReason::CredentialUseUnsupported)
        );
    }
}
