//! Default-deny authorization policy: pure matcher, no I/O, no network.
//!
//! Policy files are operator-written JSON (see `example_policy`
//! in tests). Unknown fields anywhere are rejected at load: an
//! ambiguous policy must never silently grant access.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum policy-file size. Callers should enforce this before reading an
/// entire file into memory; the parser rechecks it defensively.
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// Maximum path segments in one response rule. This is also the maximum
/// depth constructed in a filtered response.
pub const MAX_RESPONSE_RULE_DEPTH: usize = 8;
/// Maximum response string length accepted through one string rule.
pub const MAX_RESPONSE_STRING_LEN: usize = 4096;
/// Maximum items accepted through one array rule.
pub const MAX_RESPONSE_ARRAY_ITEMS: usize = 1024;

/// Permitted JSON type for one response field. Objects are deliberately not
/// a permitted kind: every nested value must be selected by an explicit leaf
/// path. This prevents an allowed parent object from smuggling an arbitrary
/// nested `token`, `password`, or `secret` to the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseKind {
    #[serde(rename = "string")]
    Text,
    Integer,
    Number,
    Boolean,
    Null,
    Array,
}

/// Scalar kinds permitted as array elements. Nested arrays and objects are
/// never permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseElementKind {
    #[serde(rename = "string")]
    Text,
    Integer,
    Number,
    Boolean,
    Null,
}

/// One explicitly disclosable response leaf. `path` uses dot-separated
/// object keys, for example `data.id`. There are no wildcards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFieldRule {
    pub path: String,
    pub kind: ResponseKind,
    #[serde(default)]
    pub max_len: Option<usize>,
    #[serde(default)]
    pub max_items: Option<usize>,
    #[serde(default)]
    pub element_kind: Option<ResponseElementKind>,
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
    pub paths: Vec<String>, // path scopes, e.g. "/v1/"
    #[serde(default)]
    pub headers: BTreeMap<String, String>, // fixed pairs, always sent
    #[serde(default)]
    pub allow_body: bool,
    #[serde(default)]
    pub max_body_bytes: usize,
    #[serde(default)]
    pub allow_response_fields: Vec<ResponseFieldRule>,
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub loopback: bool, // allow 127/8 + ::1 (tests only; warned)
    #[serde(default = "default_credential_use")]
    pub credential_use: String, // "bearer" is the only v1 value
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
    if !grant.paths.iter().any(|prefix| path_in_scope(path, prefix)) {
        return Err(DenyReason::PathNotAllowed);
    }
    Ok(grant)
}

/// Segment-aware path-scope check. A `/v1` grant covers exactly `/v1` and
/// paths beneath it (`/v1/status`); it does not cover `/v10`.
pub fn path_in_scope(request_path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return request_path.starts_with('/');
    }
    if request_path == prefix {
        return true;
    }
    request_path
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Load + validate a policy file. Fails closed on any structural problem.
pub fn load_policy(bytes: &[u8]) -> Result<Policy, String> {
    if bytes.len() > MAX_POLICY_BYTES {
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
    if grant.credential_use != "bearer" {
        return Err(bad("credential_use (only \"bearer\" is supported)"));
    }
    if grant.methods.is_empty() || grant.hosts.is_empty() || grant.paths.is_empty() {
        return Err(bad("methods/hosts/paths must not be empty"));
    }
    for method in &grant.methods {
        // The broker implements exactly these methods. Anything else would
        // otherwise pass policy matching and fail only after a credential
        // had been loaded.
        if method != "GET" && method != "POST" {
            return Err(bad("method (only GET and POST are supported)"));
        }
    }
    for host in &grant.hosts {
        // Exact "host:port" shape; deeper checks happen per-request.
        let Some((name, port)) = host.rsplit_once(':') else {
            return Err(bad("host (expected host:port)"));
        };
        let port: u16 = port.parse().unwrap_or(0);
        if name.is_empty()
            || port == 0
            || name != name.to_ascii_lowercase()
            || name.contains(char::is_whitespace)
            || name.contains(char::is_control)
        {
            return Err(bad("host (expected lowercase host:port)"));
        }
    }
    for path in &grant.paths {
        if !path.starts_with('/')
            || path.contains(char::is_whitespace)
            || path.contains(char::is_control)
        {
            return Err(bad("path (must start with /)"));
        }
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            if segment == "." || segment == ".." {
                return Err(bad("path (dot segments are forbidden)"));
            }
        }
    }
    validate_response_rules(&grant.allow_response_fields).map_err(|reason| bad(&reason))?;
    // Header names/values become HTTP headers verbatim: anything outside
    // visible ASCII (or containing controls) would panic the HTTP stack at
    // send time, so it is rejected at policy load instead.
    for (k, v) in &grant.headers {
        let name_ok = !k.is_empty()
            && k.len() <= 256
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        let value_ok = v.len() <= 4096 && v.bytes().all(|b| (0x20..0x7f).contains(&b));
        if !name_ok || !value_ok || is_reserved_header(k) {
            return Err(bad("headers (visible-ASCII names/values only)"));
        }
    }
    // Request bodies are disabled in v1. The fields remain so that enabling
    // them later is explicit; a nonzero body allowance fails closed now.
    if grant.allow_body || grant.max_body_bytes != 0 {
        return Err(bad("body (request bodies are disabled)"));
    }
    if grant.max_response_bytes == 0 || grant.max_response_bytes > 16 * 1024 * 1024 {
        return Err(bad("max_response_bytes (1..16MiB)"));
    }
    if grant.timeout_secs == 0 || grant.timeout_secs > 300 {
        return Err(bad("timeout_secs (1..300)"));
    }
    Ok(())
}

/// Headers controlled by the broker or HTTP itself. A policy must not
/// override authentication, framing, routing, or hop-by-hop behavior.
fn is_reserved_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

fn validate_response_rules(rules: &[ResponseFieldRule]) -> Result<(), String> {
    if rules.is_empty() {
        return Err("allow_response_fields (must not be empty)".to_string());
    }
    let mut paths = Vec::with_capacity(rules.len());
    for rule in rules {
        let segments = split_response_path(&rule.path)?;
        match rule.kind {
            ResponseKind::Text => {
                let Some(max_len) = rule.max_len else {
                    return Err(format!(
                        "response field {:?} (string rules need max_len)",
                        rule.path
                    ));
                };
                if max_len == 0 || max_len > MAX_RESPONSE_STRING_LEN {
                    return Err(format!(
                        "response field {:?} (max_len 1..{MAX_RESPONSE_STRING_LEN})",
                        rule.path
                    ));
                }
                if rule.max_items.is_some() || rule.element_kind.is_some() {
                    return Err(format!(
                        "response field {:?} (unexpected array limits)",
                        rule.path
                    ));
                }
            }
            ResponseKind::Integer
            | ResponseKind::Number
            | ResponseKind::Boolean
            | ResponseKind::Null => {
                if rule.max_len.is_some() || rule.max_items.is_some() || rule.element_kind.is_some()
                {
                    return Err(format!(
                        "response field {:?} (unexpected limits)",
                        rule.path
                    ));
                }
            }
            ResponseKind::Array => {
                let Some(max_items) = rule.max_items else {
                    return Err(format!(
                        "response field {:?} (array rules need max_items)",
                        rule.path
                    ));
                };
                let Some(element_kind) = rule.element_kind else {
                    return Err(format!(
                        "response field {:?} (array rules need element_kind)",
                        rule.path
                    ));
                };
                if max_items == 0 || max_items > MAX_RESPONSE_ARRAY_ITEMS {
                    return Err(format!(
                        "response field {:?} (max_items 1..{MAX_RESPONSE_ARRAY_ITEMS})",
                        rule.path
                    ));
                }
                if element_kind == ResponseElementKind::Text {
                    let Some(max_len) = rule.max_len else {
                        return Err(format!(
                            "response field {:?} (string arrays need max_len)",
                            rule.path
                        ));
                    };
                    if max_len == 0 || max_len > MAX_RESPONSE_STRING_LEN {
                        return Err(format!(
                            "response field {:?} (max_len 1..{MAX_RESPONSE_STRING_LEN})",
                            rule.path
                        ));
                    }
                } else if rule.max_len.is_some() {
                    return Err(format!(
                        "response field {:?} (unexpected max_len)",
                        rule.path
                    ));
                }
            }
        }
        paths.push(segments);
    }
    for (i, a) in paths.iter().enumerate() {
        for b in paths.iter().skip(i + 1) {
            if a == b {
                return Err("allow_response_fields (duplicate path)".to_string());
            }
            let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
            if long.starts_with(short.as_slice()) {
                return Err("allow_response_fields (overlapping paths)".to_string());
            }
        }
    }
    Ok(())
}

fn split_response_path(path: &str) -> Result<Vec<String>, String> {
    if path.is_empty() || path.len() > 256 {
        return Err("response field path (1..256 bytes)".to_string());
    }
    let segments: Vec<String> = path.split('.').map(str::to_string).collect();
    if segments.len() > MAX_RESPONSE_RULE_DEPTH {
        return Err(format!(
            "response field path (maximum depth {MAX_RESPONSE_RULE_DEPTH})"
        ));
    }
    for segment in &segments {
        if segment.is_empty()
            || segment.len() > 64
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("response field path (invalid segment)".to_string());
        }
    }
    Ok(segments)
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
                max_body_bytes: 0,
                allow_response_fields: vec![
                    ResponseFieldRule {
                        path: "status".to_string(),
                        kind: ResponseKind::Text,
                        max_len: Some(64),
                        max_items: None,
                        element_kind: None,
                    },
                    ResponseFieldRule {
                        path: "echo".to_string(),
                        kind: ResponseKind::Text,
                        max_len: Some(64),
                        max_items: None,
                        element_kind: None,
                    },
                ],
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
    fn policy_semantics_fail_closed() {
        assert!(validate_grant(&example_policy().grants[0]).is_ok());

        let mut unsupported_method = example_policy();
        unsupported_method.grants[0].methods = vec!["DELETE".to_string()];
        assert!(validate_grant(&unsupported_method.grants[0]).is_err());

        let mut reserved_header = example_policy();
        reserved_header.grants[0]
            .headers
            .insert("Authorization".to_string(), "x".to_string());
        assert!(validate_grant(&reserved_header.grants[0]).is_err());

        let mut enabled_body = example_policy();
        enabled_body.grants[0].allow_body = true;
        enabled_body.grants[0].max_body_bytes = 1024;
        assert!(validate_grant(&enabled_body.grants[0]).is_err());

        let mut dot_path = example_policy();
        dot_path.grants[0].paths = vec!["/v1/../admin".to_string()];
        assert!(validate_grant(&dot_path.grants[0]).is_err());

        assert!(path_in_scope("/v1", "/v1"));
        assert!(path_in_scope("/v1/status", "/v1/"));
        assert!(!path_in_scope("/v10/status", "/v1"));
        assert!(!path_in_scope("/v10/status", "/v1/"));
        assert!(path_in_scope("/anything", "/"));

        let mut missing_limit = example_policy();
        missing_limit.grants[0].allow_response_fields[0].max_len = None;
        assert!(validate_grant(&missing_limit.grants[0]).is_err());

        let mut overlapping = example_policy();
        overlapping.grants[0]
            .allow_response_fields
            .push(ResponseFieldRule {
                path: "status.detail".to_string(),
                kind: ResponseKind::Text,
                max_len: Some(16),
                max_items: None,
                element_kind: None,
            });
        assert!(validate_grant(&overlapping.grants[0]).is_err());
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
