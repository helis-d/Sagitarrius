//! Broker request schema: strict, deny-unknown-fields, no network types.
//!
//! The agent supplies this JSON. Every field is untrusted data: the grant id
//! selects exactly one policy entry, and everything else must match it
//! literally. Notably there is NO headers/body freedom: v1 requests carry
//! no headers at all (policy-fixed headers are always sent) and no body.
//! Query strings, fragments, and embedded credentials are rejected.

use serde::{Deserialize, Serialize};

/// ±5 minutes. No cross-call replay cache in v1 (documented limitation):
/// the window bounds abuse, it does not prevent in-window replay of an
/// idempotent test call.
pub const TIMESTAMP_SKEW_SECS: u64 = 300;

/// Maximum request-file size. Callers should enforce this before reading an
/// entire file into memory; the parser rechecks it defensively.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequest {
    pub grant: String,
    pub credential: String,
    pub method: String,
    pub url: String,
    pub timestamp: u64,
    pub nonce: String,
}

pub fn parse_request(bytes: &[u8], now_secs: u64) -> Result<BrokerRequest, String> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("request too large (max 64 KiB)".to_string());
    }
    let req: BrokerRequest =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid request JSON: {e}"))?;
    if req.grant.is_empty() || req.credential.is_empty() {
        return Err("request grant/credential must not be empty".to_string());
    }
    if req.method != "GET" && req.method != "POST" {
        return Err("request method invalid".to_string());
    }
    if req.url.is_empty() || req.url.len() > 4096 {
        return Err("request url invalid".to_string());
    }
    validate_request_url_shape(&req.url)?;
    if req.nonce.is_empty() || req.nonce.len() > 256 {
        return Err("request nonce invalid".to_string());
    }
    let skew = req.timestamp.abs_diff(now_secs);
    if skew > TIMESTAMP_SKEW_SECS {
        return Err(format!(
            "request timestamp outside ±{TIMESTAMP_SKEW_SECS}s window"
        ));
    }
    Ok(req)
}

/// Syntactic URL screen without the `url` crate (which is broker-HTTP-only).
/// Full parsing and canonicalization happen again immediately before
/// authorization and sending.
fn validate_request_url_shape(url: &str) -> Result<(), String> {
    let rest = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if url.to_ascii_lowercase().starts_with("http://")
        || url.to_ascii_lowercase().starts_with("https://")
    {
        return Err("request url scheme must be lowercase http or https".to_string());
    } else {
        return Err("request url scheme must be http or https".to_string());
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(authority_end);
    if authority.is_empty() || authority.contains('@') {
        return Err("request url authority invalid".to_string());
    }
    if target.contains('#') {
        return Err("request url fragments are forbidden".to_string());
    }
    if target.contains('?') {
        return Err("request url queries are forbidden".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_req() -> serde_json::Value {
        serde_json::json!({
            "grant": "g1",
            "credential": "C",
            "method": "GET",
            "url": "https://127.0.0.1:1/v1/echo",
            "timestamp": 1_700_000_000u64,
            "nonce": "n-1"
        })
    }

    #[test]
    fn happy_path_parses() {
        let r = parse_request(base_req().to_string().as_bytes(), 1_700_000_000).unwrap();
        assert_eq!(r.grant, "g1");
    }

    #[test]
    fn hostile_requests_rejected_before_network() {
        let now = 1_700_000_000u64;
        // Unknown fields (headers freedom, extra authority) are denied.
        for (name, mut v) in [
            ("headers", base_req()),
            ("extra", base_req()),
            ("credential_use", base_req()),
        ] {
            v[name] = serde_json::json!("x");
            assert!(
                parse_request(v.to_string().as_bytes(), now).is_err(),
                "{name} must be rejected"
            );
        }
        // Malformed / empty / oversized.
        assert!(parse_request(b"{", now).is_err());
        assert!(parse_request(b"", now).is_err());
        let mut v = base_req();
        v["method"] = serde_json::json!("");
        assert!(parse_request(v.to_string().as_bytes(), now).is_err());
        // Stale + future timestamps.
        let mut v = base_req();
        v["timestamp"] = serde_json::json!(1_700_000_000u64 - 301);
        assert!(parse_request(v.to_string().as_bytes(), now).is_err());
        let mut v = base_req();
        v["timestamp"] = serde_json::json!(1_700_000_000u64 + 301);
        assert!(parse_request(v.to_string().as_bytes(), now).is_err());
        // Request bodies are disabled: the field itself is unknown.
        let mut v = base_req();
        v["body"] = serde_json::Value::String("x".to_string());
        assert!(parse_request(v.to_string().as_bytes(), now).is_err());
        // Queries, fragments, credentials, and unsupported methods fail here.
        for url in [
            "https://127.0.0.1:1/v1/echo?debug=1",
            "https://127.0.0.1:1/v1/echo#section",
            "https://user:pass@127.0.0.1:1/v1/echo",
            "gopher://127.0.0.1:1/v1/echo",
        ] {
            let mut v = base_req();
            v["url"] = serde_json::Value::String(url.to_string());
            assert!(
                parse_request(v.to_string().as_bytes(), now).is_err(),
                "{url} must be rejected"
            );
        }
        let mut v = base_req();
        v["method"] = serde_json::Value::String("DELETE".to_string());
        assert!(parse_request(v.to_string().as_bytes(), now).is_err());
        // Oversized request.
        assert!(parse_request(&vec![b'x'; 70 * 1024], now).is_err());
    }
}
