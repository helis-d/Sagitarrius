//! Redacted broker audit: append-only JSONL next to the vault directory.
//!
//! Recorded: timestamp, grant id, credential NAME, method, host, path,
//! outcome, response byte count, redacted error class. NEVER recorded:
//! credential values, passwords, request/response bodies, auth headers,
//! VMK or key material, raw upstream errors.
//!
//! Audit-write failure denies the operation (fail closed): an unaudited
//! grant execution must not silently succeed. The caller decides ordering
//! (audit-then-send vs send-then-audit); both are safe because entries
//! never carry secrets either way. We audit AFTER a successful call so a
//! denied request cannot fill the disk with junk... no — denied requests
//! are audited too (they are the interesting ones), with outcome=denied.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub ts: u64,
    pub grant: String,
    pub credential: String, // NAME only, never the value
    pub method: String,
    pub host: String,
    pub path: String,
    pub outcome: String, // "ok" | "denied: ..." | "error: ..." (static classes)
    pub response_bytes: u64,
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn audit_path(vault_dir: &Path) -> std::path::PathBuf {
    vault_dir.join("broker-audit.jsonl")
}

/// Audit context shared by every event: who was authorized for what.
/// Bundled so `append` stays within argument limits.
pub struct CallContext<'a> {
    pub grant: &'a str,
    pub credential: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
}

pub fn append(
    vault_dir: &Path,
    ctx: &CallContext<'_>,
    outcome: &str,
    response_bytes: u64,
) -> Result<(), String> {
    let event = AuditEvent {
        ts: now_ts(),
        grant: ctx.grant.to_string(),
        credential: ctx.credential.to_string(),
        method: ctx.method.to_string(),
        host: ctx.host.to_string(),
        path: ctx.path.to_string(),
        outcome: outcome.to_string(),
        response_bytes,
    };
    let mut line = serde_json::to_string(&event).map_err(|e| format!("audit encode: {e}"))?;
    line.push('\n');
    if line.len() > 16 * 1024 {
        return Err("audit event too large".to_string());
    }
    append_line(&audit_path(vault_dir), line.as_bytes())
}

#[cfg(unix)]
fn append_line(path: &Path, line: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("audit open: {e}"))?;
    f.write_all(line).map_err(|e| format!("audit write: {e}"))?;
    f.sync_all().map_err(|e| format!("audit sync: {e}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn append_line(path: &Path, line: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("audit open: {e}"))?;
    f.write_all(line).map_err(|e| format!("audit write: {e}"))?;
    f.sync_all().map_err(|e| format!("audit sync: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_shape_has_no_body_fields() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = CallContext {
            grant: "g1",
            credential: "TESTKEY",
            method: "GET",
            host: "127.0.0.1:1",
            path: "/v1/echo",
        };
        append(dir.path(), &ctx, "ok", 12).unwrap();
        let raw = std::fs::read(audit_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        for forbidden in [
            "value",
            "body",
            "password",
            "secret",
            "authorization",
            "vmk",
        ] {
            assert!(
                !v.as_object().unwrap().contains_key(forbidden),
                "audit must not hold {forbidden}"
            );
        }
        assert_eq!(v["credential"], "TESTKEY");
        assert_eq!(v["outcome"], "ok");
    }
}
