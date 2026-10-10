//! Redacted broker audit: append-only JSONL next to the vault directory.
//!
//! Recorded: timestamp, grant id, credential NAME, method, host, path,
//! outcome, response byte count, redacted error class. NEVER recorded:
//! credential values, passwords, request/response bodies, auth headers,
//! VMK or key material, raw upstream errors.
//!
//! The broker writes an `attempt:authorized` intent record after it has
//! loaded and validated the credential, but before it sends the HTTP
//! request. If the intent record cannot be written, the request is not
//! sent. A completion record is written afterward. If the completion record
//! fails, the broker reports that a remote side effect may already have
//! occurred; withholding the response does not undo that side effect.
//!
//! On Unix, an existing audit file must already be a non-symlink regular
//! file; the broker tightens it to mode 0600. Windows has no Unix mode bits,
//! so the deployment must restrict the vault directory with ACLs.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Maximum audit-file size. The file is append-only, so this bounds log
/// growth. When the file is full, broker operations fail closed.
pub const MAX_AUDIT_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum length for any metadata field in one audit event. Policy and
/// request values are bounded here even though they were validated earlier.
pub const MAX_AUDIT_FIELD_LEN: usize = 1024;

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

fn validate_field(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_AUDIT_FIELD_LEN {
        return Err(format!("audit {name} invalid"));
    }
    if value.contains('\0') {
        return Err(format!("audit {name} invalid"));
    }
    Ok(())
}

fn validate_audit_path(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("audit path is a symlink".to_string());
            }
            if !metadata.is_file() {
                return Err("audit path is not a regular file".to_string());
            }
            if metadata.len() > MAX_AUDIT_FILE_BYTES {
                return Err("audit log is full".to_string());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut permissions = metadata.permissions();
                if permissions.mode() & 0o077 != 0 {
                    permissions.set_mode(0o600);
                    std::fs::set_permissions(path, permissions)
                        .map_err(|e| format!("audit permissions: {e}"))?;
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("audit metadata: {e}")),
    }
    Ok(())
}

pub fn append(
    vault_dir: &Path,
    ctx: &CallContext<'_>,
    outcome: &str,
    response_bytes: u64,
) -> Result<(), String> {
    validate_field("grant", ctx.grant)?;
    validate_field("credential", ctx.credential)?;
    validate_field("method", ctx.method)?;
    validate_field("host", ctx.host)?;
    validate_field("path", ctx.path)?;
    validate_field("outcome", outcome)?;
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
    let path = audit_path(vault_dir);
    validate_audit_path(&path)?;
    append_line(&path, line.as_bytes())
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

    fn test_context() -> CallContext<'static> {
        CallContext {
            grant: "g1",
            credential: "TESTKEY",
            method: "GET",
            host: "127.0.0.1:1",
            path: "/v1/echo",
        }
    }

    #[test]
    fn oversized_metadata_is_rejected_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = test_context();
        // Leak the overlong test string so its lifetime matches CallContext.
        let leaked: &'static str = Box::leak("x".repeat(MAX_AUDIT_FIELD_LEN + 1).into_boxed_str());
        ctx.path = leaked;
        assert!(append(dir.path(), &ctx, "ok", 12).is_err());
        assert!(!audit_path(dir.path()).exists());
    }

    #[test]
    fn missing_audit_parent_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-parent");
        assert!(append(&missing, &test_context(), "attempt:authorized", 0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn audit_symlink_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-audit.jsonl");
        std::fs::write(&target, "{}\n").unwrap();
        std::os::unix::fs::symlink(&target, audit_path(dir.path())).unwrap();
        assert!(append(dir.path(), &test_context(), "ok", 12).is_err());
    }
}
