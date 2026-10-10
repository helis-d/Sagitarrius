//! `sagitarrius-broker`: use a vault credential for one authorized HTTPS
//! call without ever exposing it to the caller.
//!
//! ```text
//! printf '%s' "$MASTER_PW" | sagitarrius-broker call \
//!   --policy policy.json --request req.json
//! ```
//!
//! stdin carries exactly ONE line: the master password (never the request —
//! request and policy travel as files, so the protocol is unambiguous on
//! every OS). stdout carries exactly ONE JSON envelope line:
//! `{"ok":true,"result":{...}}` or `{"ok":false,"error":"<static reason>"}`.
//! Diagnostics go to stderr. Exit 0 = executed; exit 2 = denied/failed.
//!
//! This is the ONLY binary allowed to open sockets (feature `broker-http`).

use clap::{Parser, Subcommand};
use sagitarrius::broker::{audit, http, policy, request, respond};
use sagitarrius::{platform, storage, vault};
use std::fs::File;
use std::io::{IsTerminal, Read};
use std::path::Path;
use zeroize::Zeroize;

/// Maximum password bytes accepted on stdin. The value is deliberately
/// generous; its purpose is to bound memory before Argon2, not to judge
/// password strength. Unlock attempts are never length-gated otherwise.
const MAX_BROKER_PASSWORD_BYTES: usize = 16 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "sagitarrius-broker",
    version,
    about = "Use a vault credential for one authorized call (credential never leaves the broker)",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Execute one authorized call described by REQUEST against POLICY
    Call {
        /// Operator-written policy file (JSON, default-deny)
        #[arg(long)]
        policy: String,
        /// Request file (JSON: grant, credential, method, url, ...)
        #[arg(long)]
        request: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Call { policy, request } => call(&policy, &request),
    };
    std::process::exit(code);
}

/// Master password for the broker: TTY → hidden prompt, otherwise one
/// stdin line. The `SAGITARRIUS_PASSWORD` env var is deliberately NOT
/// honored here: agent environments inherit env vars, and the broker must
/// not turn an ambient variable into vault access.
fn broker_password() -> Result<String, String> {
    if std::io::stdin().is_terminal() {
        let password = rpassword::prompt_password("Broker master password: ")
            .map_err(|e| format!("password input: {e}"))?;
        if password.len() > MAX_BROKER_PASSWORD_BYTES {
            return Err("password input too long".to_string());
        }
        Ok(password)
    } else {
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .take(MAX_BROKER_PASSWORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("password input: {e}"))?;
        if bytes.len() > MAX_BROKER_PASSWORD_BYTES {
            return Err("password input too long".to_string());
        }
        let mut line =
            String::from_utf8(bytes).map_err(|_| "password input invalid".to_string())?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }
}

fn deny(reason: &str) -> i32 {
    println!("{}", respond::err_envelope(reason));
    2
}

/// Read at most `limit + 1` bytes so an oversized policy or request file
/// cannot exhaust memory before its size is checked.
fn read_bounded_file(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("cannot read file: {e}"))?;
    let len = file
        .metadata()
        .map_err(|e| format!("cannot read file: {e}"))?
        .len();
    if len > limit as u64 {
        return Err("file too large".to_string());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read file: {e}"))?;
    if bytes.len() > limit {
        return Err("file too large".to_string());
    }
    Ok(bytes)
}

/// Best-effort denial audit. The caller still returns the denial envelope;
/// an audit failure is reported on stderr because stdout must remain one
/// machine-readable envelope.
fn audit_denial(vault_dir: &Path, ctx: &audit::CallContext<'_>, outcome: &str) {
    if audit::append(vault_dir, ctx, outcome, 0).is_err() {
        eprintln!("audit write failed for {outcome}");
    }
}

fn call(policy_path: &str, request_path: &str) -> i32 {
    // The trusted audit directory must resolve before anything else. There
    // is deliberately no fallback to the current working directory: an
    // audit event in an unexpected directory is not an audit event.
    let vault_dir = match platform::vault_dir() {
        Ok(dir) => dir,
        Err(_) => return deny("audit unavailable"),
    };
    // 1-2. Load policy + request. Pure validation, no network yet.
    let policy_bytes = match read_bounded_file(policy_path, policy::MAX_POLICY_BYTES) {
        Ok(b) => b,
        Err(_) => return deny("cannot read policy file"),
    };
    let policy = match policy::load_policy(&policy_bytes) {
        Ok(p) => p,
        Err(_) => return deny("invalid policy file"),
    };
    let request_bytes = match read_bounded_file(request_path, request::MAX_REQUEST_BYTES) {
        Ok(b) => b,
        Err(_) => return deny("cannot read request file"),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let req = match request::parse_request(&request_bytes, now) {
        Ok(r) => r,
        Err(_) => return deny("invalid request"),
    };
    // One canonical parser supplies both authorization and connection
    // validation, so the authorized path cannot differ from the sent path.
    let parts = match http::request_target_parts(&req.url) {
        Ok(parts) => parts,
        Err(e) => return deny(e.message()),
    };
    let grant = match policy::authorize(
        &policy,
        &req.grant,
        &req.credential,
        &req.method,
        &parts.host_key,
        &parts.path,
    ) {
        Ok(g) => g,
        Err(_) => {
            let ctx = audit::CallContext {
                grant: &req.grant,
                credential: &req.credential,
                method: &req.method,
                host: &parts.host_key,
                path: &parts.path,
            };
            audit_denial(&vault_dir, &ctx, "denied:policy");
            return deny("denied by policy");
        }
    };
    let target = match http::validate_target(&req.url, &grant.hosts, &grant.paths, grant.loopback) {
        Ok(t) => t,
        Err(e) => {
            let ctx = audit::CallContext {
                grant: &grant.id,
                credential: &req.credential,
                method: &req.method,
                host: &parts.host_key,
                path: &parts.path,
            };
            audit_denial(&vault_dir, &ctx, "denied:destination");
            return deny(e.message());
        }
    };
    let ctx = audit::CallContext {
        grant: &grant.id,
        credential: &req.credential,
        method: &req.method,
        host: &target.host_key,
        path: &target.path,
    };

    // 3. Authenticate the operator: unlock the vault. Lockdown, generation
    // and strip protections apply exactly as in the main CLI.
    if storage::ensure_unlocked().is_err() {
        audit_denial(&vault_dir, &ctx, "denied:lockdown");
        return deny("vault is in lockdown");
    }
    let data = match storage::read_vault() {
        Ok(d) => d,
        Err(_) => {
            audit_denial(&vault_dir, &ctx, "denied:vault-unavailable");
            return deny("vault unavailable");
        }
    };
    let mut password = match broker_password() {
        Ok(p) if !p.is_empty() => p,
        _ => {
            audit_denial(&vault_dir, &ctx, "denied:authentication");
            return deny("authentication failed");
        }
    };
    let vault = match vault::Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(_) => {
            password.zeroize();
            audit_denial(&vault_dir, &ctx, "denied:authentication");
            return deny("authentication failed");
        }
    };
    password.zeroize();
    if sagitarrius::state::verify_generation(&vault).is_err() {
        audit_denial(&vault_dir, &ctx, "denied:stale-vault");
        return deny("vault freshness check failed");
    }

    // 4. Resolve the credential to a bearer value. Only single-value kinds
    //    are brokerable in v1; the value lives only in this scope. The owned
    //    decrypted payload is wiped as soon as its one copy is made. Buffers
    //    inside the HTTP library are not guaranteed to be wiped; that limit
    //    is documented rather than claimed away.
    let mut payload = match vault.get_payload(&req.credential) {
        Some(payload) => payload,
        None => {
            audit_denial(&vault_dir, &ctx, "denied:unknown-credential");
            return deny("unknown credential");
        }
    };
    let mut credential_value = match payload.single_value() {
        Some(value) => value.to_string(),
        None => {
            payload.zeroize();
            audit_denial(&vault_dir, &ctx, "denied:credential-kind");
            return deny("credential kind not brokerable");
        }
    };
    payload.zeroize();
    if credential_value.contains('\0') {
        credential_value.zeroize();
        audit_denial(&vault_dir, &ctx, "denied:credential-unusable");
        return deny("credential unusable");
    }
    // Bearer values become an HTTP header verbatim: controls or non-ASCII
    // would panic the HTTP stack, so deny first (legacy odd values stay
    // usable through every other command).
    if !credential_value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        credential_value.zeroize();
        audit_denial(&vault_dir, &ctx, "denied:credential-unusable");
        return deny("credential unusable");
    }

    // 5. Execute with hard limits. Headers are policy-fixed; the request
    //    carries none, and v1 carries no body. Record the durable intent
    //    first: if it cannot be recorded, do not create a side effect.
    if audit::append(&vault_dir, &ctx, "attempt:authorized", 0).is_err() {
        credential_value.zeroize();
        eprintln!("audit intent write failed; request was not sent");
        return deny("audit unavailable");
    }
    let agent = http::agent_for_target(&target, grant.timeout_secs);
    let auth = format!("Bearer {credential_value}");
    credential_value.zeroize();
    let mut auth_holder = auth;
    let response = match req.method.as_str() {
        "GET" => {
            let mut b = agent.get(&target.url);
            for (k, v) in &grant.headers {
                b = b.header(k.as_str(), v.as_str());
            }
            b = b.header("Authorization", auth_holder.as_str());
            auth_holder.zeroize();
            b.call()
        }
        "POST" => {
            let mut b = agent.post(&target.url);
            for (k, v) in &grant.headers {
                b = b.header(k.as_str(), v.as_str());
            }
            b = b.header("Authorization", auth_holder.as_str());
            auth_holder.zeroize();
            b.send_empty()
        }
        _ => {
            return deny("denied by policy");
        }
    };
    let response = match response {
        Ok(r) => r,
        Err(e) => {
            let outcome = http::redact_ureq_error(&e);
            if audit::append(&vault_dir, &ctx, &format!("error:{outcome}"), 0).is_err() {
                eprintln!("request failed and completion audit failed");
                println!(
                    "{}",
                    respond::err_envelope("request failed; completion audit unavailable")
                );
                return 2;
            }
            println!("{}", respond::err_envelope(&outcome));
            return 2;
        }
    };
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        if audit::append(&vault_dir, &ctx, "error:redirect-denied", 0).is_err() {
            eprintln!("upstream call completed but completion audit failed");
            println!(
                "{}",
                respond::err_envelope("upstream call completed; completion audit unavailable")
            );
            return 2;
        }
        println!("{}", respond::err_envelope("redirect denied"));
        return 2;
    }
    if status != 200 {
        if audit::append(&vault_dir, &ctx, "error:upstream-non-ok-status", 0).is_err() {
            eprintln!("upstream call completed but completion audit failed");
            println!(
                "{}",
                respond::err_envelope("upstream call completed; completion audit unavailable")
            );
            return 2;
        }
        println!(
            "{}",
            respond::err_envelope(&format!("upstream HTTP error status: {status}"))
        );
        return 2;
    }

    // 6. Bounded read + schema-constrained filter. The result prints only
    //    after the completion event lands. A completion-audit failure after
    //    a remote call is reported as possibly already effective: withholding
    //    the response does not undo the side effect.
    let mut bytes = match http::read_capped(response.into_body(), grant.max_response_bytes) {
        Ok(bytes) => bytes,
        Err(e) => {
            let (audit_outcome, envelope) = if e == "failed reading upstream response" {
                (
                    "error:response-unreadable",
                    "failed reading upstream response",
                )
            } else {
                ("error:response-too-large", "upstream response too large")
            };
            if audit::append(&vault_dir, &ctx, audit_outcome, 0).is_err() {
                eprintln!("upstream call completed but completion audit failed");
                println!(
                    "{}",
                    respond::err_envelope("upstream call completed; completion audit unavailable")
                );
                return 2;
            }
            println!("{}", respond::err_envelope(envelope));
            return 2;
        }
    };
    let response_len = bytes.len() as u64;
    let filtered = match respond::filter_response(&bytes, &grant.allow_response_fields) {
        Ok(v) => v,
        Err(_) => {
            if audit::append(&vault_dir, &ctx, "error:response-rejected", response_len).is_err() {
                eprintln!("upstream call completed but completion audit failed");
                println!(
                    "{}",
                    respond::err_envelope("upstream call completed; completion audit unavailable")
                );
                return 2;
            }
            println!("{}", respond::err_envelope("upstream response rejected"));
            return 2;
        }
    };
    bytes.zeroize();
    if audit::append(&vault_dir, &ctx, "ok", response_len).is_err() {
        eprintln!("upstream call may have completed but completion audit failed");
        println!(
            "{}",
            respond::err_envelope("upstream call may have completed; completion audit unavailable")
        );
        return 2;
    }
    println!("{}", respond::ok_envelope(filtered));
    0
}
