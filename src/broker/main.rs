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
use std::io::IsTerminal;
use zeroize::Zeroize;

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
        rpassword::prompt_password("Broker master password: ")
            .map_err(|e| format!("password input: {e}"))
    } else {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)
            .map_err(|e| format!("password input: {e}"))?;
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

fn call(policy_path: &str, request_path: &str) -> i32 {
    // 1-2. Load policy + request. Pure validation, no network yet.
    let policy_bytes = match std::fs::read(policy_path) {
        Ok(b) => b,
        Err(_) => return deny("cannot read policy file"),
    };
    let policy = match policy::load_policy(&policy_bytes) {
        Ok(p) => p,
        Err(_) => return deny("invalid policy file"),
    };
    let request_bytes = match std::fs::read(request_path) {
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
    // Strict URL shape first (cheap, no policy involved yet).
    let parsed = match url::Url::parse(&req.url) {
        Ok(u) => u,
        Err(_) => return deny("denied: malformed request URL"),
    };
    let host_key = match parsed.host_str() {
        Some(h) => format!(
            "{}:{}",
            h.to_ascii_lowercase(),
            parsed.port_or_known_default().unwrap_or(0)
        ),
        None => return deny("denied: malformed request URL"),
    };
    let req_path = parsed.path().to_string();
    let grant = match policy::authorize(
        &policy,
        &req.grant,
        &req.credential,
        &req.method,
        &host_key,
        &req_path,
    ) {
        Ok(g) => g,
        Err(_) => return deny("denied by policy"),
    };
    let target = match http::validate_target(&req.url, &grant.hosts, &grant.paths, grant.loopback) {
        Ok(t) => t,
        Err(e) => return deny(e.message()),
    };

    // 3. Authenticate the operator: unlock the vault. Lockdown, generation
    // and strip protections apply exactly as in the main CLI.
    if storage::ensure_unlocked().is_err() {
        return deny("vault is in lockdown");
    }
    let data = match storage::read_vault() {
        Ok(d) => d,
        Err(_) => return deny("vault unavailable"),
    };
    let mut password = match broker_password() {
        Ok(p) if !p.is_empty() => p,
        _ => return deny("authentication failed"),
    };
    let vault = match vault::Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(_) => {
            password.zeroize();
            return deny("authentication failed");
        }
    };
    password.zeroize();
    if sagitarrius::state::verify_generation(&vault).is_err() {
        return deny("vault freshness check failed");
    }

    // 4. Resolve the credential to a bearer value. Only single-value kinds
    //    are brokerable in v1; the value lives only in this scope.
    let mut credential_value = match vault.get_payload(&req.credential) {
        Some(p) => match p.single_value() {
            Some(v) => v.to_string(),
            None => return deny("credential kind not brokerable"),
        },
        None => return deny("unknown credential"),
    };
    if credential_value.contains('\0') {
        credential_value.zeroize();
        return deny("credential unusable");
    }
    // Bearer values become an HTTP header verbatim: controls or non-ASCII
    // would panic the HTTP stack, so deny first (legacy odd values stay
    // usable through every other command).
    if !credential_value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        credential_value.zeroize();
        return deny("credential unusable");
    }

    // 5. Execute with hard limits. Headers are policy-fixed; the request
    //    carries none (schema rejects them). GET and POST builders are
    //    different types, so each arm sends separately (no shared builder).
    let agent = http::locked_agent(grant.timeout_secs);
    let body_bytes: Option<Vec<u8>> = match (&req.method as &str, &req.body) {
        ("POST", Some(b)) => {
            if !grant.allow_body || b.len() > grant.max_body_bytes {
                credential_value.zeroize();
                return deny("request body not allowed");
            }
            Some(b.as_bytes().to_vec())
        }
        (_, Some(_)) => {
            credential_value.zeroize();
            return deny("request body not allowed");
        }
        _ => None,
    };
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
            match body_bytes {
                Some(ref bytes) => b.send(bytes),
                None => b.send_empty(),
            }
        }
        _ => {
            return deny("denied by policy");
        }
    };
    let response = match response {
        Ok(r) => r,
        Err(e) => {
            let outcome = http::redact_ureq_error(&e);
            let ctx = audit::CallContext {
                grant: &grant.id,
                credential: &req.credential,
                method: &req.method,
                host: &target.host_key,
                path: &req_path,
            };
            let _ = audit::append(&vault_dir_or_dot(), &ctx, &format!("error: {outcome}"), 0);
            println!("{}", respond::err_envelope(&outcome));
            return 2;
        }
    };
    if response.status() != 200 {
        let ctx = audit::CallContext {
            grant: &grant.id,
            credential: &req.credential,
            method: &req.method,
            host: &target.host_key,
            path: &req_path,
        };
        let _ = audit::append(
            &vault_dir_or_dot(),
            &ctx,
            "error: upstream non-OK status",
            0,
        );
        println!(
            "{}",
            respond::err_envelope(&format!(
                "upstream HTTP error status: {}",
                response.status().as_u16()
            ))
        );
        return 2;
    }

    // 6. Bounded read + allowlist filter. Audit failure denies (no silent
    //    unaudited success): the result prints only after the event lands.
    let body = response.into_body();
    let bytes = {
        use std::io::Read;
        let mut reader = body.into_reader().take(grant.max_response_bytes as u64 + 1);
        let mut out = Vec::new();
        match reader.read_to_end(&mut out) {
            Ok(_) => out,
            Err(_) => {
                println!(
                    "{}",
                    respond::err_envelope("failed reading upstream response")
                );
                return 2;
            }
        }
    };
    if bytes.len() > grant.max_response_bytes {
        let ctx = audit::CallContext {
            grant: &grant.id,
            credential: &req.credential,
            method: &req.method,
            host: &target.host_key,
            path: &req_path,
        };
        let _ = audit::append(
            &vault_dir_or_dot(),
            &ctx,
            "error: upstream response too large",
            0,
        );
        println!("{}", respond::err_envelope("upstream response too large"));
        return 2;
    }
    let filtered = match respond::filter_response(&bytes, &grant.allow_response_fields) {
        Ok(v) => v,
        Err(_) => {
            let ctx = audit::CallContext {
                grant: &grant.id,
                credential: &req.credential,
                method: &req.method,
                host: &target.host_key,
                path: &req_path,
            };
            let _ = audit::append(
                &vault_dir_or_dot(),
                &ctx,
                "error: upstream response rejected",
                bytes.len() as u64,
            );
            println!("{}", respond::err_envelope("upstream response rejected"));
            return 2;
        }
    };
    let ctx = audit::CallContext {
        grant: &grant.id,
        credential: &req.credential,
        method: &req.method,
        host: &target.host_key,
        path: &req_path,
    };
    if audit::append(&vault_dir_or_dot(), &ctx, "ok", bytes.len() as u64).is_err() {
        println!("{}", respond::err_envelope("audit failure"));
        return 2;
    }
    println!("{}", respond::ok_envelope(filtered));
    0
}

fn vault_dir_or_dot() -> std::path::PathBuf {
    platform::vault_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
}
