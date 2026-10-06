use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use std::process::Command;
use zeroize::Zeroize;

pub fn run(selected: Vec<String>, allow_dangerous_env: bool, args: Vec<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    if args.is_empty() {
        return Err(SagitarriusError::Usage(
            "no command specified; usage: sagitarrius run --secret NAME -- <command> [args...]"
                .into(),
        ));
    }
    if selected.is_empty() {
        // Fail closed: the vault is never exposed wholesale to a child.
        // Name exactly what the child may see.
        return Err(SagitarriusError::Usage(
            "no secrets selected; pass at least one --secret NAME (e.g. sagitarrius run --secret OPENAI_API_KEY -- ./app)".into(),
        ));
    }
    // NUL can never survive into an environment block: reject up front,
    // flag or not. Errors name the secret, never the value.
    for name in &selected {
        if name.contains('\0') {
            return Err(SagitarriusError::Usage(format!(
                "invalid secret name {name:?}: must not contain NUL"
            )));
        }
        if !allow_dangerous_env && crate::vault::needs_dangerous_opt_in(name) {
            return Err(SagitarriusError::Usage(format!(
                "refusing dangerous secret name {name:?} for environment injection \
                 (loader/shell-startup name, whitespace or shell metacharacters); pass --allow-dangerous-env to inject it anyway"
            )));
        }
    }

    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    data.zeroize();
    crate::state::verify_generation(&vault)?;

    // Spawn the child directly. Never construct a shell string.
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);

    // The child must never inherit the master password (or the new-password
    // helper used by `passwd`). `Command` inherits the parent environment by
    // default, so strip these explicitly.
    cmd.env_remove("SAGITARRIUS_PASSWORD");
    cmd.env_remove("SAGITARRIUS_NEW_PASSWORD");

    // Inject only the explicitly selected secrets. Anything else in the
    // vault stays out of the child's environment (blast-radius control).
    // Deduplicate so `--secret A --secret A` injects once.
    let mut selected = selected;
    selected.sort();
    selected.dedup();
    for mut name in selected {
        let Some(mut value) = vault.get(&name) else {
            return Err(SagitarriusError::SecretNotFound(name));
        };
        // A NUL value (legacy vaults only — write paths reject them) can
        // never enter an environment block: fail naming the secret, never
        // the value, instead of the OS "nul byte found" error.
        if let Err(e) = crate::vault::check_value_for_env(&name, &value) {
            name.zeroize();
            value.zeroize();
            return Err(e);
        }
        if !is_valid_env_name(&name) {
            eprintln!("Warning: skipping secret {name:?} (not a valid environment variable name)");
            name.zeroize();
            value.zeroize();
            continue;
        }
        // `cmd.env` copies name/value into the child's env block; wipe both
        // of our copies afterwards.
        cmd.env(&name, &value);
        name.zeroize();
        value.zeroize();
    }

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(1))
}

/// POSIX env-var identifier rule: `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}
