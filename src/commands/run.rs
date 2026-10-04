use crate::error::{Result, SagitarriusError};
use crate::input;
use crate::storage;
use crate::vault::Vault;
use std::process::Command;
use zeroize::Zeroize;

pub fn run(args: Vec<String>) -> Result<i32> {
    if args.is_empty() {
        return Err(SagitarriusError::Other(
            "no command specified; usage: sagitarrius run -- <command> [args...]".into(),
        ));
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

    // Spawn the child directly. Never construct a shell string.
    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);

    // The child must never inherit the master password (or the new-password
    // helper used by `passwd`). `Command` inherits the parent environment by
    // default, so strip these explicitly.
    cmd.env_remove("SAGITARRIUS_PASSWORD");
    cmd.env_remove("SAGITARRIUS_NEW_PASSWORD");

    for (mut k, mut v) in vault.secrets() {
        if is_valid_env_name(&k) {
            cmd.env(&k, &v);
        } else {
            eprintln!("Warning: skipping secret {k:?} (not a valid environment variable name)");
        }
        k.zeroize();
        v.zeroize();
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
