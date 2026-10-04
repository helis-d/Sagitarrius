//! Terminal input helpers.
//!
//! Interactive when stdin is a TTY (via `rpassword`, no echo). Falls back to
//! reading a plain line from stdin when piped — this keeps the CLI scriptable
//! and testable.
//!
//! `SAGITARRIUS_PASSWORD` can supply the master password non-interactively.
//! This is intended for scripting and automated tests. It is NOT safer than
//! typing the password: environment variables are visible to other processes
//! and to children. Do not use it with a real master password.

//! Terminal input helpers.
//!
//! Interactive when stdin is a TTY (via `rpassword`, no echo). Falls back to
//! reading a plain line from stdin when piped — this keeps the CLI scriptable
//! and testable.
//!
//! `SAGITARRIUS_PASSWORD` can supply the master password non-interactively.
//! This exists for automated tests and throwaway scripting only. It is NOT
//! safer than typing the password: environment variables are visible to
//! other processes and to children. For scripted production use, prefer
//! `--password-stdin`, which reads the password from stdin without involving
//! the process environment. Do not use the env var with a real master
//! password.

use crate::error::{Result, SagitarriusError};
use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once at startup from the `--password-stdin` CLI flag.
static PASSWORD_FROM_STDIN: AtomicBool = AtomicBool::new(false);

pub fn configure(password_stdin: bool) {
    PASSWORD_FROM_STDIN.store(password_stdin, Ordering::SeqCst);
}

pub fn master_password(prompt: &str) -> Result<String> {
    // Explicit flag wins over the environment: the operator asked for the
    // safer path, so honor it even if the env var happens to be set.
    if PASSWORD_FROM_STDIN.load(Ordering::SeqCst) {
        return read_stdin_line();
    }
    if let Ok(pw) = std::env::var("SAGITARRIUS_PASSWORD") {
        return Ok(pw);
    }
    read_secret(prompt)
}

/// Read one line from stdin with no prompt and no echo handling: the
/// `--password-stdin` path for scripted use.
fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Read a line without echoing when interactive; read a plain line otherwise.
pub fn read_secret(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        return Ok(line);
    }
    rpassword::prompt_password(prompt).map_err(SagitarriusError::from)
}

/// Yes/no confirmation. Defaults to "no" — anything other than `y` / `yes`
/// (case-insensitively) is treated as a decline.
pub fn confirm(prompt: &str) -> Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(ans == "y" || ans == "yes")
}

/// Plain line input with echo (for non-secret values like usernames).
pub fn read_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}
