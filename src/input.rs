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

use crate::error::{Result, SagitarriusError};
use std::io::{self, BufRead, IsTerminal, Write};

pub fn master_password(prompt: &str) -> Result<String> {
    if let Ok(pw) = std::env::var("SAGITARRIUS_PASSWORD") {
        return Ok(pw);
    }
    read_secret(prompt)
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
