mod archive;
mod banner;
mod cli;
mod commands;
mod crypto;
mod envelope;
mod error;
mod files;
mod input;
mod platform;
mod state;
mod storage;
mod vault;
mod vault_v3;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
    crate::input::configure(cli.password_stdin);
    let command = match cli.command {
        // Bare `sagitarrius` in CMD: show the logo + menu, touch nothing.
        None => {
            banner::print_landing();
            std::process::exit(0);
        }
        Some(cmd) => cmd,
    };
    match commands::dispatch(command) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            // Every failure exits 2 — wrong password, corruption, lockdown,
            // usage errors alike. Clean negatives never reach here: `exists`
            // (absent), `search` (no match) and `audit` (findings) return
            // Ok(1). `run` child codes pass through untouched.
            eprintln!("Error: {e}");
            std::process::exit(2);
        }
    }
}
