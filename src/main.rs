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
            eprintln!("Error: {e}");
            std::process::exit(e.exit_code());
        }
    }
}
