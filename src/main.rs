mod banner;
mod cli;
mod commands;
mod crypto;
mod error;
mod input;
mod platform;
mod storage;
mod vault;

use clap::Parser;
use cli::Cli;

fn main() {
    let cli = Cli::parse();
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
            std::process::exit(1);
        }
    }
}
