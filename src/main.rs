use clap::Parser;
use sagitarrius::{banner, cli, commands, input};

fn main() {
    let cli = cli::Cli::parse();
    input::configure(cli.password_stdin);
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
