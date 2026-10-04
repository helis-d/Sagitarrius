use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "sagitarrius",
    version,
    about = "Sagitarrius — local-first secret manager",
    long_about = "Your secrets. Your machine. Your terminal.\n\
                  A tiny, local-first CLI secret manager for developers.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Subcommand. When omitted, the Sagitarrius launch menu is shown.
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show the Sagitarrius launch menu (same as running with no arguments)
    Menu,

    /// Create a new encrypted vault
    Init,

    /// Change vault master password
    Passwd,

    /// Add a new secret (interactive entry is preferred)
    Add {
        /// Secret name
        name: String,
        /// Secret value. Warning: may be recorded in shell history.
        value: Option<String>,
    },

    /// Generate a cryptographically secure random secret
    Gen {
        /// Secret name to store in the vault
        name: String,
        /// Length of generated secret (default: 32)
        #[arg(short, long, default_value_t = 32)]
        length: usize,
        /// Exclude special symbols (letters and numbers only)
        #[arg(long, default_value_t = false)]
        no_symbols: bool,
    },

    /// Print a secret value to stdout (only the value is printed)
    Get {
        /// Secret name
        name: String,
    },

    /// Show metadata for a secret (creation time, modified time, length)
    Info {
        /// Secret name
        name: String,
    },

    /// List stored secret names (values are never shown)
    List,

    /// Remove a secret
    Remove {
        /// Secret name
        name: String,
        /// Skip the confirmation prompt (for scripts)
        #[arg(short, long, default_value_t = false)]
        yes: bool,
    },

    /// Replace the value of an existing secret
    Edit {
        /// Secret name
        name: String,
    },

    /// Rename a secret without changing its value
    Rename {
        /// Current name
        old: String,
        /// New name
        new: String,
    },

    /// Exit 0 if the secret exists, exit 1 otherwise. Silent.
    Exists {
        /// Secret name
        name: String,
    },

    /// Search secret names for a substring (values are never searched)
    Search {
        /// Substring to match against secret names
        query: String,
    },

    /// Import secrets from a file (e.g. .env format)
    Import {
        /// Path to the .env file
        path: String,
        /// Overwrite existing secret values if present
        #[arg(short, long, default_value_t = false)]
        overwrite: bool,
    },

    /// Export stored secrets in .env format
    Export {
        /// Optional destination file path (prints to stdout if omitted)
        path: Option<String>,
    },

    /// Perform a security audit on stored secrets
    Audit,

    /// Run a command with all secrets injected into its environment
    Run {
        /// Command and arguments (typically after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
}
