use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "sagitarrius",
    version,
    about = "Sagitarrius — local-first secret manager",
    long_about = "Your secrets. Your machine. Your terminal.\n\
                  A tiny, local-first CLI secret manager for developers.",
    after_help = "Exit codes:\n  \
                  0  success (note: `exists` uses 1 for 'absent', and `run`\n  \
                  propagates its child process exit code)\n  \
                  1  operational failure (wrong password, missing secret,\n  \
                  tampered vault, lockdown, stale generation, ...)\n  \
                  2  usage error (bad flags/values, missing --secret or\n  \
                  --plaintext, invalid names)",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Read the master password from stdin (one line, no prompt) instead of
    /// the terminal or `SAGITARRIUS_PASSWORD`. Prefer this over the env var
    /// for scripted use: stdin is not visible in `ps` or `/proc`.
    #[arg(long, global = true, default_value_t = false)]
    pub password_stdin: bool,

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
        /// Record kind: secret, password, note, credential, document
        #[arg(long, default_value = "secret")]
        kind: String,
        /// Username for `--kind credential` (prompted when omitted)
        #[arg(long)]
        username: Option<String>,
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
        /// Print the full record as JSON (needed for credential records)
        #[arg(long, default_value_t = false)]
        json: bool,
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
        /// Import names with shell-dangerous characters too (skipped otherwise)
        #[arg(long, default_value_t = false)]
        allow_dangerous: bool,
    },

    /// Export stored secrets in .env format (PLAINTEXT — see warning)
    Export {
        /// Acknowledge plaintext export. Required: without it the command
        /// refuses, so scripts cannot decrypt the vault to disk by accident.
        #[arg(long, default_value_t = false)]
        plaintext: bool,
        /// Optional destination file path (prints to stdout if omitted)
        path: Option<String>,
    },

    /// Perform a security audit on stored secrets
    Audit,

    /// Migrate a v2 vault to the v3 envelope format (VMK + per-record keys)
    Migrate,

    /// Encrypted snapshots: local versioned history of the vault
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },

    /// Encrypted backups with retention, verifiable and restorable
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },

    /// Recovery kit: survive a lost master password via a recovery code
    Recovery {
        #[command(subcommand)]
        action: RecoveryAction,
    },

    /// Store and retrieve encrypted files (chunked authenticated encryption)
    File {
        #[command(subcommand)]
        action: FileAction,
    },

    /// Concise security status: integrity, generation, recovery, backups
    Status,

    /// Lockdown: refuse all decryption until explicitly released
    Lockdown {
        /// Release lockdown instead of enabling it
        #[arg(long, default_value_t = false)]
        off: bool,
    },

    /// Run a command with selected secrets injected into its environment.
    /// Only the named secrets are exposed — never the whole vault.
    Run {
        /// Secret name to inject. Repeatable. At least one is required.
        #[arg(long = "secret")]
        secret: Vec<String>,
        /// Inject names with shell-dangerous characters too (refused otherwise)
        #[arg(long, default_value_t = false)]
        allow_dangerous_env: bool,
        /// Command and arguments (typically after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SnapshotAction {
    /// Record the current vault as an encrypted snapshot
    Create,
    /// List snapshots (id, generation, timestamp, validity)
    List,
    /// Fully verify a snapshot (prompt for password) or all of them
    Verify {
        /// Snapshot id (verifies all when omitted)
        id: Option<String>,
    },
    /// Replace the vault with a snapshot (updates trusted state)
    Restore {
        /// Snapshot id
        id: String,
    },
    /// Delete a snapshot
    Delete {
        /// Snapshot id
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum BackupAction {
    /// Write an encrypted backup (+ integrity manifest)
    Create {
        /// External directory (offline disk). Defaults to the local backup dir.
        #[arg(long)]
        to: Option<String>,
    },
    /// List backups
    List,
    /// Fully verify a backup (prompt for password) or all of them
    Verify {
        /// Backup id (verifies all when omitted)
        id: Option<String>,
        /// Verify in an external directory instead of the local backup dir
        #[arg(long)]
        from: Option<String>,
    },
    /// Restore the vault from a backup (updates trusted state)
    Restore {
        /// Backup id
        id: String,
        /// Restore from an external directory instead of the local backup dir
        #[arg(long)]
        from: Option<String>,
    },
    /// Delete backups, keeping the newest N (`--keep 0` deletes all)
    Prune {
        /// Number of newest backups to keep
        #[arg(long, default_value_t = 5)]
        keep: usize,
    },
}

#[derive(Subcommand, Debug)]
pub enum RecoveryAction {
    /// Generate a recovery code and store its wrap (code shown ONCE)
    Create,
    /// Check a recovery code without changing anything
    Verify,
    /// Set a new master password using a recovery code (password lost?)
    ResetPassword,
}

#[derive(Subcommand, Debug)]
pub enum FileAction {
    /// Encrypt a file into the vault (chunked, authenticated)
    Put {
        /// Local file to store
        path: String,
        /// Record name (defaults to the file name)
        #[arg(long)]
        name: Option<String>,
    },
    /// Decrypt a stored file to a destination path
    Get {
        /// Record name
        name: String,
        /// Destination path
        dest: String,
    },
}
