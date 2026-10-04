//! Launch banner: the Sagitarrius logo as CMD-safe ASCII-ART plus a menu.
//!
//! The art is a rasterization of the real logo
//! (`assets/sagitarrius-logo.svg`): the white "S" strokes are `#`, the
//! tilted satellite ring is `=`, and the core dot is `@` — same paint order
//! as the SVG (ring over S, core on top).
//!
//! Pure ASCII on purpose — no ANSI colors, no Unicode box drawing — so the
//! menu renders correctly in legacy `cmd.exe` as well as Windows Terminal.
//! Printing the landing screen never touches the vault and never asks for
//! the master password.

/// The logo, rasterized from `assets/sagitarrius-logo.svg`.
pub const LOGO_ART: &str = r#"
                ############
             #######################
                             ########
                                #####
                          =============
                    =====###########  ==
                ====#######   #####  ==
             ===##### @@@@#######  ===
           ==########@@@@@@##    ===
         ==##########         ===
        ==   ####        ====
         === ###  =======         ###
             ===#               #####
              #####         #######
                ################
"#;

/// Short tagline shown under the logo.
pub const TAGLINE: &str = "Your secrets. Your machine. Your terminal.";

/// The full launch menu. Kept as a hand-aligned literal so it always lines
/// up in CMD. If a subcommand is added/renamed in `cli.rs`, update this too.
pub const MENU: &str = r#"
  MENU
    menu                  Show this launch menu again

  VAULT
    init                  Create a new encrypted vault
    passwd                Change the master password (needs SAGITARRIUS_NEW_PASSWORD)

  SECRETS
    add <name> [value]    Add a secret (interactive entry is preferred)
    gen <name>            Generate a random secret and store it
    get <name>            Print a secret value to stdout
    info <name>           Show metadata (length, timestamps)
    list                  List secret names (values are never shown)
    search <query>        Search secret names for a substring
    exists <name>         Exit 0 if present, 1 otherwise (silent)
    edit <name>           Replace a secret's value
    rename <old> <new>    Rename without overwriting
    remove <name> [-y]    Delete after confirmation (use -y in scripts)

  BULK
    import <file>         Import secrets from a .env file
    export [file]         Export secrets in .env format
    audit                 Health check: short values, duplicates, bad names

  RUN
    run --secret N -- <cmd>  Run a command with only the named secrets

  RESILIENCE
    snapshot <cmd>        Encrypted local snapshots (create/list/verify/restore/delete)
    backup <cmd>          Encrypted backups, retention, external targets
    recovery <cmd>        Recovery code: create/verify/reset-password
    file <cmd>            Encrypted files (put/get, chunked + authenticated)
    migrate               Upgrade a v2 vault to v3 (VMK envelope)
    status                Security status: integrity, recovery, backups
    lockdown [--off]      Refuse all decryption until released
"#;

/// Print the launch screen: logo, title, tagline, menu, footer.
pub fn print_landing() {
    println!("{LOGO_ART}");
    println!("   S A G I T A R R I U S");
    println!("   {TAGLINE}");
    println!("{MENU}");
    match crate::platform::vault_dir() {
        Ok(dir) => println!("   Vault: {}", dir.join("vault.json").display()),
        Err(_) => println!("   Vault location: (could not be determined)"),
    }
    println!("   Help:  sagitarrius <command> --help");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logo_is_pure_ascii() {
        assert!(!LOGO_ART.is_empty());
        assert!(LOGO_ART.is_ascii(), "banner must stay CMD-safe pure ASCII");
    }

    #[test]
    fn menu_lists_every_subcommand() {
        // Guard against the menu drifting out of sync with cli.rs.
        for cmd in [
            "init", "passwd", "add", "gen", "get", "info", "list", "search", "exists", "edit",
            "rename", "remove", "import", "export", "audit", "run", "menu", "migrate", "snapshot",
            "backup", "recovery", "file", "status", "lockdown",
        ] {
            assert!(MENU.contains(cmd), "menu is missing `{cmd}`");
        }
    }
}
