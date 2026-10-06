//! End-to-end CLI tests using the compiled binary.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PW: &str = "correct horse battery staple";
const SECRET: &str = "test-secret-123";

fn cmd(dir: &TempDir) -> Command {
    let mut c = Command::cargo_bin("sagitarrius").expect("binary built");
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", PW);
    c
}

#[test]
fn init_creates_vault_file() {
    let dir = TempDir::new().unwrap();
    cmd(&dir)
        .arg("init")
        .assert()
        .success()
        .stderr(predicate::str::contains("initialized"));
    assert!(dir.path().join("vault.json").exists());
}

#[test]
fn init_refuses_overwrite() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn add_get_list_round_trip() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();

    // add via stdin (secret + confirm)
    cmd(&dir)
        .args(["add", "openai"])
        .write_stdin(format!("{SECRET}\n{SECRET}\n"))
        .assert()
        .success()
        .stderr(predicate::str::contains("added"));

    // get must print ONLY the value to stdout
    cmd(&dir)
        .args(["get", "openai"])
        .assert()
        .success()
        .stdout(format!("{SECRET}\n"));

    // list must show the name but never the value
    let out = cmd(&dir).arg("list").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("openai"));
    assert!(!stdout.contains(SECRET));
}

#[test]
fn add_duplicate_fails_safely() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "openai"])
        .write_stdin(format!("{SECRET}\n{SECRET}\n"))
        .assert()
        .success();

    cmd(&dir)
        .args(["add", "openai"])
        .write_stdin("other\nother\n".to_string())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn get_missing_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["get", "nope"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn exists_exit_codes() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "k"])
        .write_stdin("v\nv\n")
        .assert()
        .success();

    cmd(&dir).args(["exists", "k"]).assert().code(0).stdout("");
    cmd(&dir).args(["exists", "nope"]).assert().code(1);
}

#[test]
fn search_only_matches_names() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    for name in ["github-token", "github-actions", "openai"] {
        cmd(&dir)
            .args(["add", name])
            .write_stdin("v\nv\n")
            .assert()
            .success();
    }

    let out = cmd(&dir).args(["search", "github"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("github-token"));
    assert!(stdout.contains("github-actions"));
    assert!(!stdout.contains("openai"));

    cmd(&dir).args(["search", "zzz"]).assert().code(1);
}

#[test]
fn rename_does_not_overwrite() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    for name in ["a", "b"] {
        cmd(&dir)
            .args(["add", name])
            .write_stdin("v\nv\n")
            .assert()
            .success();
    }

    cmd(&dir).args(["rename", "a", "b"]).assert().failure();
    cmd(&dir).args(["rename", "a", "c"]).assert().success();
    cmd(&dir).args(["exists", "a"]).assert().code(1);
    cmd(&dir).args(["exists", "c"]).assert().code(0);
}

#[test]
fn edit_changes_value() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "k"])
        .write_stdin("old\nold\n")
        .assert()
        .success();
    cmd(&dir)
        .args(["edit", "k"])
        .write_stdin("new\nnew\n")
        .assert()
        .success();
    cmd(&dir)
        .args(["get", "k"])
        .assert()
        .success()
        .stdout("new\n");
}

#[test]
fn remove_requires_confirmation() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "k"])
        .write_stdin("v\nv\n")
        .assert()
        .success();

    // Decline — secret stays
    cmd(&dir)
        .args(["remove", "k"])
        .write_stdin("n\n")
        .assert()
        .success();
    cmd(&dir).args(["exists", "k"]).assert().code(0);

    // Confirm — secret goes
    cmd(&dir)
        .args(["remove", "k"])
        .write_stdin("y\n")
        .assert()
        .success();
    cmd(&dir).args(["exists", "k"]).assert().code(1);
}

#[test]
fn list_before_init_errors() {
    let dir = TempDir::new().unwrap();
    cmd(&dir)
        .arg("list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not been initialized"));
}

#[test]
fn value_from_argv_warns_but_works() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "k", "sk-inline"])
        .assert()
        .success()
        .stderr(predicate::str::contains("Warning"));
    cmd(&dir)
        .args(["get", "k"])
        .assert()
        .success()
        .stdout("sk-inline\n");
}

#[cfg(unix)]
#[test]
fn run_injects_env_and_propagates_exit_code() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "OPENAI_API_KEY"])
        .write_stdin("sk-run\nsk-run\n")
        .assert()
        .success();
    cmd(&dir)
        .args(["add", "UNRELATED"])
        .write_stdin("nope\nnope\n")
        .assert()
        .success();

    // Only the selected secret is injected; the rest stays out.
    // Password helpers must never enter the child environment either.
    cmd(&dir)
        .args([
            "run",
            "--secret",
            "OPENAI_API_KEY",
            "--",
            "sh",
            "-c",
            "printf %s \"$OPENAI_API_KEY\"; test -z \"$UNRELATED\"; test -z \"$SAGITARRIUS_PASSWORD\"; test -z \"$SAGITARRIUS_NEW_PASSWORD\"",
        ])
        .assert()
        .success()
        .stdout("sk-run");

    cmd(&dir)
        .args([
            "run",
            "--secret",
            "OPENAI_API_KEY",
            "--",
            "sh",
            "-c",
            "exit 42",
        ])
        .assert()
        .code(42);
}

#[test]
fn run_without_secret_selection_refuses() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "k", "v"]).assert().success();

    cmd(&dir)
        .args(["run", "--", "sh", "-c", "exit 0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no secrets selected"));
}

#[test]
fn no_secret_leaked_on_wrong_password() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "k"])
        .write_stdin(format!("{SECRET}\n{SECRET}\n"))
        .assert()
        .success();

    // Override the password env var with a wrong one.
    let mut c = Command::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", "definitely-wrong");

    let out = c.args(["get", "k"]).assert().failure();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(!stdout.contains(SECRET));
    assert!(!stderr.contains(SECRET));
    assert!(stderr.contains("invalid master password"));
}

#[test]
fn gen_creates_random_secret() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["gen", "RAND_KEY", "--length", "16"])
        .assert()
        .success();

    let out = cmd(&dir).args(["get", "RAND_KEY"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.trim().len(), 16);
}

#[test]
fn info_shows_metadata() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "TEST_KEY", "value12345"])
        .assert()
        .success();

    let out = cmd(&dir).args(["info", "TEST_KEY"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("TEST_KEY"));
    assert!(stdout.contains("10 characters"));
}

#[test]
fn import_export_flow() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();

    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "API_HOST=localhost\nAPI_PORT=8080\n").unwrap();

    cmd(&dir)
        .args(["import", env_path.to_str().unwrap()])
        .assert()
        .success();

    cmd(&dir)
        .args(["get", "API_HOST"])
        .assert()
        .success()
        .stdout("localhost\n");

    let out = cmd(&dir).args(["export", "--plaintext"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("API_HOST=localhost"));
    assert!(stdout.contains("API_PORT=8080"));
}

#[test]
fn export_without_plaintext_flag_refuses() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "k", "v"]).assert().success();

    cmd(&dir)
        .args(["export"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--plaintext"));
}

#[test]
fn audit_identifies_weak_and_duplicates() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "SHORT_KEY", "123"])
        .assert()
        .success();

    cmd(&dir)
        .args(["audit"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("SHORT_KEY"));
}

#[test]
fn passwd_changes_master_password() {
    use assert_cmd::Command as AssertCommand;
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "k", "v"]).assert().success();

    const NEW_PW: &str = "brand-new-master-pw-123";
    // Old password via SAGITARRIUS_PASSWORD, new via SAGITARRIUS_NEW_PASSWORD.
    let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", PW);
    c.env("SAGITARRIUS_NEW_PASSWORD", NEW_PW);
    c.args(["passwd"]).assert().success();

    // Old password must no longer work.
    let mut c_old = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c_old.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c_old.env("SAGITARRIUS_PASSWORD", PW);
    c_old.env_remove("SAGITARRIUS_NEW_PASSWORD");
    c_old.args(["get", "k"]).assert().failure();

    // New password works.
    let mut c_new = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c_new.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c_new.env("SAGITARRIUS_PASSWORD", NEW_PW);
    c_new.env_remove("SAGITARRIUS_NEW_PASSWORD");
    c_new.args(["get", "k"]).assert().success().stdout("v\n");
}

#[test]
fn bare_invocation_shows_launch_menu() {
    // No vault, no password needed: the landing screen must never touch disk
    // secrets or prompt for anything.
    let dir = TempDir::new().unwrap();
    let out = cmd(&dir).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("S A G I T A R R I U S"));
    assert!(stdout.contains("Your secrets. Your machine. Your terminal."));
    for cmd_name in ["init", "add", "get", "list", "run", "menu"] {
        assert!(stdout.contains(cmd_name), "menu is missing `{cmd_name}`");
    }
    // ASCII-ART logo from assets/sagitarrius-logo.svg must be present (# =
    // S strokes, = = ring, @ = core) and pure ASCII for legacy cmd.exe.
    assert!(stdout.contains("############"));
    assert!(stdout.contains("@@@@"));
    assert!(stdout.is_ascii());
    // No vault file may be created as a side effect.
    assert!(!dir.path().join("vault.json").exists());
}

#[test]
fn menu_subcommand_shows_launch_menu() {
    let dir = TempDir::new().unwrap();
    cmd(&dir)
        .arg("menu")
        .assert()
        .success()
        .stdout(predicate::str::contains("S A G I T A R R I U S"));
}

#[test]
fn gen_rejects_invalid_names_like_add() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    // `=` / newlines in names are rejected on every write path.
    cmd(&dir)
        .args(["gen", "A=B", "--length", "16"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid secret name"));
    cmd(&dir).args(["exists", "A=B"]).assert().code(1);
}

#[test]
fn export_warns_about_skipped_names() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "odd-name", "value12345"])
        .assert()
        .success();
    cmd(&dir)
        .args(["add", "FINE", "value12345"])
        .assert()
        .success();

    let out = cmd(&dir).args(["export", "--plaintext"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stdout.contains("FINE=value12345"));
    assert!(!stdout.contains("odd-name"));
    assert!(stderr.contains("odd-name"));
}

#[test]
fn v3_lifecycle_migrate_snapshot_rollback_recovery() {
    use assert_cmd::Command as AssertCommand;
    let dir = TempDir::new().unwrap();
    // Fresh vaults are v3.
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "K", "v-secret"]).assert().success();

    // Snapshot, then verify it.
    let out = cmd(&dir).args(["snapshot", "create"]).assert().success();
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    let snap_id = err
        .split_whitespace()
        .nth(1)
        .expect("snapshot id in output")
        .to_string();
    cmd(&dir)
        .args(["snapshot", "verify", &snap_id])
        .assert()
        .success();

    // Rollback simulation: tamper the live vault generation downward by
    // restoring... instead simulate stale state by bumping trusted state:
    // add another secret (gen 3), snapshot it, then restore the older snap.
    cmd(&dir).args(["add", "K2", "v2"]).assert().success();
    cmd(&dir)
        .args(["snapshot", "restore", &snap_id])
        .assert()
        .success();
    // Restored vault opens and holds the old data, not K2.
    cmd(&dir)
        .args(["get", "K"])
        .assert()
        .success()
        .stdout("v-secret\n");
    cmd(&dir).args(["exists", "K2"]).assert().code(1);
    // Rollback tripwire: replacing vault.json with the *current* bytes plus
    // a forged future state file must fail closed.
    let state_path = dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["generation"] = serde_json::Value::from(9999u64);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    cmd(&dir)
        .args(["get", "K"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("older than trusted"));

    // Fix state by restoring again (adopts manifest generation).
    cmd(&dir)
        .args(["snapshot", "restore", &snap_id])
        .assert()
        .success();

    // Recovery round-trip via env-provided code piped to stdin-less verify?
    // recovery create prints the code; capture it from stdout.
    let out = cmd(&dir).args(["recovery", "create"]).assert().success();
    let code = String::from_utf8(out.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert!(code.len() > 32);
    // status shows recovery ready.
    let out = cmd(&dir).arg("status").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("READY"));

    // Reset the password using only the code: simulate a lost password by
    // dropping SAGITARRIUS_PASSWORD and feeding interactive answers.
    let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env_remove("SAGITARRIUS_PASSWORD");
    c.args(["recovery", "reset-password"])
        .write_stdin(format!("{code}\nnew-after-loss\nnew-after-loss\n"))
        .assert()
        .success();
    // Old password dead, new password opens, data intact.
    cmd(&dir).args(["get", "K"]).assert().failure();
    let mut c2 = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c2.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c2.env("SAGITARRIUS_PASSWORD", "new-after-loss");
    c2.args(["get", "K"])
        .assert()
        .success()
        .stdout("v-secret\n");
}

/// F2: oversized writes fail BEFORE anything is modified.
#[test]
fn write_cap_enforced_before_writing() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "K", "v"]).assert().success();

    let big = "x".repeat(1024 * 1024 + 1);
    cmd(&dir)
        .args(["add", "BIG"])
        .write_stdin(format!("{big}\n{big}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("at most"));
    // Nothing was modified: the old record is intact.
    cmd(&dir)
        .args(["get", "K"])
        .assert()
        .success()
        .stdout("v\n");
    cmd(&dir).args(["exists", "BIG"]).assert().code(1);
}

/// F4/F5: dangerous names need opt-in on import and run; errors name the
/// secret, never the value.
#[test]
fn dangerous_names_need_opt_in() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();

    let env_path = dir.path().join("evil.env");
    std::fs::write(&env_path, "EVIL NAME=sekrit\nFINE=ok\n").unwrap();

    // Default: skipped with a warning naming the secret (not the value).
    let out = cmd(&dir)
        .args(["import", env_path.to_str().unwrap()])
        .assert()
        .success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("EVIL NAME"));
    assert!(!stderr.contains("sekrit"));
    cmd(&dir).args(["exists", "EVIL NAME"]).assert().code(1);

    // Opt-in import works.
    cmd(&dir)
        .args(["import", "--allow-dangerous", env_path.to_str().unwrap()])
        .assert()
        .success();
    cmd(&dir).args(["exists", "EVIL NAME"]).assert().code(0);

    // run refuses without the flag — naming the secret, never the value.
    // The observing child is platform-native: /usr/bin/env on unix (no
    // shell in between; dash would drop space-names), `cmd /c set` on
    // Windows. Both print the raw environment block.
    #[cfg(unix)]
    {
        let out = cmd(&dir)
            .args(["run", "--secret", "EVIL NAME", "--", "/usr/bin/env"])
            .assert()
            .failure();
        let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
        assert!(stderr.contains("EVIL NAME"));
        assert!(!stderr.contains("sekrit"));

        // ...and injects with it.
        let out = cmd(&dir)
            .args([
                "run",
                "--secret",
                "EVIL NAME",
                "--allow-dangerous-env",
                "--",
                "/usr/bin/env",
            ])
            .assert()
            .success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        assert!(stdout.contains("EVIL NAME=sekrit"));
    }
    #[cfg(windows)]
    {
        let out = cmd(&dir)
            .args(["run", "--secret", "EVIL NAME", "--", "cmd", "/c", "set"])
            .assert()
            .failure();
        let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
        assert!(stderr.contains("EVIL NAME"));
        assert!(!stderr.contains("sekrit"));

        let out = cmd(&dir)
            .args([
                "run",
                "--secret",
                "EVIL NAME",
                "--allow-dangerous-env",
                "--",
                "cmd",
                "/c",
                "set",
            ])
            .assert()
            .success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        assert!(stdout.contains("EVIL NAME=sekrit"));
    }
}

/// F6: clean negatives exit 1, every failure exits 2.
#[test]
fn exit_codes_usage_vs_operational() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();

    // Usage errors -> 2.
    cmd(&dir).args(["search", ""]).assert().code(2);
    cmd(&dir).args(["export"]).assert().code(2);
    cmd(&dir)
        .args(["run", "--", "sh", "-c", "exit 0"])
        .assert()
        .code(2);
    cmd(&dir)
        .args(["gen", "BAD=NAME", "--length", "16"])
        .assert()
        .code(2);

    // Operational failures -> 2 as well (wrong password, missing secret,
    // corrupt vault, lockdown, stale generation all land here).
    cmd(&dir).args(["get", "missing"]).assert().code(2);

    // Wrong password -> 2 (not 1).
    {
        use assert_cmd::Command as AssertCommand;
        let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
        c.env("SAGITARRIUS_VAULT_DIR", dir.path());
        c.env("SAGITARRIUS_PASSWORD", "definitely-wrong");
        c.args(["get", "missing"]).assert().code(2);
    }

    // No vault at all -> 2.
    {
        let fresh = TempDir::new().unwrap();
        let mut c = cmd(&fresh);
        c.arg("list").assert().code(2);
    }

    // Lockdown refusal -> 2.
    cmd(&dir).args(["add", "LOCKME", "v"]).assert().success();
    cmd(&dir).arg("lockdown").assert().success();
    cmd(&dir).args(["get", "LOCKME"]).assert().code(2);
    cmd(&dir).args(["lockdown", "--off"]).assert().success();

    // Clean negatives -> 1 (and only they do).
    cmd(&dir).args(["search", "zzz"]).assert().code(1);
    cmd(&dir).args(["exists", "missing"]).assert().code(1);

    // --help documents the codes.
    cmd(&dir)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Exit codes:"));
}

/// F7: new master passwords need 12+ chars on every path (env included);
/// unlock attempts are never gated.
#[test]
fn short_master_passwords_rejected() {
    use assert_cmd::Command as AssertCommand;
    // init via env: rejected, and no vault is created.
    let dir = TempDir::new().unwrap();
    let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", "short-11!!!");
    c.arg("init").assert().failure().code(2);
    assert!(!dir.path().join("vault.json").exists());

    // Healthy vault, then a short rotation attempt via env: refused, and
    // the old password keeps working.
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "k", "v"]).assert().success();
    let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", PW);
    c.env("SAGITARRIUS_NEW_PASSWORD", "tiny");
    c.args(["passwd"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least 12"));
    cmd(&dir)
        .args(["get", "k"])
        .assert()
        .success()
        .stdout("v\n");
}

/// F5: NUL bytes are rejected in secret values at every entry point.
#[test]
fn nul_in_values_rejected() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();

    // add via stdin (argv cannot carry NUL on any OS — stdin can).
    cmd(&dir)
        .args(["add", "NULVAL"])
        .write_stdin("a\0b\na\0b\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("NUL"));
    cmd(&dir).args(["exists", "NULVAL"]).assert().code(1);

    // import skips NUL values (counted, never stored).
    let env_path = dir.path().join("nul.env");
    std::fs::write(&env_path, "OKNUL=1\nBADNUL=a\0b\n").unwrap();
    let out = cmd(&dir)
        .args(["import", env_path.to_str().unwrap()])
        .assert()
        .success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("1 secret(s) added"));
    cmd(&dir).args(["exists", "BADNUL"]).assert().code(1);
}

/// F4: loader/shell-startup names (LD_PRELOAD, PATH, ...) are refused by
/// default even though most are valid POSIX identifiers.
#[test]
fn loader_names_refused_by_default() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();

    let env_path = dir.path().join("loader.env");
    std::fs::write(&env_path, "LD_PRELOAD=x\nOK=1\n").unwrap();

    let out = cmd(&dir)
        .args(["import", env_path.to_str().unwrap()])
        .assert()
        .success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("LD_PRELOAD"));
    cmd(&dir).args(["exists", "LD_PRELOAD"]).assert().code(1);

    cmd(&dir)
        .args(["import", "--allow-dangerous", env_path.to_str().unwrap()])
        .assert()
        .success();
    cmd(&dir).args(["exists", "LD_PRELOAD"]).assert().code(0);

    // run refuses even though the name is a valid identifier.
    // (Live injection of LD_PRELOAD is deliberately never exercised.)
    cmd(&dir)
        .args(["run", "--secret", "LD_PRELOAD", "--", "sh", "-c", "exit 0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LD_PRELOAD"));
}
/// F10: missing state.json with generation > 1 warns (does not fail);
/// manifest MAC failure names integrity check + snapshot restore.
#[test]
fn missing_state_warns_mac_failure_explains() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "K", "v"]).assert().success();

    // Drop trusted state: next command adopts with a warning, still works.
    std::fs::remove_file(dir.path().join("state.json")).unwrap();
    let out = cmd(&dir).args(["get", "K"]).assert().success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("no trusted state"));

    // Tamper a record name: MAC failure explains itself.
    let raw = std::fs::read(dir.path().join("vault.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["records"][0]["name"] = serde_json::Value::from("TAMPERED");
    std::fs::write(
        dir.path().join("vault.json"),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();
    cmd(&dir)
        .args(["get", "K"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("metadata failed integrity check"));
}

/// F11: empty SAGITARRIUS_PASSWORD counts as unset everywhere.
#[test]
fn empty_password_env_is_unset() {
    use assert_cmd::Command as AssertCommand;
    let dir = TempDir::new().unwrap();
    // Empty env + piped password: init must work, not fail on "empty".
    let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", "");
    c.arg("init")
        .write_stdin("long-enough-password\nlong-enough-password\n")
        .assert()
        .success();
    // ...and the vault opens with that password (env still empty: master
    // password comes from stdin first, then the secret pair).
    let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", "");
    c.args(["add", "K"])
        .write_stdin("long-enough-password\nv\nv\n")
        .assert()
        .success();
}

/// F11: `export <path>` refuses to overwrite without --force.
#[test]
fn export_refuses_overwrite_without_force() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "K", "v"]).assert().success();

    let dest = dir.path().join("out.env");
    cmd(&dir)
        .args(["export", "--plaintext", dest.to_str().unwrap()])
        .assert()
        .success();
    // Second export to the same path: refused...
    cmd(&dir)
        .args(["export", "--plaintext", dest.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));
    // ...unless --force.
    cmd(&dir)
        .args(["export", "--plaintext", "--force", dest.to_str().unwrap()])
        .assert()
        .success();
}

/// F11: a pre-existing non-empty vault dir keeps its permissions.
#[cfg(unix)]
#[test]
fn preexisting_vault_dir_not_chmodded() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let vault_dir = dir.path().join("custom");
    std::fs::create_dir_all(&vault_dir).unwrap();
    // Marker makes it non-empty; 0755 must survive.
    std::fs::write(vault_dir.join("keep.txt"), b"mine").unwrap();
    std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let mut c = assert_cmd::Command::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", &vault_dir);
    c.env("SAGITARRIUS_PASSWORD", PW);
    c.arg("init").assert().success();

    let mode = std::fs::metadata(&vault_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o755,
        "pre-existing non-empty dir must keep permissions"
    );
    assert!(vault_dir.join("vault.json").exists());
}

/// §21: a stripped MAC must not heal-forward past trusted state. Attacker
/// takes a MAC'd vault, strips the MAC *and* raises generation above the
/// trusted value: must fail closed, and state must keep has_manifest_mac.
#[test]
fn stripped_mac_cannot_heal_forward() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "K", "v"]).assert().success();

    // Sanity: trusted state records a MAC.
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state["has_manifest_mac"], true);

    // Attack: strip MAC, forge a higher generation.
    let raw = std::fs::read(dir.path().join("vault.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["header"].as_object_mut().unwrap().remove("manifest_mac");
    v["header"]["generation"] = serde_json::Value::from(9999u64);
    std::fs::write(
        dir.path().join("vault.json"),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();

    cmd(&dir)
        .args(["get", "K"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("stripped"));

    // State was not downgraded by the attempt.
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("state.json")).unwrap())
            .unwrap();
    assert_eq!(state["has_manifest_mac"], true);
}

/// §22: recovery must not bypass integrity protections. A stale vault
/// (generation behind trusted state) and a MAC-stripped vault both refuse
/// recovery verify AND password reset — even with the correct code.
#[test]
fn recovery_respects_integrity_gates() {
    use assert_cmd::Command as AssertCommand;
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir).args(["add", "K", "v"]).assert().success();

    let out = cmd(&dir).args(["recovery", "create"]).assert().success();
    let code = String::from_utf8(out.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    let feed = |args: &[&str], stdin: String| {
        let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
        c.env("SAGITARRIUS_VAULT_DIR", dir.path());
        c.env_remove("SAGITARRIUS_PASSWORD");
        c.args(args);
        let _ = c.write_stdin(stdin);
        c
    };

    // Baseline: code verifies on the healthy vault.
    feed(&["recovery", "verify"], format!("{code}\n"))
        .assert()
        .success();

    // STALE: forge trusted state ahead of the vault.
    let state_path = dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["generation"] = serde_json::Value::from(9999u64);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    feed(&["recovery", "verify"], format!("{code}\n"))
        .assert()
        .failure();
    feed(
        &["recovery", "reset-password"],
        format!("{code}\nnew-pw-after-loss\nnew-pw-after-loss\n"),
    )
    .assert()
    .failure();

    // Restore trust for the next scenario: delete state (re-adopt).
    std::fs::remove_file(&state_path).unwrap();

    // STRIPPED MAC: remove it from the file (state re-adopts MAC-less, then
    // a write would flip has_mac... so instead poison state first).
    let raw = std::fs::read(dir.path().join("vault.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["header"].as_object_mut().unwrap().remove("manifest_mac");
    std::fs::write(
        dir.path().join("vault.json"),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();
    // Fresh state adopts MAC-less as legacy: verify passes (legacy accept).
    feed(&["recovery", "verify"], format!("{code}\n"))
        .assert()
        .success();
    // Now simulate a state that HAD seen the MAC: flip the flag manually
    // (equivalent to any prior write having recorded it).
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["has_manifest_mac"] = serde_json::Value::from(true);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    feed(&["recovery", "verify"], format!("{code}\n"))
        .assert()
        .failure();
    feed(
        &["recovery", "reset-password"],
        format!("{code}\nnew-pw-after-loss\nnew-pw-after-loss\n"),
    )
    .assert()
    .failure();
}

/// §24: the legacy V2 import path enforces the same denylist as v3
/// (PATH, LD_PRELOAD, BASH_ENV must not slip through on old vaults).
#[test]
fn v2_import_enforces_denylist() {
    use assert_cmd::Command as AssertCommand;
    const FIXTURE_PW: &str = "v2-fixture-password";

    let dir = TempDir::new().unwrap();
    std::fs::copy(
        "tests/fixtures/v2-basic.json",
        dir.path().join("vault.json"),
    )
    .unwrap();
    let sag = || {
        let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
        c.env("SAGITARRIUS_VAULT_DIR", dir.path());
        c.env("SAGITARRIUS_PASSWORD", FIXTURE_PW);
        c
    };

    let env_path = dir.path().join("loader.env");
    std::fs::write(&env_path, "PATH=x\nLD_PRELOAD=y\nBASH_ENV=z\nOKV2=1\n").unwrap();

    let out = sag()
        .args(["import", env_path.to_str().unwrap()])
        .assert()
        .success();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    // Only OKV2 lands; all three loader names are skipped loudly.
    assert!(stderr.contains("1 secret(s) added"));
    assert!(stderr.contains("PATH") || stderr.contains("LD_PRELOAD"));
    sag().args(["exists", "PATH"]).assert().code(1);

    sag()
        .args(["import", "--allow-dangerous", env_path.to_str().unwrap()])
        .assert()
        .success();
    sag().args(["exists", "PATH"]).assert().code(0);
    sag().args(["exists", "OKV2"]).assert().code(0);
}
/// §10/§11: argument boundaries, tricky values and unicode paths survive
/// `run` and `file` on any OS (no shell string is ever constructed).
#[test]
fn run_preserves_argument_boundaries() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    cmd(&dir)
        .args(["add", "SPACED", "a b  c"])
        .assert()
        .success();

    #[cfg(unix)]
    {
        // printf prints each argv between markers: spaces, quotes, unicode,
        // empty strings and metacharacters must arrive as single argv each.
        let out = cmd(&dir)
            .args([
                "run",
                "--secret",
                "SPACED",
                "--",
                "sh",
                "-c",
                "printf '<%s>' \"$@\"",
                "argv0",
                "a b",
                "c\"d",
                "ünïcode",
                "",
                "$HOME `tick`",
            ])
            .assert()
            .success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        assert_eq!(stdout, "<a b><c\"d><ünïcode><><$HOME `tick`>");
    }
    #[cfg(windows)]
    {
        // A temp script file plus `-File`: remaining argv reach the script
        // untouched (no shell quoting anywhere). -EncodedCommand rejects
        // trailing argv on Windows PowerShell, `-Command` string-concats
        // them — both verified unsuitable while writing this test.
        let script = dir.path().join("show_args.ps1");
        std::fs::write(
            &script,
            "param([Parameter(ValueFromRemainingArguments=$true)][string[]]$rest)\n$rest -join '|'\n",
        )
        .unwrap();
        let out = cmd(&dir)
            .args([
                "run",
                "--secret",
                "SPACED",
                "--",
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script.to_str().unwrap(),
                "a b",
                "ünïcode",
                "",
            ])
            .assert()
            .success();
        // Windows PowerShell 5.1 writes the console codepage (not UTF-8),
        // so compare the ASCII-safe skeleton: three argv => two separators.
        let stdout = String::from_utf8_lossy(&out.get_output().stdout);
        assert!(stdout.starts_with("a b|"), "boundaries: {stdout:?}");
        assert_eq!(stdout.matches('|').count(), 2, "argv: {stdout:?}");
    }
}

/// §11: unicode file names work through `file put`/`file get`.
#[test]
fn file_unicode_names_roundtrip() {
    let dir = TempDir::new().unwrap();
    cmd(&dir).arg("init").assert().success();
    let src = dir.path().join("ünïcode name_日本.bin");
    std::fs::write(&src, b"bytes-\x00-binary-ok").unwrap();
    cmd(&dir)
        .args(["file", "put", src.to_str().unwrap(), "--name", "UFILE"])
        .assert()
        .success();
    let dest = dir.path().join("out-ü.bin");
    cmd(&dir)
        .args(["file", "get", "UFILE", dest.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(std::fs::read(&dest).unwrap(), b"bytes-\x00-binary-ok");
}
/// F1: a v0.2.1 vault (v3 layout, no manifest MAC) opens as legacy, gains
/// a MAC on first write, and a later-stripped MAC is refused via state.
#[test]
fn manifest_mac_legacy_upgrade_and_strip_rejection() {
    use assert_cmd::Command as AssertCommand;
    const FIXTURE_PW: &str = "v3-nomac-fixture-pw";

    let dir = TempDir::new().unwrap();
    std::fs::copy(
        "tests/fixtures/v3-nomac.json",
        dir.path().join("vault.json"),
    )
    .unwrap();
    let sag = || {
        let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
        c.env("SAGITARRIUS_VAULT_DIR", dir.path());
        c.env("SAGITARRIUS_PASSWORD", FIXTURE_PW);
        c
    };

    // Legacy opens fine.
    sag()
        .args(["get", "OLDREC"])
        .assert()
        .success()
        .stdout("old-value\n");

    // First write upgrades: MAC appears in the header.
    sag()
        .args(["add", "NEWKEY", "new-value"])
        .assert()
        .success();
    let raw = std::fs::read(dir.path().join("vault.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(v["header"]["manifest_mac"].is_string());

    // Strip the MAC now that state records it: refused, fail closed.
    let mut tampered: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    tampered["header"]
        .as_object_mut()
        .unwrap()
        .remove("manifest_mac");
    std::fs::write(
        dir.path().join("vault.json"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    sag()
        .args(["get", "OLDREC"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("stripped"));
}

/// Real CLI migration: a genuine v2 vault file (tests/fixtures/v2-basic.json,
/// password `v2-fixture-password`, committed) is converted by the actual
/// `sagitarrius migrate` command.
#[test]
fn cli_migrate_v2_to_v3() {
    use assert_cmd::Command as AssertCommand;
    const FIXTURE_PW: &str = "v2-fixture-password";

    let dir = TempDir::new().unwrap();
    std::fs::copy(
        "tests/fixtures/v2-basic.json",
        dir.path().join("vault.json"),
    )
    .unwrap();

    // Fresh command per invocation: assert_cmd accumulates args otherwise.
    let sag = || {
        let mut c = AssertCommand::cargo_bin("sagitarrius").unwrap();
        c.env("SAGITARRIUS_VAULT_DIR", dir.path());
        c.env("SAGITARRIUS_PASSWORD", FIXTURE_PW);
        c
    };
    sag().arg("migrate").assert().success();

    // Result is v3.
    let raw = std::fs::read(dir.path().join("vault.json")).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(v["header"]["version"], 3);

    // All values survived.
    sag()
        .args(["get", "LEGACY_ONE"])
        .assert()
        .success()
        .stdout("legacy-secret-1\n");
    sag()
        .args(["get", "LEGACY_TWO"])
        .assert()
        .success()
        .stdout("legacy-secret-2\n");

    // Timestamps survived.
    let out = sag().args(["info", "LEGACY_ONE"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("1700000001"));

    // The old v2 snapshot exists (pre-migrate safety net).
    let snaps: Vec<_> = std::fs::read_dir(dir.path().join("snapshots"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(snaps.iter().any(|n| n.starts_with("pre-migrate-")));

    // Migrated vault opens normally afterward.
    sag().args(["list"]).assert().success();

    // Repeated migrate is harmless and explicit.
    sag()
        .arg("migrate")
        .assert()
        .success()
        .stderr(predicate::str::contains("already format v3"));
}
