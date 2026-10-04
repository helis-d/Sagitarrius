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
        .code(1)
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
        .args(["run", "--", "sh", "-c", "printf %s \"$OPENAI_API_KEY\""])
        .assert()
        .success()
        .stdout("sk-run");

    cmd(&dir)
        .args(["run", "--", "sh", "-c", "exit 42"])
        .assert()
        .code(42);
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

    let out = cmd(&dir).args(["export"]).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("API_HOST=localhost"));
    assert!(stdout.contains("API_PORT=8080"));
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
