//! Security-focused integration tests.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const PW: &str = "s3cret-master-pw";
const SECRET: &str = "super-secret-value-please-dont-print";

fn cmd(dir: &TempDir) -> Command {
    let mut c = Command::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", PW);
    c
}

fn seed(dir: &TempDir) {
    cmd(dir).arg("init").assert().success();
    cmd(dir)
        .args(["add", "k"])
        .write_stdin(format!("{SECRET}\n{SECRET}\n"))
        .assert()
        .success();
}

#[test]
fn tampered_ciphertext_fails_safely() {
    let dir = TempDir::new().unwrap();
    seed(&dir);

    let path = dir.path().join("vault.json");
    let mut bytes = fs::read(&path).unwrap();
    let needle = b"\"ciphertext\": \"";
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
        + needle.len();
    bytes[pos] = if bytes[pos] == b'A' { b'B' } else { b'A' };
    fs::write(&path, &bytes).unwrap();

    let out = cmd(&dir).args(["get", "k"]).assert().failure();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(!stdout.contains(SECRET));
    assert!(!stderr.contains(SECRET));
}

#[test]
fn truncated_vault_fails_safely() {
    let dir = TempDir::new().unwrap();
    seed(&dir);

    let path = dir.path().join("vault.json");
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();

    cmd(&dir).arg("list").assert().failure();
}

#[test]
fn tampered_header_fails_safely() {
    let dir = TempDir::new().unwrap();
    seed(&dir);

    let path = dir.path().join("vault.json");
    let bytes = fs::read(&path).unwrap();
    // Mutate the magic to invalidate AAD + header validation.
    let needle = b"\"magic\": \"SAGITARRIUS\"";
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut tampered = bytes.clone();
    tampered[pos + 11] = b'X';
    fs::write(&path, &tampered).unwrap();

    cmd(&dir).args(["get", "k"]).assert().failure();
}

#[test]
fn secret_never_appears_in_list_output() {
    let dir = TempDir::new().unwrap();
    seed(&dir);

    let out = cmd(&dir).arg("list").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(!stdout.contains(SECRET));
    assert!(!stderr.contains(SECRET));
}

#[test]
fn secret_never_appears_in_search_output() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    // Search for a substring that is NOT in the name; must not match.
    cmd(&dir).args(["search", "super"]).assert().code(1);
}

#[test]
fn secret_never_appears_in_exists_output() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    let out = cmd(&dir).args(["exists", "k"]).assert().code(0);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.is_empty());
}

#[test]
fn vault_file_is_not_plaintext() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    let bytes = fs::read(dir.path().join("vault.json")).unwrap();
    // Neither the secret value nor the password should appear in the file.
    assert!(!contains(&bytes, SECRET.as_bytes()));
    assert!(!contains(&bytes, PW.as_bytes()));
}

#[test]
fn no_leftover_temp_files_after_mutation() {
    let dir = TempDir::new().unwrap();
    seed(&dir);
    cmd(&dir)
        .args(["edit", "k"])
        .write_stdin("new\nnew\n")
        .assert()
        .success();

    let entries: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(
        entries.iter().all(|n| !n.starts_with(".vault-")),
        "stray temp file found: {entries:?}"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
