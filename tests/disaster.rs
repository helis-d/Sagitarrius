//! Disaster-recovery and ransomware-simulation tests: records AND files,
//! destruction of the live state, restore from external backups, and
//! refusal of incomplete/corrupt restores.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

const PW: &str = "disaster-test-password";

fn sag(dir: &TempDir, pw: &str) -> Command {
    let mut c = Command::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", pw);
    c
}

fn second_word(stderr: &str) -> String {
    stderr
        .split_whitespace()
        .nth(1)
        .expect("id in output")
        .to_string()
}

fn seed_vault_with_files(dir: &TempDir, payload: &[u8]) {
    sag(dir, PW).arg("init").assert().success();
    sag(dir, PW)
        .args(["add", "S1", "s3cret-1"])
        .assert()
        .success();
    sag(dir, PW)
        .args(["add", "P1", "--kind", "password", "p@ssw0rd!"])
        .assert()
        .success();
    sag(dir, PW)
        .args(["add", "C1", "--kind", "credential", "--username", "dbadmin"])
        .write_stdin("db-pass\ndb-pass\n")
        .assert()
        .success();
    sag(dir, PW)
        .args(["add", "N1", "--kind", "note", "remember the milk"])
        .assert()
        .success();
    sag(dir, PW)
        .args(["add", "D1", "--kind", "document", "line1\nline2"])
        .assert()
        .success();
    let src = dir.path().join("original.bin");
    std::fs::write(&src, payload).unwrap();
    sag(dir, PW)
        .args(["file", "put", src.to_str().unwrap(), "--name", "F1"])
        .assert()
        .success();
}

#[test]
fn full_disaster_recovery_with_files() {
    let dir = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    seed_vault_with_files(&dir, &payload);

    // Recovery kit BEFORE destruction.
    let out = sag(&dir, PW)
        .args(["recovery", "create"])
        .assert()
        .success();
    let code = String::from_utf8(out.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert!(code.len() > 32);

    sag(&dir, PW)
        .args(["snapshot", "create"])
        .assert()
        .success();

    let ext = TempDir::new().unwrap();
    let out = sag(&dir, PW)
        .args(["backup", "create", "--to", ext.path().to_str().unwrap()])
        .assert()
        .success();
    let backup_id = second_word(&String::from_utf8(out.get_output().stderr.clone()).unwrap());
    sag(&dir, PW)
        .args([
            "backup",
            "verify",
            &backup_id,
            "--from",
            ext.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // DESTROY the entire live state (vault, snapshots, files, trust).
    std::fs::remove_file(dir.path().join("vault.json")).unwrap();
    std::fs::remove_dir_all(dir.path().join("snapshots")).unwrap();
    std::fs::remove_dir_all(dir.path().join("files")).unwrap();
    std::fs::remove_file(dir.path().join("state.json")).unwrap();

    sag(&dir, PW).args(["get", "S1"]).assert().failure();

    // Restore from the EXTERNAL backup.
    sag(&dir, PW)
        .args([
            "backup",
            "restore",
            &backup_id,
            "--from",
            ext.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    // Every scalar record survived.
    sag(&dir, PW)
        .args(["get", "S1"])
        .assert()
        .success()
        .stdout("s3cret-1\n");
    sag(&dir, PW)
        .args(["get", "P1"])
        .assert()
        .success()
        .stdout("p@ssw0rd!\n");
    let out = sag(&dir, PW)
        .args(["get", "C1", "--json"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("dbadmin"));
    assert!(stdout.contains("db-pass")); // --json carries the whole credential
    sag(&dir, PW)
        .args(["get", "N1"])
        .assert()
        .success()
        .stdout("remember the milk\n");

    // File record exists and decrypts to identical bytes (compared by
    // length + hash: a raw assert_eq would dump 300 KiB on failure).
    let dest = dir.path().join("restored.bin");
    sag(&dir, PW)
        .args(["file", "get", "F1", dest.to_str().unwrap()])
        .assert()
        .success();
    let back = std::fs::read(&dest).unwrap();
    assert_eq!(back.len(), payload.len(), "restored file length");
    use sha2::Digest;
    let digest = |b: &[u8]| {
        let mut h = sha2::Sha256::new();
        h.update(b);
        format!("{:x}", h.finalize())
    };
    assert_eq!(digest(&back), digest(&payload), "restored file hash");

    // Generation state adopted the restore (no stale tripwire).
    let out = sag(&dir, PW).arg("status").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("CURRENT"));

    // Recovery still works against the restored vault.
    let mut c = Command::cargo_bin("sagitarrius").unwrap();
    c.env("SAGITARRIUS_VAULT_DIR", dir.path());
    c.env("SAGITARRIUS_PASSWORD", PW);
    c.args(["recovery", "verify"])
        .write_stdin(format!("{code}\n"))
        .assert()
        .success();

    // The external backup remains usable afterward.
    sag(&dir, PW)
        .args([
            "backup",
            "verify",
            &backup_id,
            "--from",
            ext.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn corrupt_backup_chunk_refuses_restore() {
    let dir = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    seed_vault_with_files(&dir, &payload);

    let ext = TempDir::new().unwrap();
    let out = sag(&dir, PW)
        .args(["backup", "create", "--to", ext.path().to_str().unwrap()])
        .assert()
        .success();
    let backup_id = second_word(&String::from_utf8(out.get_output().stderr.clone()).unwrap());

    // Corrupt one chunk byte inside the EXTERNAL backup.
    let backup_dir = std::fs::read_dir(ext.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir() && !p.file_name().unwrap().to_string_lossy().starts_with('.'))
        .unwrap();
    let files_dir = backup_dir.join("files");
    let container = std::fs::read_dir(&files_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .next()
        .unwrap();
    let chunk = container.join("chunk-00000000");
    let mut ct = std::fs::read(&chunk).unwrap();
    ct[0] ^= 1;
    std::fs::write(&chunk, ct).unwrap();

    // Verify flags it...
    sag(&dir, PW)
        .args([
            "backup",
            "verify",
            &backup_id,
            "--from",
            ext.path().to_str().unwrap(),
        ])
        .assert()
        .failure();

    // ...and restore is refused WITHOUT touching the live vault.
    let before = std::fs::read(dir.path().join("vault.json")).unwrap();
    sag(&dir, PW)
        .args([
            "backup",
            "restore",
            &backup_id,
            "--from",
            ext.path().to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("FAILED")
                .or(predicate::str::contains("mismatch"))
                .or(predicate::str::contains("Mismatch")),
        );
    let after = std::fs::read(dir.path().join("vault.json")).unwrap();
    assert_eq!(before, after);
    sag(&dir, PW)
        .args(["get", "S1"])
        .assert()
        .success()
        .stdout("s3cret-1\n");
}

#[test]
fn ransomware_simulation_detects_and_recovers() {
    let dir = TempDir::new().unwrap();
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    seed_vault_with_files(&dir, &payload);

    // Snapshot A, then one more write (generation advances).
    let out = sag(&dir, PW)
        .args(["snapshot", "create"])
        .assert()
        .success();
    let snap_a = second_word(&String::from_utf8(out.get_output().stderr.clone()).unwrap());
    sag(&dir, PW).args(["add", "B", "newer"]).assert().success();

    // External backup of the newest state.
    let ext = TempDir::new().unwrap();
    let out = sag(&dir, PW)
        .args(["backup", "create", "--to", ext.path().to_str().unwrap()])
        .assert()
        .success();
    let backup_id = second_word(&String::from_utf8(out.get_output().stderr.clone()).unwrap());

    // ATTACK 1 — replay: authentic older vault bytes, trusted state intact.
    let snap_vault = dir
        .path()
        .join("snapshots")
        .join(&snap_a)
        .join("vault.json");
    let old_bytes = std::fs::read(&snap_vault).unwrap();
    std::fs::write(dir.path().join("vault.json"), &old_bytes).unwrap();
    sag(&dir, PW)
        .args(["get", "S1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("older than trusted"));

    // ATTACK 2 — ransomware: garbage vault, no state, no snapshots, no files.
    std::fs::write(dir.path().join("vault.json"), b"ENCRYPTED-BY-MALWARE").unwrap();
    std::fs::remove_file(dir.path().join("state.json")).unwrap();
    std::fs::remove_dir_all(dir.path().join("snapshots")).unwrap();
    std::fs::remove_dir_all(dir.path().join("files")).unwrap();
    sag(&dir, PW).args(["get", "S1"]).assert().failure();
    sag(&dir, PW).args(["list"]).assert().failure();

    // RECOVERY from the offline backup (includes the newest record B).
    sag(&dir, PW)
        .args([
            "backup",
            "restore",
            &backup_id,
            "--from",
            ext.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    sag(&dir, PW)
        .args(["get", "B"])
        .assert()
        .success()
        .stdout("newer\n");
    let dest = dir.path().join("back.bin");
    sag(&dir, PW)
        .args(["file", "get", "F1", dest.to_str().unwrap()])
        .assert()
        .success();
    let back = std::fs::read(&dest).unwrap();
    assert_eq!(back.len(), payload.len(), "restored file length");
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(&back);
    let mut h2 = sha2::Sha256::new();
    h2.update(&payload);
    assert_eq!(
        format!("{:x}", h.finalize()),
        format!("{:x}", h2.finalize()),
        "restored file hash"
    );
}
