use crate::error::Result;
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
    let mut data = storage::read_vault()?;

    let mut password = input::master_password("Master password: ")?;
    let vault = match Vault::unlock(&password, &data) {
        Ok(v) => v,
        Err(e) => {
            password.zeroize();
            data.zeroize();
            return Err(e);
        }
    };
    password.zeroize();
    data.zeroize();

    let report = vault.audit();

    eprintln!("--- Sagitarrius Vault Audit ---");
    eprintln!("Total secrets evaluated: {}", report.total_secrets);
    eprintln!();

    let mut issues = 0;

    if !report.invalid_env_names.is_empty() {
        eprintln!(
            "⚠️  Invalid Environment Variable Names ({}):",
            report.invalid_env_names.len()
        );
        for name in &report.invalid_env_names {
            eprintln!("  - {name} (will be skipped during `sagitarrius run`)");
        }
        issues += report.invalid_env_names.len();
        eprintln!();
    }

    if !report.weak_secrets.is_empty() {
        eprintln!("⚠️  Short Secret Values ({}):", report.weak_secrets.len());
        for name in &report.weak_secrets {
            eprintln!("  - {name} (less than 8 characters; length is only a rough signal)");
        }
        issues += report.weak_secrets.len();
        eprintln!();
    }

    if !report.duplicate_values.is_empty() {
        eprintln!(
            "⚠️  Duplicate Secret Values Found ({} pair(s)):",
            report.duplicate_values.len()
        );
        for (a, b) in &report.duplicate_values {
            eprintln!("  - {a} and {b} share the exact same secret value");
        }
        issues += report.duplicate_values.len();
        eprintln!();
    }

    if issues == 0 {
        eprintln!("✅ No issues found by these checks (short values, duplicates, names only).");
        Ok(0)
    } else {
        eprintln!("Audit finished with {issues} potential issue(s).");
        Ok(1)
    }
}
