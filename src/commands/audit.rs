use crate::error::Result;
use crate::input;
use crate::storage;
use crate::vault::Vault;
use zeroize::Zeroize;

pub fn run() -> Result<i32> {
    crate::storage::ensure_unlocked()?;
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
    crate::state::verify_generation(&vault)?;

    let mut report = vault.audit();

    // Vault-level posture checks: all real local conditions, no scoring.
    if vault.format_version() < 3 {
        report.notices.push(
            "vault format is v2 (whole-payload encryption, no recovery, no rollback tracking); run `sagitarrius migrate`".into(),
        );
    }
    let def = crate::crypto::KdfParams::default();
    match vault.password_kdf_params() {
        Some(p) if p.m_cost < def.m_cost || p.t_cost < def.t_cost || p.p_cost < def.p_cost => {
            report.notices.push(format!(
                "password KDF is weaker than current defaults (m={} t={} p={} vs m={} t={} p={}); re-wrapping with `passwd` adopts current parameters",
                p.m_cost, p.t_cost, p.p_cost, def.m_cost, def.t_cost, def.p_cost
            ));
        }
        None => report
            .notices
            .push("no password wrap found (unexpected)".into()),
        _ => {}
    }
    if vault.is_v3() && !vault.has_recovery() {
        report.notices.push(
            "no recovery wrap: a lost master password means total loss; run `recovery create`"
                .into(),
        );
    }
    match crate::commands::snapshot::list_entries(&storage::snapshots_dir()?) {
        Ok(list) if list.is_empty() => report
            .notices
            .push("no snapshots: `snapshot create` before big changes".into()),
        Err(_) => report.notices.push("snapshot directory unreadable".into()),
        _ => {}
    }
    match crate::commands::snapshot::list_entries(&storage::backups_dir()?) {
        Ok(list) if list.is_empty() => report.notices.push(
            "no local backups: `backup create --to <offline-dir>` for ransomware resilience".into(),
        ),
        Err(_) => report.notices.push("backup directory unreadable".into()),
        _ => {}
    }
    if storage::is_locked_down()? {
        report
            .notices
            .push("lockdown is ENABLED: decryption refused until `lockdown --off`".into());
    }

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
            eprintln!(
                "  - {} (will be skipped during `sagitarrius run`)",
                crate::vault::escape_name(name)
            );
        }
        issues += report.invalid_env_names.len();
        eprintln!();
    }

    if !report.weak_secrets.is_empty() {
        eprintln!("⚠️  Short Secret Values ({}):", report.weak_secrets.len());
        for name in &report.weak_secrets {
            eprintln!(
                "  - {} (less than 8 characters; length is only a rough signal)",
                crate::vault::escape_name(name)
            );
        }
        issues += report.weak_secrets.len();
        eprintln!();
    }

    if !report.duplicate_groups.is_empty() {
        let affected: usize = report.duplicate_groups.iter().map(Vec::len).sum();
        eprintln!(
            "⚠️  Duplicate Secret Values Found ({} group(s), {affected} secret(s)):",
            report.duplicate_groups.len()
        );
        for group in &report.duplicate_groups {
            let shown: Vec<String> = group.iter().map(|n| crate::vault::escape_name(n)).collect();
            eprintln!("  - {} share the exact same secret value", shown.join(", "));
        }
        issues += report.duplicate_groups.len();
        eprintln!();
    }

    if !report.notices.is_empty() {
        eprintln!("ℹ️  Notices ({} — not failures):", report.notices.len());
        for n in &report.notices {
            eprintln!("  - {n}");
        }
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
