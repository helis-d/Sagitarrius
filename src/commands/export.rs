use crate::error::Result;
use crate::input;
use crate::storage;
use crate::vault::Vault;
use std::fs::OpenOptions;
use std::io::Write;
use zeroize::Zeroize;

pub fn run(plaintext: bool, path: Option<String>) -> Result<i32> {
    crate::storage::ensure_unlocked()?;
    if !plaintext {
        // Fail closed: decrypting the vault to disk must be a deliberate,
        // visible act, never a default. Prefer `run --secret ...` so secrets
        // stay out of files entirely.
        return Err(crate::error::SagitarriusError::Other(
            "plaintext export requires --plaintext (e.g. sagitarrius export --plaintext out.env); \
             prefer `run --secret NAME -- <cmd>` to avoid writing secrets to disk"
                .into(),
        ));
    }
    eprintln!(
        "Warning: exporting DECRYPTED secrets. The output is NOT protected by \
         the master password — handle and delete it carefully."
    );
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

    let (mut env_output, skipped) = vault.export_env();

    match path {
        Some(file_path) => {
            // Plaintext secrets: never use `fs::write` (0644). Create with
            // 0600 on unix, truncate if it already exists, and tighten
            // existing files that may have looser permissions.
            write_plaintext_file(&file_path, env_output.as_bytes())?;
            env_output.zeroize();
            if !skipped.is_empty() {
                eprintln!(
                    "Warning: skipped {} secret(s) with invalid env names: {}",
                    skipped.len(),
                    skipped.join(", ")
                );
            }
            eprintln!("Secrets exported to {file_path:?} in .env format.");
        }
        None => {
            print!("{env_output}");
            env_output.zeroize();
            if !skipped.is_empty() {
                eprintln!(
                    "Warning: skipped {} secret(s) with invalid env names: {}",
                    skipped.len(),
                    skipped.join(", ")
                );
            }
        }
    }

    Ok(0)
}

fn write_plaintext_file(path: &str, contents: &[u8]) -> Result<()> {
    use std::path::Path;
    let dest = Path::new(path);

    // Refuse to follow a symlink at the destination: writing through it
    // would truncate/overwrite an arbitrary file with plaintext secrets.
    // `symlink_metadata` does not follow the final component.
    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            return Err(crate::error::SagitarriusError::Other(format!(
                "refusing to export through symlink: {path:?}"
            )));
        }
    }

    // Write to a temp file in the same directory + rename, so we never
    // truncate through a symlink and the export is atomic. Preserves the
    // existing overwrite-when-not-symlink behaviour (no new --force flag).
    let parent = dest.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)?;
    }
    let dir: &Path = match parent {
        Some(d) => d,
        None => Path::new("."),
    };
    let unique = format!(
        ".export-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = dir.join(unique);

    {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        let write_res = f.write_all(contents).and_then(|_| f.sync_all());
        if write_res.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            write_res?;
        }
    }

    if let Err(e) = std::fs::rename(&tmp_path, dest) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten pre-existing files (e.g. created earlier with 0644).
        // rename() replaces a symlink itself rather than its target, so this
        // metadata call is on the real file.
        if let Ok(meta) = std::fs::metadata(dest) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o077 != 0 {
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(dest, perms);
            }
        }
    }
    Ok(())
}
