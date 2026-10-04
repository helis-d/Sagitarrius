mod add;
mod audit;
mod backup;
mod edit;
mod exists;
mod export;
mod file;
mod gen;
mod get;
mod import;
mod info;
mod init;
mod list;
mod lockdown;
mod migrate;
mod passwd;
mod recovery;
mod remove;
mod rename;
mod run;
mod search;
mod snapshot;
mod status;

use crate::cli::{BackupAction, Commands, FileAction, RecoveryAction, SnapshotAction};
use crate::error::Result;

pub fn dispatch(cmd: Commands) -> Result<i32> {
    match cmd {
        Commands::Menu => {
            crate::banner::print_landing();
            Ok(0)
        }
        Commands::Init => init::run(),
        Commands::Passwd => passwd::run(),
        Commands::Add {
            name,
            value,
            kind,
            username,
        } => add::run(name, value, kind, username),
        Commands::Gen {
            name,
            length,
            no_symbols,
        } => gen::run(name, length, no_symbols),
        Commands::Get { name, json } => get::run(name, json),
        Commands::Info { name } => info::run(name),
        Commands::List => list::run(),
        Commands::Remove { name, yes } => remove::run(name, yes),
        Commands::Edit { name } => edit::run(name),
        Commands::Rename { old, new } => rename::run(old, new),
        Commands::Exists { name } => exists::run(name),
        Commands::Search { query } => search::run(query),
        Commands::Import { path, overwrite } => import::run(path, overwrite),
        Commands::Export { plaintext, path } => export::run(plaintext, path),
        Commands::Audit => audit::run(),
        Commands::Migrate => migrate::run(),
        Commands::Snapshot { action } => match action {
            SnapshotAction::Create => snapshot::create(),
            SnapshotAction::List => snapshot::list(),
            SnapshotAction::Verify { id } => snapshot::verify(id),
            SnapshotAction::Restore { id } => snapshot::restore(id),
            SnapshotAction::Delete { id } => snapshot::delete(id),
        },
        Commands::Backup { action } => match action {
            BackupAction::Create { to } => backup::create(to),
            BackupAction::List => backup::list(),
            BackupAction::Verify { id, from } => backup::verify(id, from),
            BackupAction::Restore { id, from } => backup::restore(id, from),
            BackupAction::Prune { keep } => backup::prune(keep),
        },
        Commands::Recovery { action } => match action {
            RecoveryAction::Create => recovery::create(),
            RecoveryAction::Verify => recovery::verify(),
            RecoveryAction::ResetPassword => recovery::reset_password(),
        },
        Commands::File { action } => match action {
            FileAction::Put { path, name } => file::put(path, name),
            FileAction::Get { name, dest } => file::get(name, dest),
        },
        Commands::Status => status::run(),
        Commands::Lockdown { off } => lockdown::run(off),
        Commands::Run { secret, command } => run::run(secret, command),
    }
}
