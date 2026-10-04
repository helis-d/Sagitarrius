mod add;
mod audit;
mod edit;
mod exists;
mod export;
mod gen;
mod get;
mod import;
mod info;
mod init;
mod list;
mod passwd;
mod remove;
mod rename;
mod run;
mod search;

use crate::cli::Commands;
use crate::error::Result;

pub fn dispatch(cmd: Commands) -> Result<i32> {
    match cmd {
        Commands::Menu => {
            crate::banner::print_landing();
            Ok(0)
        }
        Commands::Init => init::run(),
        Commands::Passwd => passwd::run(),
        Commands::Add { name, value } => add::run(name, value),
        Commands::Gen {
            name,
            length,
            no_symbols,
        } => gen::run(name, length, no_symbols),
        Commands::Get { name } => get::run(name),
        Commands::Info { name } => info::run(name),
        Commands::List => list::run(),
        Commands::Remove { name, yes } => remove::run(name, yes),
        Commands::Edit { name } => edit::run(name),
        Commands::Rename { old, new } => rename::run(old, new),
        Commands::Exists { name } => exists::run(name),
        Commands::Search { query } => search::run(query),
        Commands::Import { path, overwrite } => import::run(path, overwrite),
        Commands::Export { path } => export::run(path),
        Commands::Audit => audit::run(),
        Commands::Run { command } => run::run(command),
    }
}
