use clap::{Parser, Subcommand};

mod crypto;
mod models;
mod storage;

#[derive(Parser)]
#[command(name = "passmngr", about = "A terminal password manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    Init,
    /// Add a new entry (interactive prompt)
    Add {
        name: String,
    },
    /// Retrieve and display an entry
    Get {
        name: String,
    },
    /// List all entries
    List,
    /// Delete an entry
    Delete {
        name: String,
    },
    /// Update an existing entry (interactive prompt)
    Update {
        name: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Init => storage::init_vault(),
        Commands::Add { name } => storage::add_entry(name),
        Commands::Get { name } => storage::get_entry(name),
        Commands::List => storage::list_entries(),
        Commands::Delete { name } => storage::delete_entry(name),
        Commands::Update { name } => storage::update_entry(name),
    }
}
