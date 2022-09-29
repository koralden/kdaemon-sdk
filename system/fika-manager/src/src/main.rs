use anyhow::Result;
use clap::{Parser, Subcommand};

use fika_manager::{daemon, DaemonOpt};
use fika_manager::{misc, MiscOpt};
use fika_manager::{recovery, RecoveryOpt};

#[derive(Parser, Debug)]
#[clap(
    name = "fika-manager",
    about = "FIKA manager to interactive with platform",
    version = "0.0.5"
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Daemon(DaemonOpt),
    Recovery(RecoveryOpt),
    Misc(MiscOpt),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //let opt = Opt::parse();
    let args = Cli::parse();
    match args.command {
        Commands::Daemon(opt) => daemon(opt).await?,
        Commands::Recovery(opt) => recovery(opt).await?,
        Commands::Misc(opt) => misc(opt).await?,
    }

    Ok(())
}
