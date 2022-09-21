use anyhow::Result;
use clap::{Parser, Subcommand};

use fika_manager::{RecoveryOpt, recovery};
use fika_manager::{MiscOpt, misc};
use fika_manager::{DaemonOpt, daemon};

#[derive(Parser, Debug)]
#[clap(
    name = "fika-manager",
    about = "FIKA manager to interactive with platform",
    version = "0.0.4"
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
        Commands::Daemon(opt) => {
            daemon(opt).await?
        },
        Commands::Recovery(opt) => {
            recovery(opt).await?
        },
        Commands::Misc(opt) => {
            misc(opt).await?
        },
    }

    Ok(())
}
