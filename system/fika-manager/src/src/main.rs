use anyhow::Result;
use clap::{Parser, Subcommand};

use fika_manager::{daemon, DaemonOpt};
use fika_manager::{time_tools, TimeToolOpt};
use fika_manager::{recovery, RecoveryOpt};
#[cfg(feature = "boss-api")]
use fika_manager::{boss_tools, CurlBossOpt};
#[cfg(feature = "ethers")]
use fika_manager::{wallet_tools, WalletCommand};

#[derive(Parser, Debug)]
#[clap(
    name = "fika-manager",
    about = "FIKA manager to interactive with platform",
    version = "0.0.6"
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Daemon(DaemonOpt),
    Recovery(RecoveryOpt),
    Time(TimeToolOpt),
    #[cfg(feature = "boss-api")]
    Boss(CurlBossOpt),
    #[cfg(feature = "ethers")]
    #[clap(subcommand)]
    Wallet(WalletCommand),
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //let opt = Opt::parse();
    let args = Cli::parse();
    match args.command {
        Commands::Daemon(opt) => daemon(opt).await?,
        Commands::Recovery(opt) => recovery(opt).await?,
        Commands::Time(opt) => time_tools(opt).await?,
        #[cfg(feature = "boss-api")]
        Commands::Boss(opt) => boss_tools(opt).await?,
        #[cfg(feature = "ethers")]
        Commands::Wallet(opt) => wallet_tools(opt).await?,
    }

    Ok(())
}
