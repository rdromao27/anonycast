use std::net::SocketAddr;

use anonycast::ModeOfOperation;
use anyhow::{Context, Result};
use clap::Parser;
use crypto::{PrivateKey, PublicKey};

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    mode: ModeOfOperation,

    #[clap(long, default_value = "0.0.0.0:8000")]
    address: SocketAddr,

    #[clap(long)]
    private_key: Option<PrivateKey>,

    #[clap(long)]
    asset_owner_key: Option<PublicKey>,

    #[clap(long, default_value = "2")]
    difficulty: u8,

    #[clap(long, default_value = "100")]
    acceptance_window: u64,
}

pub async fn main(args: Args) -> Result<()> {
    let config = anonycast::deaddrop::Config {
        mode: args.mode,
        private_key: args.private_key.unwrap_or_else(|| crypto::generate().1),
        address: args.address,
        difficulty: args.difficulty,
        acceptance_window: args.acceptance_window,
        asset_owner_key: args.asset_owner_key,
        asset_owner_update: None,
    };
    anonycast::deaddrop::run(config)
        .await
        .context("while running deaddrop")
}
