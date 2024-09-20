use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;
use crypto::{PrivateKey, PublicKey, RingPublicKey};

use super::make_deaddrop_addrs;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    mode: anonycast::ModeOfOperation,

    #[clap(long)]
    private_key: PrivateKey,

    #[clap(long)]
    tor_proxy: Option<SocketAddr>,

    #[clap(long)]
    deaddrop_tcp: Vec<SocketAddr>,

    #[clap(long)]
    deaddrop_tor: Vec<String>,

    #[clap(long)]
    allowed_sender_key: Vec<RingPublicKey>,

    #[clap(long)]
    allowed_receiver_key: Vec<PublicKey>,
}

pub async fn main(args: Args) -> Result<()> {
    let deaddrop_addresses =
        make_deaddrop_addrs(args.deaddrop_tcp, args.deaddrop_tor, args.tor_proxy);
    let config = anonycast::asset_owner::Config {
        mode: args.mode,
        private_key: args.private_key,
        deaddrop_addresses,
        allowed_sender_keys: args.allowed_sender_key,
        allowed_receiver_keys: args.allowed_receiver_key,
    };
    anonycast::asset_owner::run(config)
        .await
        .context("while running asset owner")
}
