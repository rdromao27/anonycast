use std::net::SocketAddr;

use anonycast::DeaddropAddr;
use anyhow::Result;
use clap::Parser;
use tracing_chrome::ChromeLayerBuilder;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

mod asset_owner;
mod benchmark;
mod client;
mod deaddrop;
mod genkey;
mod pubkey;

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    cmd: Subcommand,
}

#[derive(Debug, Parser)]
enum Subcommand {
    Client(client::Args),
    AssetOwner(asset_owner::Args),
    Deaddrop(deaddrop::Args),
    Genkey(genkey::Args),
    Pubkey(pubkey::Args),
    Benchmark(benchmark::Args),
}

pub async fn main() -> Result<()> {
    //let (chrome_layer, _guard) = ChromeLayerBuilder::new().build();
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::CLOSE)
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        //.with(chrome_layer)
        .init();

    let args = Args::parse();

    match args.cmd {
        Subcommand::Client(cargs) => client::main(cargs).await,
        Subcommand::AssetOwner(cargs) => asset_owner::main(cargs).await,
        Subcommand::Deaddrop(cargs) => deaddrop::main(cargs).await,
        Subcommand::Genkey(cargs) => genkey::main(cargs).await,
        Subcommand::Pubkey(cargs) => pubkey::main(cargs).await,
        Subcommand::Benchmark(cargs) => benchmark::main(cargs).await,
    }
}

fn make_deaddrop_addrs(
    tcp: Vec<SocketAddr>,
    tor: Vec<String>,
    tor_proxy: Option<SocketAddr>,
) -> Vec<DeaddropAddr> {
    let mut addrs = Vec::new();
    addrs.extend(tcp.into_iter().map(DeaddropAddr::Tcp));
    if let Some(tor_proxy) = tor_proxy {
        addrs.extend(tor.into_iter().map(|addr| DeaddropAddr::Tor {
            onion: addr,
            proxy: tor_proxy,
        }));
    }
    addrs
}
