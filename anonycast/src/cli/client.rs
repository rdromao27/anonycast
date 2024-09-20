use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use anonycast::stats;
use anonycast::ModeOfOperation;
use anyhow::Result;
use clap::Parser;
use crypto::{PrivateKey, PublicKey, RingPrivateKey, RingPublicKey};

use super::make_deaddrop_addrs;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    mode: ModeOfOperation,

    #[clap(long)]
    private_key: Option<PrivateKey>,

    #[clap(long)]
    ring_private_key: Option<RingPrivateKey>,

    #[clap(long)]
    ring_key: Vec<RingPublicKey>,

    #[clap(long)]
    receiver_key: Vec<PublicKey>,

    #[clap(long, default_value = "2")]
    difficulty: u8,

    #[clap(long, default_value = "100")]
    acceptance_window: u64,

    #[clap(long)]
    tor_proxy: Option<SocketAddr>,

    #[clap(long)]
    deaddrop_tcp: Vec<SocketAddr>,

    #[clap(long)]
    deaddrop_tor: Vec<String>,

    #[clap(long, default_value = "1")]
    number_of_requests: u64,

    #[clap(long)]
    asset_owner_public_key: Option<PublicKey>,

    #[clap(long, default_value = "0")]
    initial_delay: u64,
}

pub async fn main(args: Args) -> Result<()> {
    let deaddrop_addresses =
        make_deaddrop_addrs(args.deaddrop_tcp, args.deaddrop_tor, args.tor_proxy);
    let config = anonycast::client::Config {
        mode: args.mode,
        private_key: args.private_key,
        ring_private_key: args.ring_private_key,
        ring: if args.ring_key.is_empty() {
            None
        } else {
            Some(crypto::Ring::from(args.ring_key))
        },
        receivers_keys: args.receiver_key,
        deaddrop_addresses,
        difficulty: args.difficulty,
        acceptance_window: args.acceptance_window,
        asset_owner_public_key: args.asset_owner_public_key,
        drand_chain: Default::default(),
        drand_client: Default::default(),
    };

    tracing::info!("creating client");
    let mut client = anonycast::client::Client::new(config).await.unwrap();
    tracing::info!("client created");

    std::thread::sleep(Duration::from_secs(args.initial_delay));
    for i in 0..args.number_of_requests {
        let topic = "test-topic";
        let content = format!("test-data{}", i);
        tracing::info!("sending message {} -> {}", topic, content);

        let t_start = Instant::now();
        client.send_message(topic, content.as_bytes()).await;
        stats::log(stats::Operation::Send, t_start.elapsed());
    }

    let t_start = Instant::now();
    let messages = client.fetch_messages("test-topic", 0).await;
    stats::log(stats::Operation::Retrieve, t_start.elapsed());
    tracing::debug!("{messages:#?}");

    stats::print();

    Ok(())
}
