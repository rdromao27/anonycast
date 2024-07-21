use std::io::Read;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    ring: bool,
}

pub async fn main(args: Args) -> Result<()> {
    let mut input = String::default();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("failed to read from stdin");
    let input = input.trim();

    if args.ring {
        let key: crypto::RingPrivateKey = input
            .parse::<crypto::RingPrivateKey>()
            .expect("invalid ring private key");
        println!("{}", key.public_key());
    } else {
        let key = input
            .parse::<crypto::PrivateKey>()
            .expect("invalid private key");
        println!("{}", key.public_key());
    }
    Ok(())
}
