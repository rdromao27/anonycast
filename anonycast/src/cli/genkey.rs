use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(long)]
    ring: bool,
}

pub async fn main(args: Args) -> Result<()> {
    if args.ring {
        let (_, key) = crypto::ring_generate();
        println!("{key}");
    } else {
        let (_, key) = crypto::generate();
        println!("{key}");
    }
    Ok(())
}
