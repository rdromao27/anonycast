fn main() -> Result<(), Box<dyn std::error::Error>> {
    let chains = drand::chain_list()?;
    println!("chains: {:#?}", chains);
    for chain in chains {
        let chain_info = drand::chain_info(&chain)?;
        println!("chain_info: {:#?}", chain_info);
        let beacon = drand::chain_latest_randomness(&chain)?;
        println!("beacon: {:#?}", beacon);
        println!(
            "verify: {:?}",
            beacon.verify(chain_info.scheme_id, &chain_info.public_key)
        );
    }
    Ok(())
}
