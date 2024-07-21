use std::{io::Read, sync::Arc, time::Duration};

use anonycast::DeaddropAddr;
use anyhow::{Context, Result};
use tokio::{sync::Barrier, task::JoinSet};

#[tokio::main]
async fn main() -> Result<()> {
    let (kpub, kpriv) = crypto::generate();
    let mut config = anonycast::client::Config {
        mode: anonycast::ModeOfOperation::Open,
        private_key: Some(kpriv),
        ring_private_key: Default::default(),
        ring: Default::default(),
        receivers_keys: Default::default(),
        deaddrop_addresses: Default::default(),
        difficulty: 0,
        acceptance_window: 100,
        asset_owner_public_key: Default::default(),
        drand_chain: Some(drand::chain_list().await.unwrap()[0].clone()),
        drand_client: Default::default(),
    };
    let client = anonycast::client::Client::new(config.clone())
        .await
        .context("creating client")?;

    let messages = {
        let mut requests = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let request = anonycast::client::PrepareMessageRequest {
                topic: "topic".to_string(),
                content: "x".repeat(1024),
            };
            requests.push(request);
        }
        client.prepare_messages(requests).await
    };
    drop(client);

    println!("entering loop");
    config.deaddrop_addresses = vec![DeaddropAddr::Tcp("127.0.0.1:4000".parse().unwrap())];
    'outer: loop {
        const CLIENT_COUNT: usize = 200;
        let mut client_set = JoinSet::new();
        for _ in 0..CLIENT_COUNT {
            client_set.spawn(anonycast::client::Client::new(config.clone()));
        }

        let mut clients = Vec::with_capacity(CLIENT_COUNT);
        while let Some(result) = client_set.join_next().await {
            match result {
                Ok(Ok(client)) => clients.push(client),
                Ok(Err(err)) => {
                    eprintln!("failed to create client: {err}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue 'outer;
                }
                Err(err) => panic!("{err}"),
            };
        }

        println!("sending messages to deaddrop");

        let mut client_set = JoinSet::new();
        let barrier = Arc::new(Barrier::new(CLIENT_COUNT));
        for mut client in clients {
            let barrier = barrier.clone();
            let messages = messages.clone();
            client_set.spawn(async move {
                barrier.wait().await;
                for message in messages.clone() {
                    client.send_prepared_message(message).await;
                }
            });
        }

        while let Some(_) = client_set.join_next().await {}
        println!("done");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
