use std::time::Duration;

use crypto::{PrivateKey, PublicKey, RingPublicKey};

use crate::{
    protocol::{Message, Signed, UpdateAllowedKeys},
    DeaddropAddr, DeaddropConn, ModeOfOperation,
};

#[derive(Debug)]
pub struct Config {
    pub mode: ModeOfOperation,
    pub private_key: PrivateKey,
    pub deaddrop_addresses: Vec<DeaddropAddr>,
    pub allowed_sender_keys: Vec<RingPublicKey>,
    pub allowed_receiver_keys: Vec<PublicKey>,
}

pub async fn run(config: Config) -> std::io::Result<()> {
    tracing::info!("deadrop addresses = {:#?}", config.deaddrop_addresses);
    let update = Signed::sign(
        &config.private_key,
        Message::UpdateAllowedKeys(UpdateAllowedKeys {
            allowed_sender_keys: config.allowed_sender_keys,
            allowed_receiver_keys: config.allowed_receiver_keys,
            beacon: drand::get_beacon_from_first_chain().await.unwrap(),
        }),
    );

    let mut streams = Vec::new();
    for addr in &config.deaddrop_addresses {
        match DeaddropConn::connect(addr).await {
            Ok(stream) => streams.push(stream),
            Err(err) => {
                tracing::error!("failed to connect to deaddrop {:?}: {}", addr, err);
                return Err(err);
            }
        }
    }

    loop {
        tracing::info!("sending allowed keys update to {} deaddrops", streams.len());
        for stream in &mut streams {
            stream.send(&update).await;
            // if let Err(err) = rle::serialize_and_write(&mut *stream, &update) {
            //     tracing::error!("failed to send update message to {:?}: {}", stream, err);
            // }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub async fn create_update_message(
    private_key: &PrivateKey,
    allowed_sender_keys: Vec<RingPublicKey>,
    allowed_receiver_keys: Vec<PublicKey>,
) -> Signed<UpdateAllowedKeys> {
    Signed::sign(
        &private_key,
        UpdateAllowedKeys {
            allowed_sender_keys,
            allowed_receiver_keys,
            beacon: drand::get_beacon_from_first_chain().await.unwrap(),
        },
    )
}
