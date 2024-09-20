use std::{
    net::{SocketAddr, ToSocketAddrs as _},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::Barrier;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(subcommand)]
    bench: Benchmark,
}

#[derive(Debug, Parser)]
enum Benchmark {
    PublishTroughput(PublishTroughputArgs),
    RetreiveTroughput(RetreiveTroughputArgs),
    Latency(LatencyArgs),
}

#[derive(Debug, Parser)]
struct PublishTroughputArgs {
    #[clap(long)]
    clients: usize,
    #[clap(long)]
    runtime: usize,
    #[clap(long)]
    difficulty: usize,
    #[clap(long)]
    message_size: usize,
    #[clap(long)]
    prepared_messages: usize,
    #[clap(long)]
    deaddrop_address: String,
    #[clap(long)]
    acceptance_window: usize,
    #[clap(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct RetreiveTroughputArgs {
    #[clap(long)]
    clients: usize,
    #[clap(long)]
    runtime: usize,
    #[clap(long)]
    difficulty: usize,
    #[clap(long)]
    message_size: usize,
    #[clap(long)]
    message_count: usize,
    #[clap(long)]
    deaddrop_address: String,
    #[clap(long)]
    acceptance_window: usize,
    #[clap(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct LatencyArgs {
    #[clap(long)]
    deaddrops: usize,

    #[clap(long)]
    deaddrop_listen_address: Vec<SocketAddr>,

    #[clap(long)]
    deaddrop_onion_address: Vec<String>,

    #[clap(long)]
    client_tor_proxy: SocketAddr,

    #[clap(long)]
    allowed_receivers: usize,

    #[clap(long)]
    allowed_senders: usize,

    #[clap(long)]
    difficulty: usize,

    #[clap(long)]
    mode: anonycast::ModeOfOperation,

    #[clap(long)]
    acceptance_window: usize,

    #[clap(long)]
    output: Option<PathBuf>,
}

pub async fn main(args: Args) -> Result<()> {
    match args.bench {
        Benchmark::PublishTroughput(args) => benchmark_publish_troughput(args).await,
        Benchmark::RetreiveTroughput(args) => benchmark_retrieve_troughput(args).await,
        Benchmark::Latency(args) => benchmark_latency(args).await,
    }
}

#[derive(Debug, Clone)]
struct ConsumerQueue<T> {
    values: Arc<Mutex<Vec<T>>>,
}

impl<T> ConsumerQueue<T> {
    pub fn new(values: Vec<T>) -> Self {
        Self {
            values: Arc::new(Mutex::new(values)),
        }
    }

    pub fn consume(&self) -> Option<T> {
        self.values.lock().unwrap().pop()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PublishTroughputResultsMessage {
    client: usize,
    message: usize,
    timestamp: f64,
    latency: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PublishTroughputResults {
    clients: usize,
    difficulty: usize,
    message_size: usize,
    prepared_messages: usize,
    acceptance_window: usize,
    messages: Vec<PublishTroughputResultsMessage>,
}

async fn benchmark_publish_troughput(args: PublishTroughputArgs) -> Result<()> {
    let deaddrop_addr = deaddrop_sockaddr(&args.deaddrop_address)?;
    let (client_priv_key, prepared_messages) = prepare_open_mode_messages_cached(
        args.prepared_messages,
        args.message_size,
        args.difficulty,
    )
    .await;
    let message_queue = ConsumerQueue::new(prepared_messages);
    let barrier = Arc::new(Barrier::new(args.clients + 1));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(args.clients);
    for client_id in 0..args.clients {
        let config = anonycast::client::Config {
            mode: anonycast::ModeOfOperation::Open,
            private_key: Some(client_priv_key.clone()),
            ring_private_key: None,
            ring: None,
            receivers_keys: Default::default(),
            deaddrop_addresses: vec![anonycast::DeaddropAddr::Tcp(deaddrop_addr)],
            difficulty: args.difficulty as u8,
            acceptance_window: args.acceptance_window as u64,
            asset_owner_public_key: None,
            drand_chain: Default::default(),
            drand_client: Default::default(),
        };

        let message_queue = message_queue.clone();
        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let handle = tokio::spawn(async move {
            // stagger connects to help prevent timeouts
            tokio::time::sleep(Duration::from_millis(50 * client_id as u64)).await;

            let mut client = match create_client_retry(&config, 5).await {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("client failed to connect: {err}");
                    std::process::exit(1);
                }
            };

            let mut message_id = 0;
            let mut result_messages = Vec::new();

            barrier.wait().await;
            while let Some(message) = message_queue.consume() {
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                let timestamp = get_timestamp();
                client.send_prepared_message(message).await;
                let latency = get_timestamp() - timestamp;
                let result_message = PublishTroughputResultsMessage {
                    client: client_id,
                    message: message_id,
                    timestamp,
                    latency,
                };
                result_messages.push(result_message);
                message_id += 1;
            }

            result_messages
        });
        handles.push(handle);
    }

    barrier.wait().await;
    tokio::time::sleep(Duration::from_secs(args.runtime as u64)).await;
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    let mut client_messages = Vec::new();
    for handle in handles {
        let m = handle.await.context("client task failed")?;
        client_messages.extend(m);
    }

    let results = PublishTroughputResults {
        clients: args.clients,
        difficulty: args.difficulty,
        message_size: args.message_size,
        prepared_messages: args.prepared_messages,
        acceptance_window: args.acceptance_window,
        messages: client_messages,
    };

    write_result_to_output(&args.output, &results).await?;

    let min_ts = results
        .messages
        .iter()
        .map(|m| m.timestamp)
        .fold(f64::INFINITY, |a, b| a.min(b));
    let max_ts = results
        .messages
        .iter()
        .map(|m| m.timestamp)
        .fold(f64::NEG_INFINITY, |a, b| a.max(b));
    let troughput = results.messages.len() as f64 / (max_ts - min_ts);
    println!("troughput: {:.2} ops/s", troughput);

    Ok(())
}

#[derive(Debug, Serialize)]
struct RetreiveTroughputResultsFetch {
    client: usize,
    fetch: usize,
    timestamp: f64,
    latency: f64,
}

#[derive(Debug, Serialize)]
struct RetreiveTroughputResults {
    clients: usize,
    runtime: usize,
    difficulty: usize,
    message_size: usize,
    message_count: usize,
    acceptance_window: usize,
    message_fetches: Vec<RetreiveTroughputResultsFetch>,
}

async fn benchmark_retrieve_troughput(args: RetreiveTroughputArgs) -> Result<()> {
    const TOPIC: &'static str = "topic";

    let deaddrop_addr = deaddrop_sockaddr(&args.deaddrop_address)?;

    {
        let (_kpub, kpriv) = crypto::generate();
        let config = anonycast::client::Config {
            mode: anonycast::ModeOfOperation::Open,
            private_key: Some(kpriv),
            ring_private_key: Default::default(),
            ring: Default::default(),
            receivers_keys: Default::default(),
            deaddrop_addresses: vec![anonycast::DeaddropAddr::Tcp(deaddrop_addr)],
            difficulty: args.difficulty as u8,
            acceptance_window: args.acceptance_window as u64,
            asset_owner_public_key: Default::default(),
            drand_chain: Default::default(),
            drand_client: Default::default(),
        };
        let mut client = anonycast::client::Client::new(config).await?;

        let mut data = vec![0u8; args.message_size];
        for message_id in 0..args.message_count {
            data[0..4].copy_from_slice(&(message_id as u32).to_be_bytes());
            client.send_message(TOPIC, &data).await;
        }
    }

    let (_client_kpub, client_kpriv) = crypto::generate();
    let drand_client = drand::CachingClient::new(drand::DEFAULT_API_URL);
    let mut handles = Vec::with_capacity(args.clients);
    let barrier = Arc::new(Barrier::new(args.clients + 1));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let drand_chain = drand::chain_list().await.unwrap()[0].clone();
    for client_id in 0..args.clients {
        let config = anonycast::client::Config {
            mode: anonycast::ModeOfOperation::Open,
            private_key: Some(client_kpriv.clone()),
            ring_private_key: Default::default(),
            ring: Default::default(),
            receivers_keys: Default::default(),
            deaddrop_addresses: vec![anonycast::DeaddropAddr::Tcp(deaddrop_addr)],
            difficulty: args.difficulty as u8,
            acceptance_window: args.acceptance_window as u64,
            asset_owner_public_key: Default::default(),
            drand_chain: Some(drand_chain.clone()),
            drand_client: Some(drand_client.clone()),
        };

        let barrier = barrier.clone();
        let stop_flag = stop_flag.clone();
        let handle = tokio::spawn(async move {
            // stagger connects to help prevent timeouts
            tokio::time::sleep(Duration::from_millis(50 * client_id as u64)).await;

            let mut client = match create_client_retry(&config, 5).await {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("client failed to connect: {err}");
                    std::process::exit(1);
                }
            };

            barrier.wait().await;
            let mut fetches = Vec::new();
            let mut fetch_id = 0;
            while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let timestamp = get_timestamp();
                client.fetch_messages_bench(TOPIC).await;
                let latency = get_timestamp() - timestamp;
                fetches.push(RetreiveTroughputResultsFetch {
                    client: client_id,
                    fetch: fetch_id,
                    timestamp,
                    latency,
                });
                fetch_id += 1;
            }
            fetches
        });
        handles.push(handle);
    }

    barrier.wait().await;
    tokio::time::sleep(Duration::from_secs(args.runtime as u64)).await;
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    let mut fetches = Vec::new();
    for handle in handles {
        let f = handle.await.context("client task failed")?;
        fetches.extend(f);
    }

    let results = RetreiveTroughputResults {
        clients: args.clients,
        runtime: args.runtime,
        difficulty: args.difficulty,
        message_size: args.message_size,
        message_count: args.message_count,
        acceptance_window: args.acceptance_window,
        message_fetches: fetches,
    };

    write_result_to_output(&args.output, &results).await?;

    let min_ts = results
        .message_fetches
        .iter()
        .map(|m| m.timestamp)
        .fold(f64::INFINITY, |a, b| a.min(b));
    let max_ts = results
        .message_fetches
        .iter()
        .map(|m| m.timestamp)
        .fold(f64::NEG_INFINITY, |a, b| a.max(b));
    let troughput = results.message_fetches.len() as f64 / (max_ts - min_ts);
    println!("troughput: {:.2} ops/s", troughput);

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreparedMessageCache {
    message_size: usize,
    crypto_difficulty: usize,
    private_key: crypto::PrivateKey,
    messages: Vec<anonycast::client::PreparedMessage>,
}

pub async fn prepare_open_mode_messages_cached(
    message_count: usize,
    message_size: usize,
    crypto_difficulty: usize,
) -> (crypto::PrivateKey, Vec<anonycast::client::PreparedMessage>) {
    let cache_dir = PathBuf::from(".cache/prepared-messages");
    tokio::fs::create_dir_all(&cache_dir)
        .await
        .context("creating prepared messages cache dir")
        .unwrap();
    let filename = format!("ms{message_size}_cd{crypto_difficulty}.bin");
    let filepath = cache_dir.join(filename);
    if filepath.exists() {
        let content = tokio::fs::read(&filepath)
            .await
            .context("reading prepared messages cache file")
            .unwrap();
        let cached = bincode::deserialize::<PreparedMessageCache>(&content).unwrap();
        assert_eq!(cached.message_size, message_size);
        assert_eq!(cached.crypto_difficulty, crypto_difficulty);
        if cached.messages.len() >= message_count {
            return (cached.private_key, cached.messages);
        }
    }

    let (_pubkey, privkey) = crypto::generate();
    let messages =
        prepare_open_mode_messages(message_count, message_size, crypto_difficulty, &privkey).await;
    let cached = PreparedMessageCache {
        message_size,
        private_key: privkey,
        crypto_difficulty,
        messages,
    };
    let serialized = bincode::serialize(&cached).unwrap();
    tokio::fs::write(filepath, serialized)
        .await
        .context("writing prepared messages cache")
        .unwrap();
    (cached.private_key, cached.messages)
}

pub async fn prepare_open_mode_messages(
    message_count: usize,
    message_size: usize,
    crypto_difficulty: usize,
    client_private_key: &crypto::PrivateKey,
) -> Vec<anonycast::client::PreparedMessage> {
    let config = anonycast::client::Config {
        mode: anonycast::ModeOfOperation::Open,
        private_key: Some(client_private_key.clone()),
        ring_private_key: Default::default(),
        ring: Default::default(),
        receivers_keys: Default::default(),
        deaddrop_addresses: Default::default(),
        difficulty: crypto_difficulty as u8,
        acceptance_window: Default::default(),
        asset_owner_public_key: Default::default(),
        drand_chain: Default::default(),
        drand_client: Default::default(),
    };
    let client = anonycast::client::Client::new(config).await.unwrap();
    let mut requests = Vec::with_capacity(message_count);
    for i in 0..message_count {
        use std::fmt::Write;
        let mut content = String::with_capacity(message_size);
        write!(&mut content, "{i}").unwrap();
        content.extend(std::iter::repeat('x').take(message_size - content.len()));
        content.truncate(message_size);
        requests.push(anonycast::client::PrepareMessageRequest {
            topic: "topic".to_string(),
            content,
        });
    }
    client.prepare_messages(requests).await
}

#[derive(Debug, Serialize)]
struct LatencyResults {
    deaddrops: usize,
    allowed_receivers: usize,
    allowed_senders: usize,
    difficulty: usize,
    mode: String,
    acceptance_window: usize,
    publish_latency: f64,
    retreive_latency: f64,
}

async fn benchmark_latency(args: LatencyArgs) -> Result<()> {
    const TOPIC: &'static str = "topic";
    const TOPIC_WARMUP: &'static str = "warmup";
    const MESSAGE_DATA: &'static [u8] = &[0u8; 128];

    if args.deaddrops != args.deaddrop_listen_address.len() {
        anyhow::bail!("deaddrop listen address count must match number of deaddrops");
    }

    match args.mode {
        anonycast::ModeOfOperation::Open => {
            if args.allowed_senders != 0 {
                anyhow::bail!("allowed senders must be 0 in open mode");
            }
            if args.allowed_receivers != 0 {
                anyhow::bail!("allowed receivers must be 0 in open mode");
            }
        }
        anonycast::ModeOfOperation::SenderRestricted => {
            if args.allowed_senders <= 1 {
                anyhow::bail!("allowed senders must be greater than 1 in sender restricted mode");
            }
            if args.allowed_receivers != 0 {
                anyhow::bail!("allowed receivers must be 0 in sender restricted mode");
            }
        }
        anonycast::ModeOfOperation::ReceiverRestricted => {
            if args.allowed_senders != 0 {
                anyhow::bail!("allowed senders must be 0 in receiver restricted mode");
            }
        }
        anonycast::ModeOfOperation::FullyRestricted => {
            if args.allowed_senders <= 1 {
                anyhow::bail!("allowed senders must be greater than 1 in restricted mode");
            }
        }
    }

    let (ring, ring_private_key, allowed_sender_keys) = {
        match args.mode {
            anonycast::ModeOfOperation::SenderRestricted
            | anonycast::ModeOfOperation::FullyRestricted => {
                let (ring_pub, ring_priv) = crypto::ring_generate();
                let mut pubkeys = vec![ring_pub];
                for _ in 0..args.allowed_senders - 1 {
                    let (rpub, _rpriv) = crypto::ring_generate();
                    pubkeys.push(rpub);
                }
                let ring = crypto::Ring::from(pubkeys.clone());
                (Some(ring), Some(ring_priv), pubkeys)
            }
            _ => (None, None, Vec::default()),
        }
    };

    let receivers_keys = {
        (0..args.allowed_receivers)
            .map(|_| crypto::generate().0)
            .collect::<Vec<_>>()
    };

    let (asset_owner_public_key, asset_owner_private_key) = crypto::generate();
    let asset_owner_update = if args.mode != anonycast::ModeOfOperation::Open {
        Some(
            anonycast::asset_owner::create_update_message(
                &asset_owner_private_key,
                allowed_sender_keys.clone(),
                receivers_keys.clone(),
            )
            .await,
        )
    } else {
        None
    };

    for i in 0..args.deaddrops {
        let (_kpub, kpriv) = crypto::generate();
        let config = anonycast::deaddrop::Config {
            mode: args.mode,
            private_key: kpriv,
            address: args.deaddrop_listen_address[i],
            difficulty: args.difficulty as u8,
            acceptance_window: args.acceptance_window as u64,
            asset_owner_key: Some(asset_owner_public_key.clone()),
            asset_owner_update: asset_owner_update.clone(),
        };
        tokio::spawn(async move {
            if let Err(err) = anonycast::deaddrop::run(config).await {
                eprintln!("deaddrop failure: {err}");
                std::process::exit(1);
            }
        });
    }

    let deaddrop_addresses = {
        let mut addrs = Vec::new();
        for onion_addr in args.deaddrop_onion_address {
            addrs.push(anonycast::DeaddropAddr::Tor {
                onion: onion_addr,
                proxy: args.client_tor_proxy,
            });
        }
        addrs
    };

    let (publish_latency, retreive_latency) = {
        let (_kpub, kpriv) = crypto::generate();
        let config = anonycast::client::Config {
            mode: args.mode,
            private_key: Some(kpriv),
            ring_private_key,
            ring,
            receivers_keys,
            deaddrop_addresses,
            difficulty: args.difficulty as u8,
            acceptance_window: args.acceptance_window as u64,
            asset_owner_public_key: Some(asset_owner_public_key),
            drand_chain: Default::default(),
            drand_client: Default::default(),
        };

        let mut client = anonycast::client::Client::new(config)
            .await
            .context("creating client")?;

        client.send_message(TOPIC_WARMUP, &MESSAGE_DATA).await;
        client.fetch_messages(TOPIC_WARMUP, 0).await;

        let p_start = Instant::now();
        client.send_message(TOPIC, &MESSAGE_DATA).await;
        let publish_latency = p_start.elapsed();

        let r_start = Instant::now();
        client.fetch_messages(TOPIC, 0).await;
        let retreive_latency = r_start.elapsed();

        (publish_latency, retreive_latency)
    };

    let results = LatencyResults {
        deaddrops: args.deaddrops,
        allowed_receivers: args.allowed_receivers,
        allowed_senders: args.allowed_senders,
        difficulty: args.difficulty,
        mode: args.mode.to_string(),
        acceptance_window: args.acceptance_window,
        publish_latency: publish_latency.as_secs_f64(),
        retreive_latency: retreive_latency.as_secs_f64(),
    };

    println!("publish latency: {} s", results.publish_latency);
    println!("retreive latency: {} s", results.retreive_latency);

    write_result_to_output(&args.output, &results).await?;

    Ok(())
}

fn deaddrop_sockaddr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()
        .context("while creating deaddrop sockaddr")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve deaddrop address"))
}

fn get_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

async fn write_result_to_output(output: &Option<PathBuf>, result: &impl Serialize) -> Result<()> {
    if let Some(output) = output {
        if let Some(parent) = output.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .context("while creating benchmark results output parent directory")?;
        }
        let serialized = serde_json::to_string(result).unwrap();
        tokio::fs::write(output, serialized)
            .await
            .context("while writing benchmark results")?;
    }
    Ok(())
}

async fn create_client_retry(
    config: &anonycast::client::Config,
    retries: usize,
) -> Result<anonycast::client::Client> {
    for _ in 0..retries {
        match anonycast::client::Client::new(config.clone())
            .await
            .context("creating client")
        {
            Ok(client) => return Ok(client),
            Err(_) => continue,
        };
    }
    anyhow::bail!("create client failed")
}
