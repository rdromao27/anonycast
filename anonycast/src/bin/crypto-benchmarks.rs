use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use serde::Serialize;

#[derive(Default, Serialize)]
struct CryptoBench {
    message_size: usize,
    crypto_difficulty: usize,
    durations: Vec<u128>,
}

#[derive(Default, Serialize)]
struct RingBench {
    message_size: usize,
    members: usize,
    durations: Vec<u128>,
}

#[derive(Default, Serialize)]
struct BroadcastBench {
    message_size: usize,
    members: usize,
    durations: Vec<u128>,
}

#[derive(Default, Serialize)]
struct Output {
    puzzle_bench: Vec<CryptoBench>,
    ring_bench: Vec<RingBench>,
    broadcast_bench: Vec<BroadcastBench>,
}

fn run_future<F, R>(f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    tokio::runtime::Runtime::new().unwrap().block_on(f)
}

fn get_chain_and_beacon() -> (drand::ChainInfo, drand::Beacon) {
    run_future(async {
        let chains = drand::chain_list().await.unwrap();
        let chain = drand::chain_info(&chains[0]).await.unwrap();
        let beacon = drand::chain_latest_randomness(&chains[0]).await.unwrap();
        (chain, beacon)
    })
}

fn get_beacon() -> drand::Beacon {
    get_chain_and_beacon().1
}

fn create_message(size: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(size);
    for i in 0..size {
        message.push((i % 255) as u8);
    }
    return message;
}

fn main() {
    let iterations_per_combination = 128;
    let min_iterations_per_combination = 8;
    let max_time_per_combination = Duration::from_secs(5 * 60);
    let message_sizes = [
        128,
        1024,
        4 * 1024,
        8 * 1024,
        32 * 1024,
        64 * 1024,
        128 * 1024,
        512 * 1024,
        1024 * 1024,
    ];
    let crypto_puzzle_message_size_limit = 8 * 1024;
    let crypto_puzze_difficulties = [4, 8, 12, 14, 16, 20];
    let ring_members = [2, 3, 8, 16, 32, 64, 128];
    let broadcast_members = [2, 3, 8, 16, 32, 64, 128];
    let mut output = Output::default();

    let mut beacon = get_beacon();
    for message_size in message_sizes {
        let mut message = create_message(message_size);
        if message_size > crypto_puzzle_message_size_limit {
            break;
        }
        for difficulty in crypto_puzze_difficulties {
            let mut durations = Vec::with_capacity(iterations_per_combination);
            let mut total_time = Duration::default();

            for i in 0..iterations_per_combination {
                if i > min_iterations_per_combination && total_time > max_time_per_combination {
                    break;
                }
                let instant_begin = Instant::now();
                black_box(anonycast::crypto_puzzle_solve(
                    black_box(&mut message),
                    black_box(&mut beacon),
                    difficulty,
                ));
                let elapsed = instant_begin.elapsed();
                total_time += elapsed;
                durations.push(elapsed.as_nanos());
            }

            eprintln!(
                "crypto bench message_size={message_size} difficulty={difficulty} - {} s",
                total_time.as_secs_f64()
            );
            output.puzzle_bench.push(CryptoBench {
                message_size,
                crypto_difficulty: difficulty as usize,
                durations,
            });
        }
    }

    for message_size in message_sizes {
        let mut message = create_message(message_size);
        for members in ring_members {
            let key_pairs = (0..members)
                .map(|_| crypto::ring_generate())
                .collect::<Vec<_>>();
            let pub_keys = key_pairs.iter().map(|p| p.0.clone()).collect::<Vec<_>>();
            let priv_key = &key_pairs[0].1;
            let mut ring = crypto::Ring::from(pub_keys);

            let mut durations = Vec::new();
            let mut total_time = Duration::default();

            for i in 0..iterations_per_combination {
                if i > min_iterations_per_combination && total_time > max_time_per_combination {
                    break;
                }
                let instant_begin = Instant::now();
                black_box(crypto::ring_sign(
                    priv_key,
                    black_box(&mut ring),
                    black_box(&mut message),
                ));
                let elapsed = instant_begin.elapsed();
                total_time += elapsed;
                durations.push(elapsed.as_nanos());
            }

            eprintln!(
                "ring bench message_size={message_size} members={members} - {} s",
                total_time.as_secs_f64()
            );
            output.ring_bench.push(RingBench {
                message_size,
                members,
                durations,
            });
        }
    }

    for message_size in message_sizes {
        // rsa crate panics with MessageTooLong when message size is somewhere between (128, 1024]
        if message_size > 128 {
            break;
        }
        let mut message = create_message(message_size);
        for members in broadcast_members {
            let pubkeys = (0..members)
                .map(|_| crypto::generate().0)
                .collect::<Vec<_>>();

            let mut durations = Vec::new();
            let mut total_time = Duration::default();

            for i in 0..iterations_per_combination {
                let message = black_box(&mut message);
                if i > min_iterations_per_combination && total_time > max_time_per_combination {
                    break;
                }
                let instant_begin = Instant::now();
                for pubkey in &pubkeys {
                    black_box(crypto::encrypt(pubkey, message));
                }
                let elapsed = instant_begin.elapsed();
                total_time += elapsed;
                durations.push(elapsed.as_nanos());
            }

            eprintln!(
                "broadcast bench message_size={message_size} members={members} - {} s",
                total_time.as_secs_f64()
            );
            output.broadcast_bench.push(BroadcastBench {
                message_size,
                members,
                durations,
            });
        }
    }

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
