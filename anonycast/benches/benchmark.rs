use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

pub fn bench_crypto_puzzle(c: &mut Criterion) {
    let beacon = get_beacon();

    for size in [4096] {
        let mut group = c.benchmark_group(format!("crypto_puzzle-size={size}"));
        for difficulty in [4, 8, 12, 14, 16, 20] {
            //group.throughput(criterion::Throughput::Bytes(size));
            group.bench_with_input(
                BenchmarkId::from_parameter(difficulty),
                &difficulty,
                |b, &difficulty| {
                    let data = vec![0u8; size as usize];
                    b.iter(|| anonycast::crypto_puzzle_solve(&data, &beacon, difficulty));
                },
            );
        }
    }
}

pub fn bench_beacon_verify(c: &mut Criterion) {
    c.bench_function("beacon_verify", move |b| {
        let (chain, beacon) = get_chain_and_beacon();
        b.iter(|| {
            beacon.verify(chain.scheme_id, &chain.public_key).unwrap();
        });
    });
}

pub fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("crypto_sign"));
    for size in [
        32,
        64,
        128,
        256,
        512,
        1024,
        4096,
        8196,
        16 * 1024,
        32 * 1024,
    ] {
        let (_pubk, privk) = crypto::generate();
        group.throughput(criterion::Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let data = vec![0u8; size as usize];
                crypto::sign(&privk, &data)
            });
        });
    }
}

pub fn bench_sign_ring(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_sign_ring");
    for group_size in [2, 3, 8, 16, 32, 64, 128] {
        let pub_priv_pairs = (0..group_size)
            .map(|_| crypto::ring_generate())
            .collect::<Vec<_>>();
        let priv_key = &pub_priv_pairs[0].1;
        let ring = crypto::Ring::from(
            pub_priv_pairs
                .iter()
                .map(|p| p.0.clone())
                .collect::<Vec<_>>(),
        );

        let message_size = 4096;
        group.bench_with_input(
            BenchmarkId::from_parameter(group_size),
            &(&ring, &priv_key),
            |b, (ring, priv_key)| {
                let data = vec![0u8; message_size as usize];
                b.iter(|| crypto::ring_sign(priv_key, ring, &data));
            },
        );
    }
}

pub fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("crypto_verify"));
    for size in [
        32,
        64,
        128,
        256,
        512,
        1024,
        4096,
        8196,
        16 * 1024,
        32 * 1024,
    ] {
        let (pubk, privk) = crypto::generate();
        group.throughput(criterion::Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let data = vec![0u8; size as usize];
            let signature = crypto::sign(&privk, &data);
            b.iter(|| crypto::verify(&pubk, &data, &signature));
        });
    }
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

fn run_future<F, R>(f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    tokio::runtime::Runtime::new().unwrap().block_on(f)
}

criterion_group!(
    benches,
    bench_crypto_puzzle,
    bench_sign,
    bench_sign_ring,
    //bench_beacon_verify,
    //bench_sign,
    //bench_verify
);
criterion_main!(benches);
