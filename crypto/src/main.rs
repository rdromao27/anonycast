fn main() {
    // Collect times of signing a message with size
    // 128,1024,4096,8192,32768,65536,131072,524288,1048576
    // for all sizes create message and sign it
    let sizes = vec![128, 1024, 4096, 8192, 32768, 65536, 131072, 524288, 1048576];
    let mut times = Vec::new();
    for &size in &sizes {  // Iterate over a reference to sizes
        let message = vec![0; size];
        let (public_key, private_key) = crypto::generate();
        let start = std::time::Instant::now();
        let signature = crypto::sign(&private_key, &message);
        let end = std::time::Instant::now();
        times.push(end - start);
    }
    // Print the times
    for (size, time) in sizes.iter().zip(times.iter()) {
        println!("Size: {}, Time: {:?}", size, time);
    }
}