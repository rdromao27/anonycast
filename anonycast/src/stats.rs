use std::io::Write;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    ops::DerefMut,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

static STATS: OnceLock<Mutex<Stats>> = OnceLock::new();

#[derive(Debug, Default)]
struct Stats {
    operations: HashMap<String, Vec<Duration>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    Send,
    Retrieve,
    BuildCircuits,
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Operation::Send => "send",
            Operation::Retrieve => "retreive",
            Operation::BuildCircuits => "build-circuits",
        })
    }
}

pub fn log(operation: impl std::fmt::Display, dur: Duration) {
    get_stats()
        .operations
        .entry(operation.to_string())
        .or_default()
        .push(dur);
}

pub fn log_with<R>(operation: impl std::fmt::Display, f: impl FnOnce() -> R) -> R {
    let start = Instant::now();
    let value = f();
    let dur = start.elapsed();
    log(operation, dur);
    value
}

pub fn print() {
    let stats = get_stats();

    for (op, times) in stats.operations.iter() {
        let min = times
            .iter()
            .min()
            .copied()
            .unwrap_or_default()
            .as_secs_f64();
        let max = times
            .iter()
            .max()
            .copied()
            .unwrap_or_default()
            .as_secs_f64();
        let avg = times.iter().copied().sum::<Duration>().as_secs_f64() / times.len() as f64;

        println!("{op} {min} {avg} {max}");
    }
}

pub fn print_to_file() {
    let path = std::env::current_dir().unwrap().join("test_logs.txt");
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    let stats = get_stats();

    for (op, times) in stats.operations.iter() {
        let min = times
            .iter()
            .min()
            .copied()
            .unwrap_or_default()
            .as_secs_f64();
        let max = times
            .iter()
            .max()
            .copied()
            .unwrap_or_default()
            .as_secs_f64();
        let avg = times.iter().copied().sum::<Duration>().as_secs_f64() / times.len() as f64;

        writeln!(file, "{op}: min = {min}, avg = {avg}, max = {max}").unwrap();
    }
}

fn get_stats() -> impl DerefMut<Target = Stats> {
    STATS.get_or_init(Default::default).lock().unwrap()
}
