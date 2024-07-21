use anyhow::Result;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    cli::main().await
}
