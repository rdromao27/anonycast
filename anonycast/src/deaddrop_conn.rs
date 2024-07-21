use std::{net::SocketAddr, sync::Arc};

use serde::{de::DeserializeOwned, Serialize};
use tokio::{io::BufStream, net::TcpStream, sync::Mutex, time::Instant};
use tor_stream::TorStream;

use crate::rle;

#[derive(Debug)]
pub struct InvalidDeaddropAddr;

impl std::fmt::Display for InvalidDeaddropAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid deaddrop addr")
    }
}

impl std::error::Error for InvalidDeaddropAddr {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeaddropAddr {
    Tor { onion: String, proxy: SocketAddr },
    Tcp(SocketAddr),
}

#[derive(Debug, Clone)]
struct Inner(Arc<Mutex<BufStream<TcpStream>>>);

#[derive(Debug, Clone)]
pub struct DeaddropConn(Inner);

impl DeaddropConn {
    pub fn new(stream: TcpStream) -> Self {
        Self(Inner(Arc::new(Mutex::new(BufStream::new(stream)))))
    }

    pub async fn connect(addr: &DeaddropAddr) -> std::io::Result<Self> {
        match addr {
            DeaddropAddr::Tor { onion, proxy } => Self::connect_tor(onion, *proxy).await,
            DeaddropAddr::Tcp(addr) => Self::connect_tcp(*addr).await,
        }
    }

    pub async fn connect_tcp(addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self::new(stream))
    }

    pub async fn connect_tor(onion: &str, proxy: SocketAddr) -> std::io::Result<Self> {
        let (onion_addr, onion_port) = match onion.split_once(":") {
            Some((addr, port)) => (addr, port.parse::<u16>().unwrap()),
            None => (onion, 80),
        };

        let onion_addr = onion_addr.to_string();
        let tor_stream = tokio::task::spawn_blocking(move || {
            TorStream::connect_with_address(
                proxy,
                tor_stream::socks::TargetAddr::Domain(onion_addr, onion_port),
            )
        })
        .await
        .unwrap()?;
        let tcp_stream = tor_stream.into_inner();
        tcp_stream.set_nonblocking(true)?;
        Ok(Self::new(TcpStream::from_std(tcp_stream)?))
    }

    pub async fn send<T>(&self, message: &T)
    where
        T: Serialize,
    {
        let mut stream = self.0 .0.lock().await;
        rle::async_serialize_and_write(&mut *stream, message)
            .await
            .unwrap()
    }

    pub async fn read<R>(&self) -> R
    where
        R: DeserializeOwned,
    {
        let mut stream = self.0 .0.lock().await;
        rle::async_deserialize_and_read(&mut *stream).await.unwrap()
    }

    #[tracing::instrument(skip_all)]
    pub async fn send_and_read<R, T>(&self, message: &T) -> R
    where
        R: DeserializeOwned,
        T: Serialize,
    {
        let mut stream = self.0 .0.lock().await;
        rle::async_serialize_and_write(&mut *stream, message)
            .await
            .unwrap();
        let r = rle::async_deserialize_and_read(&mut *stream).await.unwrap();
        r
    }
}
