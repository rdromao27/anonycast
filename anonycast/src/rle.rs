use std::io::{Read, Write};

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

// run length encoding
pub fn write<W: Write>(mut stream: W, data: &[u8]) -> std::io::Result<()> {
    let size = u32::to_be_bytes(data.len().try_into().unwrap());
    stream.write_all(&size)?;
    stream.write_all(data)?;
    stream.flush()?;
    tracing::debug!("wrote {} bytes", data.len());
    Ok(())
}

pub async fn async_write<W: AsyncWrite + Unpin>(mut stream: W, data: &[u8]) -> std::io::Result<()> {
    let size = u32::to_be_bytes(data.len().try_into().unwrap());
    stream.write_all(&size).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    tracing::debug!("wrote {} bytes", data.len());
    Ok(())
}

pub fn read<R: Read>(mut stream: R) -> std::io::Result<Vec<u8>> {
    let mut size = [0u8; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size);
    let mut data = vec![0u8; size as usize];
    stream.read_exact(&mut data)?;
    tracing::debug!("read {size} bytes");
    Ok(data)
}

pub async fn async_read<R: AsyncRead + Unpin>(mut stream: R) -> std::io::Result<Vec<u8>> {
    let mut size = [0u8; 4];
    stream.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size);
    let mut data = vec![0u8; size as usize];
    stream.read_exact(&mut data).await?;
    tracing::debug!("read {size} bytes");
    Ok(data)
}

pub fn serialize_and_write<T: Serialize, W: Write>(stream: W, data: &T) -> std::io::Result<()> {
    let serialized = bincode::serialize(data).unwrap();
    write(stream, &serialized)
}

#[tracing::instrument(skip_all)]
pub async fn async_serialize_and_write<T: Serialize, W: AsyncWrite + Unpin>(
    stream: W,
    data: &T,
) -> std::io::Result<()> {
    let serialized = bincode::serialize(data).unwrap();
    async_write(stream, &serialized).await
}

pub fn deserialize_and_read<T: DeserializeOwned, R: Read>(stream: R) -> std::io::Result<T> {
    let data = read(stream)?;
    Ok(bincode::deserialize::<T>(&data).unwrap())
}

#[tracing::instrument(skip_all)]
pub async fn async_deserialize_and_read<T: DeserializeOwned, R: AsyncRead + Unpin>(
    stream: R,
) -> std::io::Result<T> {
    let data = async_read(stream).await?;
    Ok(bincode::deserialize::<T>(&data).unwrap())
}
