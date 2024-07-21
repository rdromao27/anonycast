use crypto::Sha256Hasher;
use drand::Beacon;

#[macro_use]
pub mod protocol;

pub mod asset_owner;
pub mod client;
pub mod deaddrop;
mod deaddrop_conn;
mod document;
mod rle;
pub mod stats;

pub(crate) use deaddrop_conn::DeaddropConn;
pub use deaddrop_conn::{DeaddropAddr, InvalidDeaddropAddr};

#[derive(Debug)]
pub struct InvalidModeOfOperation;

impl std::fmt::Display for InvalidModeOfOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid mode of operation")
    }
}

impl std::error::Error for InvalidModeOfOperation {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeOfOperation {
    Open,
    SenderRestricted,
    ReceiverRestricted,
    FullyRestricted,
}

impl std::fmt::Display for ModeOfOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ModeOfOperation::Open => "open",
            ModeOfOperation::SenderRestricted => "sender-restricted",
            ModeOfOperation::ReceiverRestricted => "receiver-restricted",
            ModeOfOperation::FullyRestricted => "fully-restricted",
        })
    }
}

impl std::str::FromStr for ModeOfOperation {
    type Err = InvalidModeOfOperation;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(Self::Open),
            "sender-restricted" => Ok(Self::SenderRestricted),
            "receiver-restricted" => Ok(Self::ReceiverRestricted),
            "fully-restricted" => Ok(Self::FullyRestricted),
            _ => Err(InvalidModeOfOperation),
        }
    }
}

#[doc(hidden)]
pub fn crypto_puzzle_solve(data: &[u8], beacon: &Beacon, difficulty: u8) -> u32 {
    let mut nonce: u32 = 0;

    loop {
        let mut hasher = Sha256Hasher::default();
        hasher.update(data);
        hasher.update(&beacon.signature);
        hasher.update(&nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut counter = difficulty;
        for byte in result.as_bytes() {
            if counter == 0 {
                return nonce;
            }
            let to_verify = 8.min(counter);
            counter -= to_verify;
            let compare = 0b11111111 >> (8 - to_verify);
            if byte & compare != 0 {
                break;
            }
        }
        nonce += 1;
    }
}

#[doc(hidden)]
pub fn crypto_puzzle_verify(data: &[u8], beacon: &Beacon, difficulty: u8, solution: u32) -> bool {
    let mut hasher = Sha256Hasher::default();
    hasher.update(data);
    hasher.update(&beacon.signature);
    hasher.update(&solution.to_le_bytes());
    let result = hasher.finalize();
    let mut counter = difficulty;
    for byte in result.as_bytes() {
        if counter == 0 {
            return true;
        }
        let to_verify = 8.min(counter);
        counter -= to_verify;
        let compare = 0b11111111 >> (8 - to_verify);
        if byte & compare != 0 {
            return false;
        }
    }
    true
}
