use std::{
    borrow::Cow,
    collections::HashMap,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use drand_client_rs::verify::{verify_on_g1, verify_on_g2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use drand_client_rs::verify::VerificationError;
use tokio::sync::{Mutex, MutexGuard};

pub const DEFAULT_API_URL: &'static str = "https://api.drand.sh";

const DST_G1: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const DST_G2: &str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SchemeId {
    PedersenBlsChained,
    PedersenBlsUnchained,
    UnchainedOnG1,
    UnchainedOnG1RFC9380,
}

impl From<drand_client_rs::verify::SchemeID> for SchemeId {
    fn from(value: drand_client_rs::verify::SchemeID) -> Self {
        match value {
            drand_client_rs::verify::SchemeID::PedersenBlsChained => SchemeId::PedersenBlsChained,
            drand_client_rs::verify::SchemeID::PedersenBlsUnchained => {
                SchemeId::PedersenBlsUnchained
            }
            drand_client_rs::verify::SchemeID::UnchainedOnG1 => SchemeId::UnchainedOnG1,
            drand_client_rs::verify::SchemeID::UnchainedOnG1RFC9380 => {
                SchemeId::UnchainedOnG1RFC9380
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfoMetadata {
    pub beacon_id: String,
}

impl From<drand_client_rs::chain_info::ChainInfoMetadata> for ChainInfoMetadata {
    fn from(value: drand_client_rs::chain_info::ChainInfoMetadata) -> Self {
        Self {
            beacon_id: value.beacon_id,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub scheme_id: SchemeId,
    pub public_key: Vec<u8>,
    pub chain_hash: Vec<u8>,
    pub group_hash: Vec<u8>,
    pub genesis_time: u64,
    pub period_seconds: u32,
    pub metadata: ChainInfoMetadata,
}

impl std::fmt::Debug for ChainInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainInfo")
            .field("scheme_id", &self.scheme_id)
            .field("public_key", &hex::encode(&self.public_key))
            .field("chain_hash", &hex::encode(&self.chain_hash))
            .field("group_hash", &hex::encode(&self.group_hash))
            .field("genesis_time", &self.genesis_time)
            .field("period_seconds", &self.period_seconds)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl From<drand_client_rs::chain_info::ChainInfo> for ChainInfo {
    fn from(value: drand_client_rs::chain_info::ChainInfo) -> Self {
        ChainInfo {
            scheme_id: value.scheme_id.into(),
            public_key: value.public_key,
            chain_hash: value.chain_hash,
            group_hash: value.group_hash,
            genesis_time: value.genesis_time,
            period_seconds: value.period_seconds as u32,
            metadata: value.metadata.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Beacon {
    pub round_number: u64,
    pub randomness: Vec<u8>,
    pub signature: Vec<u8>,
    pub previous_signature: Vec<u8>,
}

impl std::fmt::Debug for Beacon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Beacon")
            .field("round_number", &self.round_number)
            .field("randomness", &hex::encode(&self.randomness))
            .field("signature", &hex::encode(&self.signature))
            .field("previous_signature", &hex::encode(&self.previous_signature))
            .finish()
    }
}

impl From<drand_client_rs::verify::Beacon> for Beacon {
    fn from(value: drand_client_rs::verify::Beacon) -> Self {
        Beacon {
            round_number: value.round_number,
            randomness: value.randomness,
            signature: value.signature,
            previous_signature: value.previous_signature,
        }
    }
}

impl Beacon {
    pub fn verify(&self, scheme_id: SchemeId, public_key: &[u8]) -> Result<(), VerificationError> {
        if Into::<[u8; 32]>::into(Sha256::digest(&self.signature)) != *self.randomness {
            return Err(VerificationError::InvalidRandomness);
        }
        match scheme_id {
            SchemeId::PedersenBlsChained => {
                verify_on_g2(public_key, &self.chained_message(), &self.signature, DST_G2)
            }
            SchemeId::PedersenBlsUnchained => verify_on_g2(
                public_key,
                &self.unchained_message(),
                &self.signature,
                DST_G2,
            ),
            SchemeId::UnchainedOnG1 => verify_on_g1(
                public_key,
                &self.unchained_message(),
                &self.signature,
                DST_G2,
            ),
            SchemeId::UnchainedOnG1RFC9380 => verify_on_g1(
                public_key,
                &self.unchained_message(),
                &self.signature,
                DST_G1,
            ),
        }
    }

    fn unchained_message(&self) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(self.round_number.to_be_bytes());
        hasher.finalize().into()
    }

    fn chained_message(&self) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(&self.previous_signature);
        hasher.update(self.round_number.to_be_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug)]
pub struct ClientError(Box<dyn std::error::Error + Send + Sync>);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

impl From<reqwest::Error> for ClientError {
    fn from(value: reqwest::Error) -> Self {
        Self(Box::new(value))
    }
}

#[derive(Debug, Clone)]
pub struct BasicClient {
    base_url: Cow<'static, str>,
    client: reqwest::Client,
}

impl BasicClient {
    pub fn new(base_url: impl Into<Cow<'static, str>>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn chain_list(&self) -> Result<Vec<String>, ClientError> {
        let url = format!("{}/chains", self.base_url);
        let response = self.client.get(&url).send().await?;
        let chains: Vec<String> = response.json().await?;
        Ok(chains)
    }

    pub async fn chain_info(&self, chain: &str) -> Result<ChainInfo, ClientError> {
        let url = format!("{}/{}/info", self.base_url, chain);
        let response = self.client.get(&url).send().await?;
        let chain_info: drand_client_rs::chain_info::ChainInfo = response.json().await?;
        Ok(chain_info.into())
    }

    pub async fn chain_randomness(&self, chain: &str, round: u64) -> Result<Beacon, ClientError> {
        let url = format!("{}/{}/public/{}", self.base_url, chain, round);
        let response = self.client.get(&url).send().await?;
        let beacon: drand_client_rs::verify::Beacon = response.json().await?;
        Ok(beacon.into())
    }

    pub async fn chain_latest_randomness(&self, chain: &str) -> Result<Beacon, ClientError> {
        tracing::debug!("fetching latest randomness for chain {chain}");
        let url = format!("{}/{}/public/latest", self.base_url, chain);
        let response = self.client.get(&url).send().await?;
        tracing::debug!("response code {}", response.status());
        let beacon: drand_client_rs::verify::Beacon = response.json().await?;
        Ok(beacon.into())
    }
}

#[derive(Debug, Clone)]
struct CacheBeaconEntry {
    timestamp: Instant,
    beacon: Beacon,
    ttl: u64,
}

#[derive(Debug, Clone)]
struct CachedInfoEntry {
    info: ChainInfo,
}

#[derive(Debug, Default)]
struct Cache {
    beacon: HashMap<String, CacheBeaconEntry>,
    info: HashMap<String, CachedInfoEntry>,
}

#[derive(Debug, Clone)]
pub struct CachingClient {
    client: BasicClient,
    cache: Arc<Mutex<Cache>>,
}

impl CachingClient {
    pub fn new(base_url: impl Into<Cow<'static, str>>) -> Self {
        Self {
            client: BasicClient::new(base_url),
            cache: Default::default(),
        }
    }

    pub async fn chain_list(&self) -> Result<Vec<String>, ClientError> {
        self.client.chain_list().await
    }

    pub async fn chain_info(&self, chain: &str) -> Result<ChainInfo, ClientError> {
        let mut cache = self.cache.lock().await;
        self.chain_info_lk(chain, &mut cache).await
    }

    pub async fn chain_randomness(&self, chain: &str, round: u64) -> Result<Beacon, ClientError> {
        self.client.chain_randomness(chain, round).await
    }

    pub async fn chain_latest_randomness(&self, chain: &str) -> Result<Beacon, ClientError> {
        let mut cache = self.cache.lock().await;
        if let Some(entry) = cache.beacon.get(chain) {
            if entry.timestamp.elapsed().as_secs() > entry.ttl {
                cache.beacon.remove(chain);
            } else {
                return Ok(entry.beacon.clone());
            }
        }

        let info = self.chain_info_lk(chain, &mut cache).await?;
        let beacon = self.client.chain_latest_randomness(chain).await?;
        let unix_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ttl = (unix_now - info.genesis_time) % info.period_seconds as u64;
        cache.beacon.insert(
            chain.to_string(),
            CacheBeaconEntry {
                timestamp: Instant::now(),
                beacon: beacon.clone(),
                ttl,
            },
        );
        Ok(beacon)
    }

    async fn chain_info_lk(
        &self,
        chain: &str,
        cache: &mut MutexGuard<'_, Cache>,
    ) -> Result<ChainInfo, ClientError> {
        if let Some(entry) = cache.info.get(chain) {
            return Ok(entry.info.clone());
        }

        let info = self.client.chain_info(chain).await?;
        let entry = CachedInfoEntry { info: info.clone() };
        cache.info.insert(chain.to_string(), entry);
        Ok(info)
    }
}

pub async fn chain_list() -> Result<Vec<String>, ClientError> {
    BasicClient::new(DEFAULT_API_URL).chain_list().await
}

pub async fn chain_info(chain: &str) -> Result<ChainInfo, ClientError> {
    BasicClient::new(DEFAULT_API_URL).chain_info(chain).await
}

pub async fn chain_randomness(chain: &str, round: u64) -> Result<Beacon, ClientError> {
    BasicClient::new(DEFAULT_API_URL)
        .chain_randomness(chain, round)
        .await
}

pub async fn chain_latest_randomness(chain: &str) -> Result<Beacon, ClientError> {
    BasicClient::new(DEFAULT_API_URL)
        .chain_latest_randomness(chain)
        .await
}

pub async fn get_beacon_from_first_chain() -> Result<Beacon, ClientError> {
    let client = BasicClient::new(DEFAULT_API_URL);
    let mut chains = client.chain_list().await?;
    chains.sort();
    let chain = chains
        .first()
        .ok_or_else(|| ClientError("no chain".into()))?;
    client.chain_latest_randomness(chain).await
}
