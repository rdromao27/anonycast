use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::sha256;

#[derive(Debug)]
pub struct InvalidPrivateKey;

impl std::fmt::Display for InvalidPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid private key")
    }
}

impl std::error::Error for InvalidPrivateKey {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey(RsaPrivateKey);

impl PrivateKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap()
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(RsaPublicKey::from(&self.0))
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.to_bytes());
        f.write_str(&hex)
    }
}

impl std::str::FromStr for PrivateKey {
    type Err = InvalidPrivateKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = hex::decode(s).unwrap();
        Ok(Self(bincode::deserialize(&hex).unwrap()))
    }
}

#[derive(Debug)]
pub struct InvalidPublicKey;

impl std::fmt::Display for InvalidPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid public key")
    }
}

impl std::error::Error for InvalidPublicKey {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(RsaPublicKey);

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0).unwrap()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.to_bytes());
        f.write_str(&hex)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = InvalidPublicKey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = hex::decode(s).map_err(|_| InvalidPublicKey)?;
        Ok(Self(
            bincode::deserialize(&hex).map_err(|_| InvalidPublicKey)?,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.0.as_slice());
        f.debug_tuple("Signature").field(&hex).finish()
    }
}

impl std::cmp::PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl std::cmp::Eq for Signature {}

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub fn generate() -> (PublicKey, PrivateKey) {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let priv_key = PrivateKey(priv_key);
    let pub_key = priv_key.public_key();
    (pub_key, priv_key)
}

pub fn sign(key: &PrivateKey, data: &[u8]) -> Signature {
    let mut rng = rand::thread_rng();
    let hash = sha256(data);
    let sig = key
        .0
        .sign_with_rng(&mut rng, Pkcs1v15Sign::new_unprefixed(), hash.as_bytes())
        .unwrap();
    Signature(sig)
}

pub fn verify(key: &PublicKey, data: &[u8], sig: &Signature) -> bool {
    let hash = sha256(data);
    key.0
        .verify(Pkcs1v15Sign::new_unprefixed(), hash.as_bytes(), &sig.0)
        .is_ok()
}

pub fn encrypt(key: &PublicKey, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    key.0.encrypt(&mut rng, Pkcs1v15Encrypt, data).unwrap()
}
pub fn decrypt(key: &PrivateKey, data: &[u8]) -> Vec<u8> {
    key.0.decrypt(Pkcs1v15Encrypt, data).unwrap()
}
