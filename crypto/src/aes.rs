use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Key,
};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct InvalidSymmetricKey;

impl std::fmt::Display for InvalidSymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid symmetric key")
    }
}

impl std::error::Error for InvalidSymmetricKey {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for SymmetricKey {
    type Error = InvalidSymmetricKey;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(
            TryFrom::try_from(value).map_err(|_| InvalidSymmetricKey)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymmetricData {
    pub nonce: Vec<u8>,
    pub data: Vec<u8>,
}

pub fn symmetric_generate() -> SymmetricKey {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    SymmetricKey(key.into())
}

pub fn symmetric_encrypt(key: &SymmetricKey, data: &[u8]) -> SymmetricData {
    let key: Key<Aes256Gcm> = key.0.into();
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, data).unwrap();
    SymmetricData {
        nonce: nonce.to_vec(),
        data: ciphertext,
    }
}

pub fn symmetric_decrypt(key: &SymmetricKey, data: &SymmetricData) -> Vec<u8> {
    let key: Key<Aes256Gcm> = key.0.into();
    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher
        .decrypt(From::from(data.nonce.as_slice()), data.data.as_slice())
        .unwrap();
    plaintext
}
