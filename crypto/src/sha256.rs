use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Default, Clone)]
pub struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    pub fn finalize(self) -> Sha256 {
        Sha256(From::from(self.0.finalize()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.0);
        f.write_str("sha256(")?;
        f.write_str(&hex)?;
        f.write_str(")")
    }
}

impl std::fmt::Display for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = hex::encode(self.0);
        f.write_str(&hex)
    }
}

pub fn sha256(data: &[u8]) -> Sha256 {
    let mut hasher = Sha256Hasher::default();
    hasher.update(data);
    hasher.finalize()
}
