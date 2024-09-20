use crypto::{PrivateKey, PublicKey, Sha256, SymmetricData, SymmetricKey};
use serde::{Deserialize, Serialize};

use crate::{crypto_puzzle_solve, crypto_puzzle_verify, protocol::Signed};

pub type SignedDocument = Signed<Document>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DocumentId {
    pub round: u64,
    pub content_hash: Sha256,
    pub public_key_hash: Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentKeyPair {
    pub public_key: PublicKey,
    // symmetric key encrypted with public key
    pub symmetric_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DocumentContent {
    Plaintext(Vec<u8>),
    Encrypted {
        data: SymmetricData,
        keys: Vec<DocumentKeyPair>,
    },
}

impl DocumentContent {
    fn data(&self) -> &[u8] {
        match self {
            DocumentContent::Plaintext(plaintext) => plaintext.as_slice(),
            DocumentContent::Encrypted { data, .. } => data.data.as_slice(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentDrand {
    pub chain: String,
    pub beacon: drand::Beacon,
    pub scheme: drand::SchemeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: DocumentId,
    pub topic: String,
    pub content: DocumentContent,
    pub crypto_difficulty: u8,
    pub nonce_solution: u32,
    pub drand: DocumentDrand,
}
impl_signable_serde!(Document);

impl Document {
    fn new(
        topic: &str,
        content: DocumentContent,
        difficulty: u8,
        public_key_hash: Sha256,
        drand: DocumentDrand,
    ) -> Self {
        let topic = topic.to_owned();
        let content_hash = crypto::sha256(content.data());
        let round = drand.beacon.round_number;
        let solution = crypto_puzzle_solve(content.data(), &drand.beacon, difficulty);

        Document {
            id: DocumentId {
                round,
                content_hash,
                public_key_hash,
            },
            topic,
            content,
            crypto_difficulty: difficulty,
            nonce_solution: solution,
            drand,
        }
    }

    pub fn plaintext(
        topic: &str,
        data: &[u8],
        difficulty: u8,
        public_key_hash: Sha256,
        drand: DocumentDrand,
    ) -> Self {
        Self::new(
            topic,
            DocumentContent::Plaintext(data.to_vec()),
            difficulty,
            public_key_hash,
            drand,
        )
    }

    pub fn encrypted(
        topic: &str,
        data: &[u8],
        difficulty: u8,
        public_key_hash: Sha256,
        receiver_keys: &[PublicKey],
        drand: DocumentDrand,
    ) -> Self {
        let skey = crypto::symmetric_generate();
        let mut pairs = Vec::new();
        for key in receiver_keys {
            let encrypted_skey = crypto::encrypt(key, skey.as_bytes());
            let pair = DocumentKeyPair {
                public_key: key.clone(),
                symmetric_key: encrypted_skey,
            };
            pairs.push(pair);
        }
        let encrypted_data = crypto::symmetric_encrypt(&skey, data);
        let content = DocumentContent::Encrypted {
            data: encrypted_data,
            keys: pairs,
        };
        Self::new(topic, content, difficulty, public_key_hash, drand)
    }

    pub fn decrypt(&mut self, key: &PrivateKey) -> bool {
        let public_key = key.public_key();
        let (data, skey) = match &self.content {
            DocumentContent::Plaintext(_) => return true,
            DocumentContent::Encrypted { data, keys } => {
                let pair = match keys.iter().find(|p| p.public_key == public_key) {
                    Some(pair) => pair,
                    None => return false,
                };
                (
                    data,
                    <SymmetricKey as TryFrom<&[u8]>>::try_from(
                        crypto::decrypt(key, &pair.symmetric_key).as_slice(),
                    )
                    .unwrap(),
                )
            }
        };
        let content = DocumentContent::Plaintext(crypto::symmetric_decrypt(&skey, data));
        self.content = content;
        true
    }

    pub fn is_valid(
        &self,
        expected_difficulty: u8,
        acceptance_window: u64,
        drand_chain: &drand::ChainInfo,
        drand_beacon: &drand::Beacon,
    ) -> bool {
        if !crypto_puzzle_verify(
            self.content.data(),
            &self.drand.beacon,
            self.crypto_difficulty,
            self.nonce_solution,
        ) {
            tracing::warn!("document contained invalid crypto solution");
            return false;
        }
        if self.crypto_difficulty != expected_difficulty {
            tracing::warn!(
                "message verify crypto difficulty missmatch: expected {} got {}",
                expected_difficulty,
                self.crypto_difficulty
            );
            return false;
        }

        if drand_beacon
            .verify(drand_chain.scheme_id, &drand_chain.public_key)
            .is_err()
        {
            tracing::error!("Failed to verify beacon");
            return false;
        }

        if acceptance_window != 0
            && self.drand.beacon.round_number + acceptance_window <= drand_beacon.round_number
        {
            tracing::error!("Failed to verify beacon round");
            return false;
        }

        true
    }
}
