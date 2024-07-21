use crypto::{PrivateKey, PublicKey, Ring, RingPrivateKey, RingPublicKey};
use serde::{Deserialize, Serialize};

use crate::document::{DocumentId, SignedDocument};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    Asymmetric {
        key: PublicKey,
        signature: crypto::Signature,
    },
    RingAsymmetric {
        signature: crypto::RingSignature,
    },
}

pub trait Signable {
    fn serialize_for_signature(&self) -> Vec<u8>;
}

macro_rules! impl_signable_serde {
    ($t:ty) => {
        impl $crate::protocol::Signable for $t {
            fn serialize_for_signature(&self) -> Vec<u8> {
                bincode::serialize(self).unwrap()
            }
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T> {
    pub content: T,
    pub signature: Signature,
}

impl<T: Signable> Signed<T> {
    pub fn new(content: T, signature: Signature) -> Self {
        Self { content, signature }
    }

    pub fn sign(key: &PrivateKey, content: T) -> Self {
        let serialized = content.serialize_for_signature();
        let signature = crypto::sign(key, &serialized);
        Self {
            content,
            signature: Signature::Asymmetric {
                key: key.public_key(),
                signature,
            },
        }
    }

    pub fn ring_sign(key: &RingPrivateKey, ring: &Ring, content: T) -> Self {
        let serialized = content.serialize_for_signature();
        let signature = crypto::ring_sign(key, ring, &serialized);
        Self {
            content,
            signature: Signature::RingAsymmetric { signature },
        }
    }

    pub fn is_asymmetric(&self) -> bool {
        std::matches!(self.signature, Signature::Asymmetric { .. })
    }

    pub fn is_ring_asymmetric(&self) -> bool {
        std::matches!(self.signature, Signature::RingAsymmetric { .. })
    }

    pub fn verify(&self) -> bool {
        let (signature_key, signature) = match self.signature {
            Signature::Asymmetric {
                ref key,
                ref signature,
            } => (key, signature),
            _ => return false,
        };
        let serialized = self.content.serialize_for_signature();
        crypto::verify(signature_key, &serialized, signature)
    }

    pub fn verify_with(&self, key: &PublicKey) -> bool {
        let (signature_key, signature) = match self.signature {
            Signature::Asymmetric {
                ref key,
                ref signature,
            } => (key, signature),
            _ => return false,
        };
        if key != signature_key {
            return false;
        }
        let serialized = self.content.serialize_for_signature();
        crypto::verify(key, &serialized, signature)
    }

    pub fn ring_verify(&self, ring: &Ring) -> bool {
        let signature = match self.signature {
            Signature::RingAsymmetric { ref signature } => signature,
            _ => return false,
        };
        let serialized = self.content.serialize_for_signature();
        crypto::ring_verify(ring, &serialized, signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Success,
    RetrieveDocumentIds(RetrieveDocumentIds),
    RetrieveDocuments(RetrieveDocuments),
    PublishDocument(PublishDocument),
    DocumentIdList(DocumentIdList),
    DocumentList(DocumentList),
    UpdateAllowedKeys(UpdateAllowedKeys),
    RetrieveKeys,
}

impl Signable for Message {
    fn serialize_for_signature(&self) -> Vec<u8> {
        match self {
            Message::Success => Default::default(), // TODO: replays?
            Message::RetrieveDocumentIds(v) => v.serialize_for_signature(),
            Message::RetrieveDocuments(v) => v.serialize_for_signature(),
            Message::PublishDocument(v) => v.serialize_for_signature(),
            Message::DocumentIdList(v) => v.serialize_for_signature(),
            Message::DocumentList(v) => v.serialize_for_signature(),
            Message::UpdateAllowedKeys(v) => v.serialize_for_signature(),
            Message::RetrieveKeys => Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveDocumentIds {
    pub topic: String,
    pub since_round: u64,
}
impl_signable_serde!(RetrieveDocumentIds);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveDocuments {
    pub message_ids: Vec<DocumentId>,
}
impl_signable_serde!(RetrieveDocuments);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishDocument {
    pub document: SignedDocument,
}
impl_signable_serde!(PublishDocument);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentIdList {
    pub message_ids: Vec<DocumentId>,
    pub allowed_sender_keys: Option<Signed<UpdateAllowedKeys>>,
}
impl_signable_serde!(DocumentIdList);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentList {
    pub documents: Vec<SignedDocument>,
}
impl_signable_serde!(DocumentList);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAllowedKeys {
    pub allowed_sender_keys: Vec<RingPublicKey>,
    pub allowed_receiver_keys: Vec<PublicKey>,
    pub beacon: drand::Beacon,
}
impl_signable_serde!(UpdateAllowedKeys);
