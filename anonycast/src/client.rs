use std::collections::HashMap;

use crypto::{PrivateKey, PublicKey, Ring, RingPrivateKey, Sha256};
use rayon::iter::{IntoParallelIterator, ParallelIterator as _};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::{
    document::{Document, DocumentDrand, DocumentId, SignedDocument},
    protocol::{
        Message, PublishDocument, RetrieveDocumentIds, RetrieveDocuments, Signed, UpdateAllowedKeys,
    },
    DeaddropAddr, DeaddropConn, ModeOfOperation,
};

#[derive(Debug, Clone)]
pub struct Config {
    pub mode: ModeOfOperation,
    pub private_key: Option<PrivateKey>,
    pub ring_private_key: Option<RingPrivateKey>,
    pub ring: Option<Ring>,
    pub receivers_keys: Vec<PublicKey>,
    pub deaddrop_addresses: Vec<DeaddropAddr>,
    pub difficulty: u8,
    pub acceptance_window: u64,
    pub asset_owner_public_key: Option<PublicKey>,
    pub drand_chain: Option<String>,
    pub drand_client: Option<drand::CachingClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedMessage(Signed<Message>);

#[derive(Debug, Clone)]
pub struct PrepareMessageRequest {
    pub topic: String,
    pub content: String,
}

pub struct Client {
    config: Config,
    drand_client: drand::CachingClient,
    drand_chain: String,
    deaddrops: Vec<DeaddropConn>,
    sender_ring: Ring,
    receiver_keys: Vec<PublicKey>,
}

impl Client {
    pub async fn new(config: Config) -> std::io::Result<Self> {
        let mut set = JoinSet::new();
        #[allow(clippy::unnecessary_to_owned)]
        for addr in config.deaddrop_addresses.iter().cloned() {
            set.spawn(async move { DeaddropConn::connect(&addr).await });
        }

        let mut conns = Vec::new();
        while let Some(Ok(result)) = set.join_next().await {
            let conn = result?;
            conns.push(conn);
        }

        let drand_chain = match config.drand_chain {
            Some(ref chain) => chain.clone(),
            None => drand::chain_list()
                .await
                .map_err(std::io::Error::other)?
                .into_iter()
                .next()
                .ok_or_else(|| std::io::Error::other("no chains found"))?,
        };
        tracing::info!("drand chain: {drand_chain}");

        let drand_client = match config.drand_client {
            Some(ref client) => client.clone(),
            None => drand::CachingClient::new(drand::DEFAULT_API_URL),
        };
        Ok(Self {
            config,
            drand_client,
            drand_chain,
            deaddrops: conns,
            sender_ring: Default::default(),
            receiver_keys: Default::default(),
        })
    }

    pub async fn prepare_message(&self, topic: &str, data: &[u8]) -> PreparedMessage {
        let document_drand = self.create_document_drand().await;
        let msg = self.create_message(topic, data, document_drand);
        PreparedMessage(msg)
    }

    pub async fn prepare_messages(
        &self,
        requests: Vec<PrepareMessageRequest>,
    ) -> Vec<PreparedMessage> {
        let document_drand = self.create_document_drand().await;
        tokio::task::block_in_place(move || {
            requests
                .into_par_iter()
                .map(|req| {
                    self.create_message(&req.topic, req.content.as_bytes(), document_drand.clone())
                })
                .map(PreparedMessage)
                .collect::<Vec<_>>()
        })
    }

    pub async fn send_message(&mut self, topic: &str, data: &[u8]) {
        self.update_keys().await;
        let document_drand = self.create_document_drand().await;
        let msg = self.create_message(topic, data, document_drand);
        self.deaddrop_broadcast_publish(&msg).await;
    }

    pub async fn send_prepared_message(&mut self, PreparedMessage(msg): PreparedMessage) {
        self.deaddrop_broadcast_publish(&msg).await;
    }

    pub async fn fetch_messages_bench(&mut self, topic: &str) {
        let since = 0;
        let request = self.sign_message(Message::RetrieveDocumentIds(RetrieveDocumentIds {
            topic: topic.to_string(),
            since_round: since,
        }));

        let message_ids = async {
            let mut response_set = JoinSet::new();
            let mut message_ids = HashMap::<DocumentId, usize>::default();
            for (stream_idx, stream) in self.deaddrops.iter_mut().enumerate() {
                let stream = stream.clone();
                let request = request.clone();
                response_set.spawn(async move {
                    let response: Signed<Message> = stream.send_and_read(&request).await;
                    (response, stream_idx)
                });
            }
            while let Some(v) = response_set.join_next().await {
                let (response, stream_idx) = v.unwrap();
                match response.content {
                    Message::DocumentIdList(list) => {
                        message_ids.extend(list.message_ids.into_iter().map(|id| (id, stream_idx)));
                    }
                    _ => panic!("unexpected deaddrop response to message id request"),
                }
            }
            message_ids
        }
        .instrument(tracing::info_span!("fetch_messages_fetch_ids"))
        .await;

        async {
            let message_ids = message_ids.keys().cloned().collect::<Vec<_>>();
            let mut retreive_set = JoinSet::new();
            for stream_idx in 0..self.deaddrops.len() {
                let stream = self.deaddrops[stream_idx].clone();
                let request = self.sign_message(Message::RetrieveDocuments(RetrieveDocuments {
                    message_ids: message_ids.clone(),
                }));
                retreive_set.spawn(async move {
                    let response: Signed<Message> = stream.send_and_read(&request).await;
                    response
                });
            }

            while let Some(response) = retreive_set.join_next().await {
                match response.unwrap().content {
                    Message::DocumentList(_) => {}
                    _ => panic!("unexpected deaddrop response"),
                }
            }
        }
        .instrument(tracing::info_span!("fetch_messages_fetch_documents"))
        .await;
    }

    async fn fetch_messages_ext(
        &mut self,
        topic: &str,
        since: u64,
        check: bool,
    ) -> Vec<SignedDocument> {
        self.update_keys().await;

        let current_round = self
            .drand_client
            .chain_latest_randomness(&self.drand_chain)
            .await
            .unwrap()
            .round_number;
        let since = 0.max(
            current_round
                .checked_sub(self.config.acceptance_window)
                .and_then(|res1| {
                    since
                        .checked_sub(self.config.acceptance_window)
                        .map(|res2| res1.min(res2))
                })
                .unwrap_or(0),
        );
        let request = self.sign_message(Message::RetrieveDocumentIds(RetrieveDocumentIds {
            topic: topic.to_string(),
            since_round: since,
        }));

        let mut response_set = JoinSet::new();
        let mut message_ids = HashMap::<DocumentId, usize>::default();
        let mut key_updates = Vec::new();
        for (stream_idx, stream) in self.deaddrops.iter_mut().enumerate() {
            let stream = stream.clone();
            let request = request.clone();
            response_set.spawn(async move {
                let response: Signed<Message> = stream.send_and_read(&request).await;
                if check && !response.verify() {
                    panic!("invalid deaddrop response signature");
                }
                (response, stream_idx)
            });
        }
        while let Some(v) = response_set.join_next().await {
            let (response, stream_idx) = v.unwrap();
            match response.content {
                Message::DocumentIdList(list) => {
                    if let Some(key_update) = list.allowed_sender_keys {
                        key_updates.push(key_update);
                    }
                    message_ids.extend(list.message_ids.into_iter().map(|id| (id, stream_idx)));
                }
                _ => panic!("unexpected deaddrop response to message id request"),
            }
        }

        for key_update in key_updates {
            self.handle_key_update(key_update);
        }

        let mut retreive_set = JoinSet::new();
        let mut documents = Vec::new();
        for stream_idx in 0..self.deaddrops.len() {
            let mut stream_ids = Vec::new();
            for (message_id, message_id_stream_idx) in message_ids.iter() {
                if *message_id_stream_idx != stream_idx {
                    continue;
                }
                stream_ids.push(message_id.clone());
            }

            for message_id in stream_ids.iter() {
                message_ids.remove(message_id);
            }

            if stream_ids.is_empty() {
                continue;
            }

            let stream = self.deaddrops[stream_idx].clone();
            let request = self.sign_message(Message::RetrieveDocuments(RetrieveDocuments {
                message_ids: stream_ids.clone(),
            }));
            retreive_set.spawn(async move {
                let response: Signed<Message> = stream.send_and_read(&request).await;
                if check && !response.verify() {
                    panic!("invalid deaddrop signature");
                }
                (response, stream_ids)
            });
        }

        while let Some(response) = retreive_set.join_next().await {
            let (response, stream_ids) = response.unwrap();
            match response.content {
                Message::DocumentList(mut list) => {
                    if check {
                        assert_eq!(list.documents.len(), stream_ids.len());
                        assert!(list
                            .documents
                            .iter()
                            .all(|m| stream_ids.contains(&m.content.id)));

                        for signed_document in list.documents.iter_mut() {
                            let document = &signed_document.content;
                            let chain = self
                                .drand_client
                                .chain_info(&document.drand.chain)
                                .await
                                .unwrap();
                            let beacon = self
                                .drand_client
                                .chain_latest_randomness(&document.drand.chain)
                                .await
                                .unwrap();
                            let valid = signed_document.content.is_valid(
                                self.config.difficulty,
                                self.config.acceptance_window,
                                &chain,
                                &beacon,
                            );

                            let verified = match self.config.mode {
                                ModeOfOperation::Open => signed_document.verify(),
                                ModeOfOperation::SenderRestricted => {
                                    signed_document.ring_verify(self.config.ring.as_ref().unwrap())
                                }
                                ModeOfOperation::ReceiverRestricted => {
                                    signed_document.verify()
                                        && signed_document
                                            .content
                                            .decrypt(self.config.private_key.as_ref().unwrap())
                                }
                                ModeOfOperation::FullyRestricted => {
                                    signed_document.ring_verify(self.config.ring.as_ref().unwrap())
                                        && signed_document
                                            .content
                                            .decrypt(self.config.private_key.as_ref().unwrap())
                                }
                            };

                            if !verified || !valid {
                                tracing::warn!(
                                "received invalid document. verified = {verified} valid = {valid}"
                            );
                            }
                        }
                    }
                    documents.extend(list.documents);
                }
                _ => panic!("unexpected deaddrop response"),
            }
        }

        documents
    }

    pub async fn fetch_messages(&mut self, topic: &str, since: u64) -> Vec<SignedDocument> {
        self.fetch_messages_ext(topic, since, true).await
    }

    pub async fn fetch_messages_unverified(
        &mut self,
        topic: &str,
        since: u64,
    ) -> Vec<SignedDocument> {
        self.fetch_messages_ext(topic, since, false).await
    }

    pub async fn update_keys(&mut self) {
        tracing::info!("updating keys...");
        if std::matches!(self.config.mode, ModeOfOperation::Open) {
            tracing::info!("skipping key update, using open mop");
            return;
        }

        let request = self.sign_message(Message::RetrieveKeys);
        let stream = &mut self.deaddrops[0];
        let response: Signed<UpdateAllowedKeys> = stream.send_and_read(&request).await;
        self.handle_key_update(response);
        tracing::info!("keys updated");
    }

    fn handle_key_update(&mut self, update: Signed<UpdateAllowedKeys>) {
        if !update.verify_with(self.config.asset_owner_public_key.as_ref().unwrap()) {
            panic!("deaddrop sent key update with invalid asset owner signature");
        }
        self.sender_ring = Ring::from(update.content.allowed_sender_keys);
        self.receiver_keys = update.content.allowed_receiver_keys;
    }

    fn create_message(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Signed<Message> {
        match self.config.mode {
            ModeOfOperation::Open => self.create_message_open(topic, data, document_drand),
            ModeOfOperation::SenderRestricted => {
                self.create_message_sender_restricted(topic, data, document_drand)
            }
            ModeOfOperation::ReceiverRestricted => {
                self.create_message_receiver_restricted(topic, data, document_drand)
            }
            ModeOfOperation::FullyRestricted => {
                self.create_message_restricted(topic, data, document_drand)
            }
        }
    }

    fn create_message_open(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Signed<Message> {
        let document = self.create_signed_document(self.create_document_plaintext(
            topic,
            data,
            document_drand,
        ));
        self.sign_message(Message::PublishDocument(PublishDocument { document }))
    }

    fn create_message_sender_restricted(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Signed<Message> {
        let document = self.create_signed_document(self.create_document_plaintext(
            topic,
            data,
            document_drand,
        ));
        self.sign_message(Message::PublishDocument(PublishDocument { document }))
    }

    fn create_message_receiver_restricted(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Signed<Message> {
        let document = self.create_signed_document(self.create_document_encrypted(
            topic,
            data,
            document_drand,
        ));
        self.sign_message(Message::PublishDocument(PublishDocument { document }))
    }

    fn create_message_restricted(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Signed<Message> {
        let document = self.create_signed_document(self.create_document_encrypted(
            topic,
            data,
            document_drand,
        ));
        self.sign_message(Message::PublishDocument(PublishDocument { document }))
    }

    async fn deaddrop_broadcast_publish(&mut self, message: &Signed<Message>) {
        tracing::info!("broadingcasting message to deaddrops");

        let mut handles = Vec::with_capacity(self.deaddrops.len());
        for (i, stream) in &mut self.deaddrops.iter_mut().enumerate() {
            let stream = stream.clone();
            let message = message.clone();
            let handle = tokio::spawn(async move {
                tracing::debug!("sending message to stream {i}");
                let response = stream.send_and_read::<Signed<Message>, _>(&message).await;
                match response.content {
                    Message::Success => {}
                    _ => panic!("expected success when publishing message"),
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        tracing::info!("broadcasting message to deaddrops complete");
    }

    fn create_document_plaintext(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Document {
        Document::plaintext(
            topic,
            data,
            self.config.difficulty,
            self.public_key_hash(),
            document_drand,
        )
    }

    fn create_document_encrypted(
        &self,
        topic: &str,
        data: &[u8],
        document_drand: DocumentDrand,
    ) -> Document {
        Document::encrypted(
            topic,
            data,
            self.config.difficulty,
            self.public_key_hash(),
            &self.receiver_keys,
            document_drand,
        )
    }

    async fn create_document_drand(&self) -> DocumentDrand {
        let chain = self.drand_chain.clone();
        let info = self.drand_client.chain_info(&chain).await.unwrap();
        let beacon = self
            .drand_client
            .chain_latest_randomness(&chain)
            .await
            .unwrap();
        DocumentDrand {
            chain,
            beacon,
            scheme: info.scheme_id,
        }
    }

    fn create_signed_document(&self, document: Document) -> SignedDocument {
        match self.config.mode {
            ModeOfOperation::Open | ModeOfOperation::ReceiverRestricted => {
                Signed::sign(self.config.private_key.as_ref().unwrap(), document)
            }
            ModeOfOperation::SenderRestricted | ModeOfOperation::FullyRestricted => {
                Signed::ring_sign(
                    self.config.ring_private_key.as_ref().unwrap(),
                    &self.sender_ring,
                    document,
                )
            }
        }
    }

    fn public_key_hash(&self) -> Sha256 {
        match self.config.mode {
            ModeOfOperation::Open | ModeOfOperation::ReceiverRestricted => crypto::sha256(
                &self
                    .config
                    .private_key
                    .as_ref()
                    .unwrap()
                    .public_key()
                    .to_bytes(),
            ),
            ModeOfOperation::SenderRestricted | ModeOfOperation::FullyRestricted => {
                crypto::sha256(self.config.ring_private_key.as_ref().unwrap().as_bytes())
            }
        }
    }

    fn sign_message(&self, message: Message) -> Signed<Message> {
        tokio::task::block_in_place(|| match self.config.mode {
            ModeOfOperation::Open | ModeOfOperation::ReceiverRestricted => {
                let key = self.config.private_key.as_ref().unwrap();
                Signed::sign(key, message)
            }
            ModeOfOperation::SenderRestricted | ModeOfOperation::FullyRestricted => {
                let key = self.config.ring_private_key.as_ref().unwrap();
                let ring = self.config.ring.as_ref().unwrap();
                Signed::ring_sign(key, ring, message)
            }
        })
    }
}
