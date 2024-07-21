use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use crossbeam::channel::{Receiver, Sender};
use crypto::{PrivateKey, PublicKey, Ring};
use tokio::{
    io::BufStream,
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use crate::{
    document::{Document, DocumentId, SignedDocument},
    protocol::{
        DocumentIdList, DocumentList, Message, PublishDocument, RetrieveDocumentIds,
        RetrieveDocuments, Signed, UpdateAllowedKeys,
    },
    rle, ModeOfOperation,
};

type ClientStream = BufStream<TcpStream>;

#[derive(Debug)]
pub struct Config {
    pub mode: ModeOfOperation,
    pub private_key: PrivateKey,
    pub address: SocketAddr,
    pub difficulty: u8,
    pub acceptance_window: u64,
    pub asset_owner_key: Option<PublicKey>,
    pub asset_owner_update: Option<Signed<UpdateAllowedKeys>>,
}

type SharedState = Arc<State>;

struct State {
    mode: ModeOfOperation,
    private_key: PrivateKey,
    asset_owner_key: Option<PublicKey>,
    difficulty: u8,
    acceptance_window: u64,
    drand_client: drand::CachingClient,
    state_mut: RwLock<StateMut>,
    success_response: Signed<Message>,
}

struct StateMut {
    published_documents: HashMap<DocumentId, SignedDocument>,
    allowed_sender_ring: Ring,
    allowed_receiver_keys: Vec<PublicKey>,
    keys_update_asset_owner: Option<Signed<UpdateAllowedKeys>>,
}

enum WorkerJob {
    Sign {
        message: Message,
        resp: oneshot::Sender<Signed<Message>>,
    },
    PublishDocument {
        request: PublishDocument,
        document_chain: drand::ChainInfo,
        document_beacon: drand::Beacon,
        resp: oneshot::Sender<bool>,
    },
    RetrieveDocuments {
        request: RetrieveDocuments,
        resp: oneshot::Sender<Vec<Signed<Document>>>,
    },
    RetrieveDocumentIds {
        request: RetrieveDocumentIds,
        resp: oneshot::Sender<(Vec<DocumentId>, Option<Signed<UpdateAllowedKeys>>)>,
    },
    VerifySignature {
        signed_message: Signed<Message>,
        resp: oneshot::Sender<bool>,
    },
}

#[derive(Debug, Clone)]
struct Workers {
    sender: Sender<WorkerJob>,
}

impl Workers {
    pub fn new(state: SharedState, workers: usize) -> Self {
        assert!(workers >= 1);
        let (sender, receiver) = crossbeam::channel::unbounded();
        for _ in 0..workers {
            std::thread::Builder::new()
                .name("deaddrop-worker".to_string())
                .spawn({
                    let state = state.clone();
                    let receiver = receiver.clone();
                    || Self::worker_entrypoint(state, receiver)
                })
                .expect("thread should spawn");
        }
        Self { sender }
    }

    #[tracing::instrument(skip_all)]
    pub async fn sign(&self, message: Message) -> Signed<Message> {
        let (sender, receiver) = oneshot::channel();
        self.send_job(WorkerJob::Sign {
            message,
            resp: sender,
        });
        receiver.await.unwrap()
    }

    pub async fn publish_document(
        &self,
        request: PublishDocument,
        document_chain: drand::ChainInfo,
        document_beacon: drand::Beacon,
    ) -> bool {
        let (sender, receiver) = oneshot::channel();
        self.send_job(WorkerJob::PublishDocument {
            request,
            document_chain,
            document_beacon,
            resp: sender,
        });
        receiver.await.unwrap()
    }

    #[tracing::instrument(skip_all)]
    pub async fn retreive_documents(&self, request: RetrieveDocuments) -> Vec<Signed<Document>> {
        let (sender, receiver) = oneshot::channel();
        self.send_job(WorkerJob::RetrieveDocuments {
            request,
            resp: sender,
        });
        receiver.await.unwrap()
    }

    pub async fn retreive_document_ids(
        &self,
        request: RetrieveDocumentIds,
    ) -> (Vec<DocumentId>, Option<Signed<UpdateAllowedKeys>>) {
        let (sender, receiver) = oneshot::channel();
        self.send_job(WorkerJob::RetrieveDocumentIds {
            request,
            resp: sender,
        });
        receiver.await.unwrap()
    }

    pub async fn verify_signature(&self, signed_message: Signed<Message>) -> bool {
        let (sender, receiver) = oneshot::channel();
        self.send_job(WorkerJob::VerifySignature {
            signed_message,
            resp: sender,
        });
        receiver.await.unwrap()
    }

    fn send_job(&self, job: WorkerJob) {
        self.sender
            .send(job)
            .expect("workers should always be alive while the Sender is alive");
    }

    fn worker_entrypoint(state: SharedState, receiver: Receiver<WorkerJob>) {
        while let Ok(job) = receiver.recv() {
            match job {
                WorkerJob::Sign { message, resp } => {
                    let _ = resp.send(sign(&state, message));
                }
                WorkerJob::PublishDocument {
                    request,
                    document_chain,
                    document_beacon,
                    resp,
                } => {
                    let _ = resp.send(publish_document(
                        &state,
                        request,
                        document_chain,
                        document_beacon,
                    ));
                }
                WorkerJob::RetrieveDocuments { request, resp } => {
                    let _ = resp.send(retreive_documents(&state, request));
                }
                WorkerJob::RetrieveDocumentIds { request, resp } => {
                    let _ = resp.send(retreive_document_ids(&state, request));
                }
                WorkerJob::VerifySignature {
                    signed_message,
                    resp,
                } => {
                    let _ = resp.send(verify_signature(&state, signed_message));
                }
            }
        }
    }
}

pub async fn run(config: Config) -> std::io::Result<()> {
    let success_response = Signed::sign(&config.private_key, Message::Success);
    let state = Arc::new(State {
        mode: config.mode,
        private_key: config.private_key,
        asset_owner_key: config.asset_owner_key.clone(),
        difficulty: config.difficulty,
        acceptance_window: config.acceptance_window,
        drand_client: drand::CachingClient::new(drand::DEFAULT_API_URL),
        success_response,
        state_mut: RwLock::new(StateMut {
            published_documents: Default::default(),
            allowed_sender_ring: Default::default(),
            allowed_receiver_keys: Default::default(),
            keys_update_asset_owner: None,
        }),
    });

    let workers = Workers::new(
        state.clone(),
        usize::from(std::thread::available_parallelism().unwrap()),
    );

    if let Some(update) = config.asset_owner_update {
        handle_update_allowed_keys(&state, &workers, update).await;
    }

    let listener = TcpListener::bind(config.address).await?;
    loop {
        let (stream, _client_address) = match listener.accept().await {
            Ok((stream, client_address)) => (stream, client_address),
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let workers = workers.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(state, workers, stream).await {
                tracing::error!("failed to handle connection: {err}");
            }
        });
    }
}

async fn handle_connection(
    state: SharedState,
    workers: Workers,
    stream: TcpStream,
) -> std::io::Result<()> {
    tracing::info!("handling connection");

    let mut stream = BufStream::new(stream);

    loop {
        let signed = match rle::async_deserialize_and_read::<Signed<Message>, _>(&mut stream).await
        {
            Ok(signed) => signed,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        };

        if !workers.verify_signature(signed.clone()).await {
            tracing::warn!(
                "signature verification failed for message {:#?}",
                signed.content
            );
            continue;
        }

        match signed.content {
            Message::RetrieveDocumentIds(request) => {
                handle_retrieve_document_ids(&state, &workers, &mut stream, request).await
            }
            Message::RetrieveDocuments(request) => {
                handle_retrieve_documents(&state, &workers, &mut stream, request).await
            }
            Message::PublishDocument(request) => {
                handle_publish_documents(&state, &workers, &mut stream, request).await;
                // let response = sign(state.clone(), Message::Success);
                // rle::async_serialize_and_write(&mut stream, &response)
                //     .await
                //     .unwrap();
            }
            Message::UpdateAllowedKeys(update) => {
                handle_update_allowed_keys(&state, &workers, Signed::new(update, signed.signature))
                    .await
            }
            Message::RetrieveKeys => handle_retreive_keys(&state, &workers, &mut stream).await,
            _ => return Err(std::io::Error::other("invalid message type received")),
        }
    }

    tracing::info!("connection handling terminated");
    Ok(())
}

async fn handle_retreive_keys(state: &SharedState, _workers: &Workers, stream: &mut ClientStream) {
    let update_message = {
        let state_mut = state.state_mut.write().unwrap();
        state_mut
            .keys_update_asset_owner
            .clone()
            .expect("asset owner hasnt sent key update")
    };
    rle::async_serialize_and_write(stream, &update_message)
        .await
        .unwrap();
}

#[tracing::instrument(skip_all)]
async fn handle_retrieve_document_ids(
    _state: &SharedState,
    workers: &Workers,
    stream: &mut ClientStream,
    request: RetrieveDocumentIds,
) {
    let (document_ids, allowed_sender_keys) = workers.retreive_document_ids(request).await;
    let message = Message::DocumentIdList(DocumentIdList {
        message_ids: document_ids,
        allowed_sender_keys,
    });
    let response = workers.sign(message).await;
    rle::async_serialize_and_write(stream, &response)
        .await
        .unwrap();
}

#[tracing::instrument(skip_all)]
async fn handle_retrieve_documents(
    _state: &SharedState,
    workers: &Workers,
    stream: &mut ClientStream,
    request: RetrieveDocuments,
) {
    let documents = workers.retreive_documents(request).await;
    let message = Message::DocumentList(DocumentList { documents });
    let response = workers.sign(message).await;
    rle::async_serialize_and_write(stream, &response)
        .await
        .unwrap();
}

async fn handle_publish_documents(
    state: &SharedState,
    workers: &Workers,
    stream: &mut ClientStream,
    request: PublishDocument,
) {
    let document = &request.document.content;
    let chain = state
        .drand_client
        .chain_info(&document.drand.chain)
        .await
        .unwrap();
    let beacon = state
        .drand_client
        .chain_latest_randomness(&document.drand.chain)
        .await
        .unwrap();
    if workers.publish_document(request, chain, beacon).await {
        rle::async_serialize_and_write(stream, &state.success_response)
            .await
            .unwrap();
    } else {
        tracing::warn!("message invalid, not publishing");
        panic!("should not be happening during testing");
    }
}

async fn handle_update_allowed_keys(
    state: &SharedState,
    _workers: &Workers,
    update: Signed<UpdateAllowedKeys>,
) {
    tracing::info!("updating allowed keys");
    let current_round = drand::get_beacon_from_first_chain()
        .await
        .unwrap()
        .round_number;
    let generated_in_round = update.content.beacon.round_number;
    if current_round - generated_in_round > state.acceptance_window {
        tracing::warn!(
            "update beacon too old, current round: {}, generated in round: {}",
            current_round,
            generated_in_round
        );
        return;
    }
    let mut state_mut = state.state_mut.write().unwrap();
    state_mut.allowed_sender_ring = Ring::from(update.clone().content.allowed_sender_keys);
    state_mut.allowed_receiver_keys = update.clone().content.allowed_receiver_keys;
    state_mut.keys_update_asset_owner = Some(update);
}

#[inline(never)]
fn verify_signature(state: &SharedState, signed_message: Signed<Message>) -> bool {
    match signed_message.content {
        Message::UpdateAllowedKeys(_) => {
            if let Some(ref asset_owner_key) = state.asset_owner_key {
                signed_message.verify_with(asset_owner_key)
            } else {
                tracing::warn!(
                    "asset owner key not configured, ignoring UpdateAllowedKeys message"
                );
                false
            }
        }
        Message::PublishDocument(_) => match state.mode {
            ModeOfOperation::Open | ModeOfOperation::ReceiverRestricted => signed_message.verify(),
            ModeOfOperation::SenderRestricted | ModeOfOperation::FullyRestricted => {
                let state_mut = state.state_mut.read().unwrap();
                let ring = &state_mut.allowed_sender_ring;
                signed_message.ring_verify(ring)
            }
        },
        Message::DocumentIdList(_) | Message::DocumentList(_) | Message::Success => {
            unreachable!("deaddrop should not received this message type")
        }
        Message::RetrieveDocumentIds(_) | Message::RetrieveDocuments(_) | Message::RetrieveKeys => {
            let state_mut = state.state_mut.read().unwrap();
            let ring = &state_mut.allowed_sender_ring;
            signed_message.verify() || signed_message.ring_verify(ring)
        }
    }
}

#[inline(never)]
#[tracing::instrument(skip_all)]
fn retreive_document_ids(
    state: &SharedState,
    request: RetrieveDocumentIds,
) -> (Vec<DocumentId>, Option<Signed<UpdateAllowedKeys>>) {
    let mut document_ids = Vec::new();
    let state_mut = state.state_mut.read().unwrap();
    for signed_document in state_mut.published_documents.values() {
        if signed_document.content.id.round >= request.since_round {
            document_ids.push(signed_document.content.id.clone());
        }
    }

    let allowed_sender_keys = match state.mode {
        ModeOfOperation::Open | ModeOfOperation::ReceiverRestricted => None,
        ModeOfOperation::FullyRestricted | ModeOfOperation::SenderRestricted => {
            state_mut.keys_update_asset_owner.clone()
        }
    };

    (document_ids, allowed_sender_keys)
}

#[inline(never)]
#[tracing::instrument(skip_all)]
fn retreive_documents(state: &SharedState, request: RetrieveDocuments) -> Vec<Signed<Document>> {
    let mut documents = Vec::new();

    let span = tracing::info_span!("acquire_state_lock");
    let _guard = span.enter();
    let state_mut = state.state_mut.read().unwrap();
    drop(_guard);

    for id in request.message_ids {
        documents.push(
            state_mut
                .published_documents
                .get(&id)
                .cloned()
                .expect("request unknown message id"),
        );
    }
    documents
}

fn publish_document(
    state: &SharedState,
    request: PublishDocument,
    document_chain: drand::ChainInfo,
    document_beacon: drand::Beacon,
) -> bool {
    if !request.document.content.is_valid(
        state.difficulty,
        state.acceptance_window,
        &document_chain,
        &document_beacon,
    ) {
        return false;
    }

    tracing::info!("storing {:#?}", request.document.content.id);
    let mut state_mut = state.state_mut.write().unwrap();
    // TODO: handle duplicates?
    state_mut
        .published_documents
        .insert(request.document.content.id.clone(), request.document);

    true
}

fn sign(state: &SharedState, message: Message) -> Signed<Message> {
    Signed::sign(&state.private_key, message)
}
