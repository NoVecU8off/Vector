use crate::validator::*;
use vec_proto::messages::*;
use vec_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use vec_chain::chain::Chain;
use vec_store::{block_store::{MemoryBlockStore, BlockStorer}, utxo_store::*};
use vec_mempool::mempool::*;
use vec_server::server::*;
use vec_transaction::transaction::hash_transaction;
use std::{collections::HashMap, sync::Arc, net::SocketAddr};
use tonic::{transport::{Server, Channel, ClientTlsConfig, ServerTlsConfig, Identity, Certificate}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use futures::future::try_join_all;
use slog::{o, Logger, info, Drain, error};
use std::time::{SystemTime, UNIX_EPOCH};
use vec_errors::errors::*;

#[derive(Clone)]
pub struct NodeService {
    pub server_config: Arc<RwLock<ServerConfig>>,
    pub peer_lock: Arc<RwLock<HashMap<String, (Arc<Mutex<NodeClient<Channel>>>, Version, bool)>>>,
    pub validator: Option<Arc<ValidatorService>>,
    pub utxo_store: Arc<Mutex<dyn UTXOStorer>>,
    pub logger: Logger,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(
        &self,
        request: Request<Version>,
    ) -> Result<Response<Version>, Status> {
        info!(self.logger, "Starting handshaking");
        let version = request.into_inner();
        let version_clone = version.clone();
        let addr = version.msg_listen_address.clone();
        info!(self.logger, "Recieved version, address: {}", addr);
        let connected_peers = self.get_addrs_list().await;
        let cfg_is_validator = {
            let server_config = self.server_config.read().await;
            server_config.cfg_is_validator
        };
        if !self.contains(&addr, &connected_peers).await {
            match make_node_client(&addr).await {
                Ok(c) => {
                    info!(self.logger, "Created node client successfully");
                    if cfg_is_validator || version_clone.msg_validator {
                        self.add_peer(c, version_clone.clone(), version_clone.msg_validator).await;
                    }
                }
                Err(e) => {
                    error!(self.logger, "Failed to create node client: {:?}", e);
                }
            }
        } else {
            info!(self.logger, "Address already connected: {}", addr);
        }
        let reply = self.get_version().await;
        info!(self.logger, "Returning version: {:?}", reply);
        Ok(Response::new(reply))
    }
    
    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
    ) -> Result<Response<Confirmed>, Status> {
        if let Some(validator) = &self.validator {
            validator.handle_transaction(request).await
        } else {
            Err(Status::unimplemented("Node is not a validator (transaction-handling process)"))
        }
    }

    async fn handle_agreement(
        &self,
        request: Request<HashAgreement>,
    ) -> Result<Response<Agreement>, Status> {
        if let Some(validator) = &self.validator {
            validator.handle_agreement(request).await
        } else {
            Err(Status::internal("Node is not a validator (agreement process)"))
        }
    }

    async fn handle_vote(
        &self,
        request: Request<Vote>,
    ) -> Result<Response<Confirmed>, Status> {
        if let Some(validator) = &self.validator {
            validator.handle_vote(request).await
        } else {
            Err(Status::internal("Node is not a validator (voting process)"))
        }
    }

    async fn push_state(
        &self,
        request: Request<LocalState>,
    ) -> Result<Response<BlockBatch>, Status> {
        if let Some(validator) = &self.validator {
            validator.push_state(request).await
        } else {
            Err(Status::internal("Node is not a validator (state request process)"))
        }
    }

    async fn handle_block(
        &self,
        request: Request<LeaderBlock>,
    ) -> Result<Response<Confirmed>, Status> {
        let leader_block = request.into_inner();
        if let Some(block) = leader_block.msg_block {
            let leader_address = leader_block.msg_leader_address;
            match self.process_incoming_leader_block(block, &leader_address).await {
                Ok(_) => {
                    info!(self.logger, "Local UTXO updated successfully");
                    if let Some(validator) = &self.validator {
                        if let Err(e) = validator.initialize_validating().await {
                            error!(self.logger, "Failed to initialize validating: {}", e);
                        }
                    }
                    Ok(Response::new(Confirmed {}))
                },
                Err(e) => {
                    error!(self.logger, "Failed to update local UTXO: {:?}", e);
                    Err(Status::internal("Failed to update local UTXO"))
                }
            }
        } else {
            Err(Status::internal("LeaderBlock missing block"))
        }
    }

    async fn handle_peer_exchange(
        &self,
        request: Request<PeerList>,
    ) -> Result<Response<Confirmed>, Status> {
        let peer_list = request.into_inner();
        let peer_addresses = peer_list.msg_peers_addresses;
        match self.bootstrap_network(peer_addresses).await {
            Ok(_) => {
                info!(self.logger, "Peer list updated successfully");
                Ok(Response::new(Confirmed {}))
            }
            Err(e) => {
                error!(self.logger, "Failed to update peer_list: {:?}", e);
                Err(Status::internal("Failed to update peer_list"))
            }
        }
    }    

    async fn handle_heartbeat(
        &self,
        _request: Request<Confirmed>,
    ) -> Result<Response<Confirmed>, Status> {
        info!(self.logger, "Received health check request");
        Ok(Response::new(Confirmed {}))
    }
}

impl NodeService {
    pub async fn new(cfg: ServerConfig) -> Result<Self, NodeServiceError> {
        let logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        info!(logger, "NodeService {} created", cfg.cfg_addr);
        let peer_lock = Arc::new(RwLock::new(HashMap::new()));
        let block_storer: Box<dyn BlockStorer> = Box::new(MemoryBlockStore::new());
        let utxo_storer: Arc<Mutex<dyn UTXOStorer>> = Arc::new(Mutex::new(MemoryUTXOStore::new()));
        let chain = Chain::new_chain(block_storer)
            .await
            .map_err(|e| NodeServiceError::ChainCreationError(format!("{:?}", e)))?;
        let server_config = Arc::new(RwLock::new(cfg.clone()));
        let node_service = NodeService {
            server_config: Arc::clone(&server_config),
            peer_lock: Arc::clone(&peer_lock),
            validator: None,
            logger: logger.clone(),
            utxo_store: utxo_storer.clone(),
        };
        let (mempool_signal, _) = tokio::sync::broadcast::channel(1);
        let (broadcast_signal, _) = tokio::sync::broadcast::channel(1);
        let (bt_loop_signal, _) = tokio::sync::broadcast::channel(1);
        let validator = if cfg.cfg_is_validator {
            let validator = ValidatorService {
                validator_id: 0,
                node_service: Arc::new(node_service),
                mempool: Arc::new(Mempool::new()),
                round_transactions: Arc::new(Mutex::new(Vec::new())),
                created_block: Arc::new(Mutex::new(None)),
                agreement_count: Arc::new(Mutex::new(HashMap::new())),
                vote_count: Arc::new(Mutex::new(HashMap::new())),
                received_responses_count: Arc::new(Mutex::new(0)),
                chain: Arc::new(RwLock::new(chain)),
                mempool_signal: Arc::new(RwLock::new(mempool_signal)),
                broadcast_signal: Arc::new(RwLock::new(broadcast_signal)),
                bt_loop_signal: Arc::new(RwLock::new(bt_loop_signal)),

            };
        Some(Arc::new(validator))
    } else {
        None
    };
        Ok(NodeService {
            server_config: server_config,
            peer_lock,
            validator,
            logger,
            utxo_store: utxo_storer,
        })
    }

    pub async fn start(&mut self, nodes_to_bootstrap: Vec<String>) -> Result<(), NodeServiceError> {
        let node_service = self.clone();
        let addr = {
                let server_config = self.server_config.read().await;
                server_config.cfg_addr.to_string()
            }
            .parse()
            .map_err(NodeServiceError::AddrParseError)?;
        info!(self.logger, "NodeServer {} starting listening", addr);
        self.setup_server(node_service, addr).await?;
        if !nodes_to_bootstrap.is_empty() {
            self.bootstrap_network(nodes_to_bootstrap).await?;
        }
        self.start_heartbeat().await;
        Ok(())
    }
    
    pub async fn setup_server(&self, node_service: NodeService, addr: SocketAddr) -> Result<(), NodeServiceError> {
        let (pem_certificate, pem_key, root_crt) = {
            let server_config = self.server_config.read().await;
            (server_config.cfg_pem_certificate.clone(), server_config.cfg_pem_key.clone(), server_config.cfg_root_crt.clone())
        };
        let server_tls_config = ServerTlsConfig::new()
            .identity(Identity::from_pem(&pem_certificate, &pem_key))
            .client_ca_root(Certificate::from_pem(&root_crt))
            .client_auth_optional(true);
        Server::builder()
            .tls_config(server_tls_config)?
            .accept_http1(true)
            .add_service(NodeServer::new(node_service))
            .serve(addr)
            .await
            .map_err(NodeServiceError::TonicTransportError)
    }

    async fn start_heartbeat(&self) {
        loop {
            let mut to_remove = Vec::new();
            {
                let peers = self.peer_lock.read().await;
                let peers_data = peers
                    .iter()
                    .filter(|(_, (_, _, is_validator))| *is_validator)
                    .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                    .collect::<Vec<_>>();

                for (addr, peer_client) in peers_data {
                    let mut client = peer_client.lock().await;
                    match client.handle_heartbeat(Request::new(Confirmed {})).await {
                        Ok(_) => {
                            info!(self.logger, "Validator {} is alive", addr);
                        }
                        Err(_) => {
                            info!(self.logger, "Removing non-responsive validator {}", addr);
                            to_remove.push(addr.clone());
                        }
                    }
                }
            }
            {
                let mut peers = self.peer_lock.write().await;
                for addr in to_remove {
                    peers.remove(&addr);
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }  

    pub async fn broadcast_tx(&self, transaction: Transaction) -> Result<(), NodeServiceError> {
        let peers_data = {
            let peers = self.peer_lock.read().await;
            peers
                .iter()
                .filter(|(_, (_, _, is_validator))| *is_validator)
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let transaction_clone = transaction.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.server_config.read().await;
                server_config.cfg_addr.to_string()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(transaction_clone.clone());
                if addr != cfg_addr {
                    if let Err(e) = peer_client_lock.handle_transaction(req).await {
                        error!(
                            self_clone.logger, 
                            "{}: Broadcast error: {:?}", 
                            cfg_addr, 
                            e
                        );
                    } else {
                        info!(
                            self_clone.logger, 
                            "{}: Broadcasted tx to: {:?}", 
                            cfg_addr, 
                            addr
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BroadcastTransactionError(format!("{:?}", err)))?;
        Ok(())
    }

    pub async fn bootstrap_network(&self, addrs: Vec<String>) -> Result<(), NodeServiceError> {
        let mut tasks = Vec::new();
        let connected_peers = self.get_addrs_list().await;
        for addr in addrs {
            if self.contains(&addr, &connected_peers).await {
                continue;
            }
            let node_service_clone = self.clone();
            let (cfg_is_validator, cfg_addr) = {
                let server_config = node_service_clone.server_config.read().await;
                (server_config.cfg_is_validator, server_config.cfg_addr.clone())
            };
            let addr_clone = addr.clone();
            let task = tokio::spawn(async move {
                match node_service_clone.dial_remote_node(&addr_clone).await {
                    Ok((c, v)) => {
                        let is_validator = v.msg_validator;
                        if cfg_is_validator || is_validator {
                            node_service_clone.add_peer(c, v, is_validator).await;
                        }
                    }
                    Err(e) => {
                        error!(node_service_clone.logger, "{}: Failed bootstrap and dial: {:?}", cfg_addr, e);
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BootstrapNetworkError(format!("{:?}", err)))?;
        Ok(())
    }

    pub async fn contains(&self, addr: &str, connected_peers: &[String]) -> bool {
        let cfg_addr = {
            let server_config = self.server_config.read().await;
            server_config.cfg_addr.to_string()
        };
        if cfg_addr == addr {
            return false;
        }
        connected_peers.iter().any(|connected_addr| addr == connected_addr)
    }

    pub async fn get_addrs_list(&self) -> Vec<String> {
        let peers = self.peer_lock.read().await;
        peers.values().map(|(_, version, _)| version.msg_listen_address.clone()).collect()
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version), NodeServiceError> {
        let cfg_addr = {
            let server_config = self.server_config.read().await;
            server_config.cfg_addr.to_string()
        };
        let mut c = make_node_client(addr)
            .await?;
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(NodeServiceError::HandshakeError)?
            .into_inner();
        info!(self.logger, "{}: Dialed remote node: {}", cfg_addr, addr);
        Ok((c, v))
    }

    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version, is_validator: bool) {
        let cfg_addr = {
            let server_config = self.server_config.read().await;
            server_config.cfg_addr.to_string()
        };
        let mut peers = self.peer_lock.write().await;
        let remote_addr = v.msg_listen_address.clone();
        if !peers.contains_key(&remote_addr) {
            peers.insert(remote_addr.clone(), (Arc::new(c.into()), v.clone(), is_validator));
            info!(self.logger, "{}: new validator peer added: {}", cfg_addr, remote_addr);
        } else {
            info!(self.logger, "{}: peer already exists: {}", cfg_addr, remote_addr);
        }
    }

    pub async fn get_version(&self) -> Version {
        let (cfg_keypair, cfg_is_validator, cfg_version, cfg_addr) = {
            let server_config = self.server_config.read().await;
            (server_config.cfg_keypair.clone(), server_config.cfg_is_validator, server_config.cfg_version.clone(), server_config.cfg_addr.clone())
        };
        let keypair = cfg_keypair;
        let msg_public_key = keypair.public.to_bytes().to_vec();
        let msg_validator_id = match &self.validator {
            Some(validator_service) => validator_service.validator_id,
            None => 0,
        };
        Version {
            msg_validator: cfg_is_validator,
            msg_version: cfg_version,
            msg_public_key,
            msg_height: 0,
            msg_listen_address: cfg_addr,
            msg_peer_list: self.get_addrs_list().await,
            msg_validator_id,
        }
    }

    pub async fn make_tx(&self, to: &Vec<u8>, amount: i64) -> Result<(), NodeServiceError> {
        let (cfg_keypair, cfg_addr) = {
            let server_config = self.server_config.read().await;
            (server_config.cfg_keypair.clone(),  server_config.cfg_addr.clone())
        };
        let keypair = &cfg_keypair;
        let public_key = keypair.public.as_bytes().to_vec();
        let from = &public_key;
        let mut utxo_store = self.utxo_store.lock().await;
        let utxos = utxo_store.find_utxos(from, amount)?;
        let mut inputs = Vec::new();
        let mut total_input = 0;
        let mut spent_utxo_keys = Vec::new();
        for utxo in &utxos {
            let msg_to_sign = format!("{}{}", utxo.transaction_hash, utxo.output_index);
            let msg_signature = keypair.sign(msg_to_sign.as_bytes());
            let input = TransactionInput {
                msg_previous_tx_hash: utxo.transaction_hash.clone().into_bytes(),
                msg_previous_out_index: utxo.output_index,
                msg_public_key: public_key.clone(),
                msg_signature: msg_signature.to_bytes().to_vec(),
            };
            inputs.push(input);
            total_input += utxo.amount;
            spent_utxo_keys.push((utxo.transaction_hash.clone(), utxo.output_index));
        }
        for key in spent_utxo_keys {
            utxo_store.remove_utxo(&key)?;
        }
        let output = TransactionOutput {
            msg_amount: amount,
            msg_to: to.clone(),
        };
        let mut outputs = vec![output];
        if total_input > amount {
            let change_output = TransactionOutput {
                msg_amount: total_input - amount,
                msg_to: from.clone(),
            };
            outputs.push(change_output);
        }
        let tx = Transaction {
            msg_version: 1,
            msg_inputs: inputs,
            msg_outputs: outputs,
            msg_relative_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        };
        info!(self.logger, "{}: Created transaction with {} to {:?}", cfg_addr, amount, to);
        self.broadcast_tx(tx).await?;
        Ok(())
    }

    pub async fn pull_state_from(&self, addr: String) -> Result<(), NodeServiceError> {
        let cfg_addr = {
            let server_config = self.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        let peer_write_lock = self.peer_lock.write().await;
        if !peer_write_lock.contains_key(&addr) {
            match self.dial_remote_node(&addr).await {
                Ok((client, version)) => {
                    if version.msg_validator {
                        self.add_peer(client.clone(), version, true).await;
                        info!(self.logger, "{}: new validator peer added: {}", cfg_addr, addr);
                        let client_arc = Arc::new(Mutex::new(client));
                        let mut client_lock = client_arc.lock().await;
                        self.pull_state_from_client(&mut client_lock).await?;
                    } else {
                        error!(self.logger, "{}: peer is not a validator: {}", cfg_addr, addr);
                        return Err(NodeServiceError::PullFromNonValidatorNode);
                    }
                },
                Err(e) => {
                    error!(self.logger, "Failed to dial remote node: {:?}", e);
                    return Err(NodeServiceError::ConnectionFailed);
                },
            }
        } else {
            let (client, _, _) = peer_write_lock.get(&addr).ok_or(NodeServiceError::PeerNotFound)?.clone();
            let mut client_lock = client.lock().await;
            self.pull_state_from_client(&mut client_lock).await?;
        }
        Ok(())
    }    
    
    pub async fn pull_state_from_client(&self, validator_client: &mut NodeClient<Channel>) -> Result<(), NodeServiceError> {
        let cfg_last_height = {
            let server_config = self.server_config.read().await;
            server_config.cfg_last_height
        };
        let request = Request::new(LocalState { msg_last_block_height: cfg_last_height });
        let response = validator_client.push_state(request).await?;
        let block_batch = response.into_inner();
        self.process_incoming_block_batch(block_batch).await?;
        Ok(())
    }

    pub async fn process_incoming_block_batch(&self, block_batch: BlockBatch) -> Result<(), NodeServiceError> {
        for block in block_batch.msg_blocks {
            self.process_incoming_block(block).await?;
        }
        Ok(())
    }

    pub async fn process_incoming_block(&self, block: Block) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.server_config.read().await;
            server_config.cfg_last_height
        };
        if let Some(header) = block.msg_header {
            for transaction in block.msg_transactions {
                self.process_transaction(&transaction).await?;
            }
            let mut server_config = self.server_config.write().await;
            let incoming_height = header.msg_height as u64;
            if local_height < incoming_height {
                server_config.cfg_last_height = incoming_height;
            }
            Ok(())
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn process_incoming_leader_block(&self, block: Block, leader_address: &str) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.server_config.read().await;
            server_config.cfg_last_height
        };
        if let Some(header) = block.msg_header.clone() {
            let incoming_height = header.msg_height as u64;
            if incoming_height == local_height + 1 {
                for transaction in &block.msg_transactions {
                    self.process_transaction(transaction).await?;
                }
                let mut server_config = self.server_config.write().await;
                server_config.cfg_last_height = incoming_height;
                if let Some(validator) = &self.validator {
                    let mut chain_lock = validator.chain.write().await;
                    chain_lock.add_leader_block(block).await?;
                }
                Ok(())
            } else {
                match self.pull_state_from(leader_address.to_string()).await {
                    Ok(_) => Err(NodeServiceError::PullStateError),
                    Err(e) => Err(e),
                }
            }
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn process_transaction(&self, transaction: &Transaction) -> Result<(), NodeServiceError> {
        let cfg_keypair = {
            let server_config = self.server_config.read().await;
            server_config.cfg_keypair.clone()
        };
        let public_key = cfg_keypair.public.as_bytes().to_vec();
        for (output_index, output) in transaction.msg_outputs.iter().enumerate() {
            if output.msg_to == public_key {
                let utxo = UTXO {
                    transaction_hash: hex::encode(hash_transaction(transaction).await),
                    output_index: output_index as u32,
                    amount: output.msg_amount,
                    address: public_key.clone(),
                };
                self.utxo_store.lock().await.put(utxo)?;
            }
        }
        Ok(())
    }
}

pub async fn make_node_client(addr: &str) -> Result<NodeClient<Channel>, NodeServiceError> {
    let (cli_pem_certificate, cli_pem_key, cli_root) = read_client_certs_and_keys().await.map_err(|_| NodeServiceError::FailedToReadCertificates)?;
    let uri = format!("https://{}", addr).parse().map_err(NodeServiceError::UriParseError)?;
    let client_tls_config = ClientTlsConfig::new()
        .domain_name("cryptotron.test.com")
        .ca_certificate(Certificate::from_pem(cli_root))
        .identity(Identity::from_pem(cli_pem_certificate, cli_pem_key));
    let channel = Channel::builder(uri)
        .tls_config(client_tls_config)
        .map_err(NodeServiceError::TonicTransportError)?
        .connect()
        .await
        .map_err(NodeServiceError::TonicTransportError)?;
    let node_client = NodeClient::new(channel);
    Ok(node_client)
}

pub async fn shutdown(shutdown_tx: tokio::sync::oneshot::Sender<()>) -> Result<(), NodeServiceError> {
    shutdown_tx.send(()).map_err(|_| NodeServiceError::ShutdownError)
}