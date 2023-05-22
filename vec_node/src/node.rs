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
    pub config: Arc<RwLock<ServerConfig>>,
    pub peers: Arc<RwLock<HashMap<String, (Arc<Mutex<NodeClient<Channel>>>, Version)>>>,
    pub utxo_store: Arc<Mutex<dyn UTXOStorer>>,
    pub mempool: Arc<Mempool>,
    pub blockchain: Arc<RwLock<Chain>>,
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
        if !self.contains(&addr, &connected_peers).await {
            match make_node_client(&addr).await {
                Ok(c) => {
                    info!(self.logger, "Created node client successfully");
                    self.add_peer(c, version_clone.clone()).await;
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
    
    async fn push_state(
        &self,
        request: Request<LocalState>,
    ) -> Result<Response<BlockBatch>, Status> {
        let current_state = request.into_inner();
        let requested_height = current_state.msg_last_block_height;
        let mut blocks = Vec::new();
        let chain_lock = self.blockchain.read().await;
        for height in (requested_height + 1)..=chain_lock.chain_height() as u64 {
            match chain_lock.get_block_by_height(height as usize).await {
                Ok(block) => blocks.push(block),
                Err(e) => {
                    error!(self.logger, "Failed to get block at height {}: {:?}", height, e);
                    return Err(Status::internal(format!("Failed to get block at height {}", height)));
                }
            }
        }
        let block_batch = BlockBatch { msg_blocks: blocks };
        Ok(Response::new(block_batch))
    }

    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
    ) -> Result<Response<Confirmed>, Status> {
        let transaction = request.into_inner();
        let hash = hash_transaction(&transaction).await;
        let hash_str = hex::encode(&hash);
        let cfg_addr = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.clone()
        };
        if !self.mempool.contains_transaction(&transaction).await && self.mempool.add(transaction.clone()).await {
                info!(self.logger, "{}: received and added transaction: {}", cfg_addr, hash_str);
                let self_clone = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = self_clone.broadcast_tx(transaction).await {
                        error!(self_clone.logger, "Error broadcasting transaction: {}", e);
                    }
                });
            }
        Ok(Response::new(Confirmed {}))
    }

    async fn handle_block(
        &self,
        request: Request<LeaderBlock>,
    ) -> Result<Response<Confirmed>, Status> {
        let leader_block = request.into_inner();
        if let Some(block) = leader_block.msg_block {
            let leader_address = leader_block.msg_leader_address;
            match self.process_leader_block(block, &leader_address).await {
                Ok(_) => {
                    info!(self.logger, "Local UTXO updated successfully");
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
    pub async fn new(server_cfg: ServerConfig) -> Result<Self, NodeServiceError> {
        let logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        info!(logger, "NodeService {} created", server_cfg.cfg_ip);
        let peers = Arc::new(RwLock::new(HashMap::new()));
        let block_storer: Box<dyn BlockStorer> = Box::new(MemoryBlockStore::new());
        let utxo_set_storer: Box<dyn UTXOSetStorer> = Box::new(MemoryUTXOSet::new());
        let utxo_store: Arc<Mutex<dyn UTXOStorer>> = Arc::new(Mutex::new(MemoryUTXOStore::new()));
        let mempool = Arc::new(Mempool::new());
        let blockchain = Chain::new(block_storer, utxo_set_storer)
            .await
            .map_err(|e| NodeServiceError::ChainCreationError(format!("{:?}", e)))?;

        let config = Arc::new(RwLock::new(server_cfg.clone()));
        Ok(NodeService {
            config,
            peers,
            logger,
            utxo_store,
            mempool,
            blockchain: Arc::new(RwLock::new(blockchain)),
        })
    }

    pub async fn start(&mut self, nodes_to_bootstrap: Vec<String>) -> Result<(), NodeServiceError> {
        let node_service = self.clone();
        let addr = {
                let server_config = self.config.read().await;
                server_config.cfg_ip.to_string()
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
            let server_config = self.config.read().await;
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
                let peers = self.peers.read().await;
                let peers_data = peers
                    .iter()
                    .map(|(addr, (peer_client, _))| (addr.clone(), Arc::clone(peer_client)))
                    .collect::<Vec<_>>();

                for (addr, peer_client) in peers_data {
                    let mut client = peer_client.lock().await;
                    match client.handle_heartbeat(Request::new(Confirmed {})).await {
                        Ok(_) => {
                            info!(self.logger, "Node {} is alive", addr);
                        }
                        Err(_) => {
                            info!(self.logger, "Removing non-responsive node {}", addr);
                            to_remove.push(addr.clone());
                        }
                    }
                }
            }
            {
                let mut peers = self.peers.write().await;
                for addr in to_remove {
                    peers.remove(&addr);
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }  

    pub async fn broadcast_tx(&self, transaction: Transaction) -> Result<(), NodeServiceError> {
        let peers_data = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .map(|(addr, (peer_client, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let transaction_clone = transaction.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.config.read().await;
                server_config.cfg_ip.to_string()
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
            let cfg_addr = {
                let server_config = node_service_clone.config.read().await;
                server_config.cfg_ip.clone()
            };
            let addr_clone = addr.clone();
            let task = tokio::spawn(async move {
                match node_service_clone.dial_remote_node(&addr_clone).await {
                    Ok((c, v)) => {
                        node_service_clone.add_peer(c, v).await;
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
            let server_config = self.config.read().await;
            server_config.cfg_ip.to_string()
        };
        if cfg_addr == addr {
            return false;
        }
        connected_peers.iter().any(|connected_addr| addr == connected_addr)
    }

    pub async fn get_addrs_list(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        peers.values().map(|(_, version)| version.msg_listen_address.clone()).collect()
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version), NodeServiceError> {
        let cfg_addr = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.to_string()
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

    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let cfg_addr = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.to_string()
        };
        let mut peers = self.peers.write().await;
        let remote_addr = v.msg_listen_address.clone();
        if !peers.contains_key(&remote_addr) {
            peers.insert(remote_addr.clone(), (Arc::new(c.into()), v.clone()));
            info!(self.logger, "{}: new validator peer added: {}", cfg_addr, remote_addr);
        } else {
            info!(self.logger, "{}: peer already exists: {}", cfg_addr, remote_addr);
        }
    }

    pub async fn get_version(&self) -> Version {
        let (cfg_keypair, cfg_version, cfg_addr) = {
            let server_config = self.config.read().await;
            (server_config.cfg_keypair.clone(), server_config.cfg_version.clone(), server_config.cfg_ip.clone())
        };
        let keypair = cfg_keypair;
        let msg_public_key = keypair.public.to_bytes().to_vec();
        Version {
            msg_version: cfg_version,
            msg_public_key,
            msg_height: 0,
            msg_listen_address: cfg_addr,
            msg_peer_list: self.get_addrs_list().await,
        }
    }

    pub async fn make_tx(&self, to: &Vec<u8>, amount: i64) -> Result<(), NodeServiceError> {
        let (cfg_keypair, cfg_addr) = {
            let server_config = self.config.read().await;
            (server_config.cfg_keypair.clone(),  server_config.cfg_ip.clone())
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

    pub async fn process_incoming_block_batch(&self, block_batch: BlockBatch) -> Result<(), NodeServiceError> {
        for block in block_batch.msg_blocks {
            self.process_incoming_block(block).await?;
        }
        Ok(())
    }

    pub async fn process_incoming_block(&self, block: Block) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.config.read().await;
            server_config.cfg_last_height
        };
        if let Some(header) = block.msg_header {
            for transaction in block.msg_transactions {
                self.process_transaction(&transaction).await?;
            }
            let mut server_config = self.config.write().await;
            let incoming_height = header.msg_height as u64;
            if local_height < incoming_height {
                server_config.cfg_last_height = incoming_height;
            }
            Ok(())
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn process_leader_block(&self, block: Block, leader_address: &str) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.config.read().await;
            server_config.cfg_last_height
        };
        if let Some(header) = block.msg_header.clone() {
            let incoming_height = header.msg_height as u64;
            if incoming_height == local_height + 1 {
                for transaction in &block.msg_transactions {
                    self.process_transaction(transaction).await?;
                }
                let mut server_config = self.config.write().await;
                server_config.cfg_last_height = incoming_height;
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
            let server_config = self.config.read().await;
            server_config.cfg_keypair.clone()
        };
        let public_key = cfg_keypair.public.as_bytes().to_vec();
        for (output_index, output) in transaction.msg_outputs.iter().enumerate() {
            if output.msg_to == public_key {
                let utxo = UTXO {
                    transaction_hash: hex::encode(hash_transaction(transaction).await),
                    output_index: output_index as u32,
                    amount: output.msg_amount,
                    public: public_key.clone(),
                };
                self.utxo_store.lock().await.put(utxo)?;
            }
        }
        Ok(())
    }

    pub async fn pull_state_from(&self, addr: String) -> Result<(), NodeServiceError> {
        let cfg_addr = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.clone()
        };
        let peer_write_lock = self.peers.write().await;
        if !peer_write_lock.contains_key(&addr) {
            match self.dial_remote_node(&addr).await {
                Ok((client, version)) => {
                    self.add_peer(client.clone(), version).await;
                    info!(self.logger, "{}: new validator peer added: {}", cfg_addr, addr);
                    let client_arc = Arc::new(Mutex::new(client));
                    let mut client_lock = client_arc.lock().await;
                    self.pull_state_from_client(&mut client_lock).await?;
                },
                Err(e) => {
                    error!(self.logger, "Failed to dial remote node: {:?}", e);
                    return Err(NodeServiceError::ConnectionFailed);
                },
            }
        } else {
            let (client, _) = peer_write_lock.get(&addr).ok_or(NodeServiceError::PeerNotFound)?.clone();
            let mut client_lock = client.lock().await;
            self.pull_state_from_client(&mut client_lock).await?;
        }
        Ok(())
    }    
    
    pub async fn pull_state_from_client(&self, validator_client: &mut NodeClient<Channel>) -> Result<(), NodeServiceError> {
        let cfg_last_height = {
            let server_config = self.config.read().await;
            server_config.cfg_last_height
        };
        let request = Request::new(LocalState { msg_last_block_height: cfg_last_height });
        let response = validator_client.push_state(request).await?;
        let block_batch = response.into_inner();
        self.process_incoming_block_batch(block_batch).await?;
        Ok(())
    }
    
    pub async fn broadcast_peer_list(&self) -> Result<(), ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.clone()
        };
        info!(self.logger, "{}: broadcasting peer list", cfg_addr);
        let my_addr = &cfg_addr;
        let mut peers_addresses = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .map(|(addr, (_, _))| (addr.clone()))
                .collect::<Vec<_>>()
        };
        peers_addresses.push(my_addr.clone());
        let msg = PeerList {
            msg_peers_addresses: peers_addresses,
        };
        let peers_data = {
            let peers = self.peers.read().await;
            peers
                .iter()
                .map(|(addr, (peer_client, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.config.read().await;
                server_config.cfg_ip.clone()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if addr != cfg_addr {
                    if let Err(err) = peer_client_lock.handle_peer_exchange(req).await {
                        error!(
                            self_clone.logger,
                            "Failed to broadcast peer list to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            self_clone.logger,
                            "{}: broadcasted peer list to {}",
                            cfg_addr,
                            addr
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|_| ValidatorServiceError::PeerBroadcastFailed)?;
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