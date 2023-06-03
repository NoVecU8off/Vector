use crate::clock::Clock;
use rand::thread_rng;
use vec_merkle::merkle::MerkleTree;
use vec_proto::messages::*;
use vec_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use vec_chain::chain::Chain;
use vec_storage::{block_db::*, output_db::*};
use vec_mempool::mempool::*;
use vec_server::server::*;
use vec_transaction::transaction::hash_transaction;
use vec_errors::errors::*;
use std::{sync::Arc, net::SocketAddr};
use tonic::{transport::{Server, Channel}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use futures::future::try_join_all;
use slog::{o, Logger, info, Drain, error};
use dashmap::DashMap;
use prost::Message;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct NodeService {
    pub config: Arc<RwLock<ServerConfig>>,
    pub peers: DashMap<String, Arc<Mutex<NodeClient<Channel>>>>,
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
        let ip = version.msg_ip.clone();
        info!(self.logger, "Recieved version, address: {}", ip);
        let connected_ips = self.get_ip_list();
        if !self.contains(&ip, &connected_ips).await {
            match make_node_client(&ip).await {
                Ok(c) => {
                    info!(self.logger, "Created node client successfully");
                    self.add_peer(c, version_clone.clone()).await;
                }
                Err(e) => {
                    error!(self.logger, "Failed to create node client: {:?}", e);
                }
            }
        } else {
            info!(self.logger, "Address already connected: {}", ip);
        }
        let reply = self.get_version().await;
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

    async fn handle_peer_list(
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

    async fn handle_tx_push(
        &self,
        request: Request<PushTxRequest>,
    ) -> Result<Response<Confirmed>, Status> {
        let push_request = request.into_inner();
        let sender_ip = push_request.msg_ip;
        let transaction_hash = push_request.msg_transaction_hash;
        if !self.mempool.has_hash(&transaction_hash) {
            match self.pull_transaction_from(&sender_ip, &transaction_hash).await {
                Ok(_) => {
                    Ok(Response::new(Confirmed {}))
                }
                Err(e) => {
                    error!(self.logger, "Failed to make transaction pull: {:?}", e);
                    Err(Status::internal("Failed to make transaction pull"))
                }
            }
        } else {
            Ok(Response::new(Confirmed {}))
        }
    }

    async fn handle_tx_pull(
        &self,
        request: Request<PullTxRequest>,
    ) -> Result<Response<Transaction>, Status> {
        let pull_request = request.into_inner();
        let transaction_hash = pull_request.msg_transaction_hash;
        if !self.mempool.has_hash(&transaction_hash) {
            if let Some(transaction) = self.mempool.get_by_hash(&transaction_hash) {
                Ok(Response::new(transaction))
            } else {
                Err(Status::internal("Requested transaction not found"))
            }
        } else {
            Err(Status::internal("Requested transaction not found"))
        }
    }

    async fn handle_block_push(
        &self,
        request: Request<PushBlockRequest>,
    ) -> Result<Response<Confirmed>, Status> {
        let push_request = request.into_inner();
        let sender_ip = push_request.msg_ip;
        let block_hash = push_request.msg_block_hash;
        let read_lock = self.blockchain.read().await;
        match read_lock.blocks.get(&block_hash).await {
            Ok(Some(_)) => {
                Ok(Response::new(Confirmed {}))
            },
            Ok(None) => {
                match self.pull_block_from(&sender_ip, &block_hash).await {
                    Ok(_) => {
                        Ok(Response::new(Confirmed {}))
                    },
                    Err(e) => {
                        error!(self.logger, "Failed to make block pull: {:?}", e);
                        Err(Status::internal("Failed to make block pull"))
                    }
                }
            },
            Err(e) => {
                error!(self.logger, "Failed to check if block exists: {:?}", e);
                Err(Status::internal("Failed to check if block exists"))
            }
        }
    }

    async fn handle_block_pull(
        &self,
        request: Request<PullBlockRequest>,
    ) -> Result<Response<Block>, Status> {
        let pull_request = request.into_inner();
        let block_hash = pull_request.msg_block_hash;
        let read_lock = self.blockchain.read().await;
        match read_lock.blocks.get(&block_hash).await {
            Ok(Some(block)) => {
                Ok(Response::new(block))
            },
            Ok(None) => {
                Err(Status::not_found("Block not found"))
            },
            Err(e) => {
                error!(self.logger, "Failed to get block: {:?}", e);
                Err(Status::internal("Failed to get block"))
            }
        }
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
        let peers = DashMap::new();
        let block_db = sled::open("PATH!!!").map_err(|_| NodeServiceError::SledOpenError)?;
        let output_db_th_oi = sled::open("PATH!!!").map_err(|_| NodeServiceError::SledOpenError)?;
        let output_db_pk = sled::open("PATH!!!").map_err(|_| NodeServiceError::SledOpenError)?;
        
        let blocks: Box<dyn BlockStorer> = Box::new(BlockDB::new(block_db));
        
        let mempool = Arc::new(Mempool::new());
        let blockchain = Chain::new(blocks)
            .await
            .map_err(|e| NodeServiceError::ChainCreationError(format!("{:?}", e)))?;
        let clock = Arc::new(Clock::new());
        let config = Arc::new(RwLock::new(server_cfg.clone()));
        Ok(NodeService {
            config,
            peers,
            logger,
            mempool,
            blockchain: Arc::new(RwLock::new(blockchain)),
        })
    }

    pub async fn start(&mut self, ips_to_bootstrap: Vec<String>) -> Result<(), NodeServiceError> {
        let node_service = self.clone();
        let cfg_ip = {
                let server_config = self.config.read().await;
                server_config.cfg_ip.to_string()
            }
            .parse()
            .map_err(NodeServiceError::AddrParseError)?;
        info!(self.logger, "NodeServer {} starting listening", cfg_ip);
        self.setup_server(node_service, cfg_ip).await?;
        if !ips_to_bootstrap.is_empty() {
            self.bootstrap_network(ips_to_bootstrap).await?;
        }
        Ok(())
    }
    
    pub async fn setup_server(&self, node_service: NodeService, cfg_ip: SocketAddr) -> Result<(), NodeServiceError> {
        Server::builder()
            .add_service(NodeServer::new(node_service))
            .serve(cfg_ip)
            .await
            .map_err(NodeServiceError::TonicTransportError)
    }

    pub async fn bootstrap_network(&self, ips: Vec<String>) -> Result<(), NodeServiceError> {
        let mut tasks = Vec::new();
        let connected_peers = self.get_ip_list();
        for ip in ips {
            if self.contains(&ip, &connected_peers).await {
                continue;
            }
            let node_service_clone = self.clone();
            let cfg_ip = {
                let server_config = node_service_clone.config.read().await;
                server_config.cfg_ip.clone()
            };
            let addr_clone = ip.clone();
            let task = tokio::spawn(async move {
                match node_service_clone.dial_remote_node(&addr_clone).await {
                    Ok((c, v)) => {
                        node_service_clone.add_peer(c, v).await;
                    }
                    Err(e) => {
                        error!(node_service_clone.logger, "{}: Failed bootstrap and dial: {:?}", cfg_ip, e);
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BootstrapNetworkError(format!("{:?}", err)))?;
        Ok(())
    }

    pub async fn contains(&self, ip: &str, connected_ips: &[String]) -> bool {
        let cfg_ip = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.to_string()
        };
        if cfg_ip == ip {
            return false;
        }
        connected_ips.iter().any(|connected_addr| ip == connected_addr)
    }

    pub fn get_ip_list(&self) -> Vec<String> {
        self.peers
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub async fn dial_remote_node(&self, ip: &str) -> Result<(NodeClient<Channel>, Version), NodeServiceError> {
        let cfg_ip = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.to_string()
        };
        let mut c = make_node_client(ip)
            .await?;
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(NodeServiceError::HandshakeError)?
            .into_inner();
        info!(self.logger, "{}: Dialed remote node: {}", cfg_ip, ip);
        Ok((c, v))
    }

    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let cfg_ip = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.to_string()
        };
        let remote_ip = v.msg_ip.clone();
        if !self.peers.contains_key(&remote_ip) {
            self.peers.insert(remote_ip.clone(), Arc::new(c.into()));
            info!(self.logger, "{}: new validator peer added: {}", cfg_ip, remote_ip);
        } else {
            info!(self.logger, "{}: peer already exists: {}", cfg_ip, remote_ip);
        }
    }

    pub async fn get_version(&self) -> Version {
        let (cfg_wallet, cfg_version, cfg_ip) = {
            let server_config = self.config.read().await;
            (server_config.cfg_wallet.clone(), server_config.cfg_version.clone(), server_config.cfg_ip.clone())
        };
        let msg_public = cfg_wallet.public_spend_key_to_vec();
        Version {
            msg_version: cfg_version,
            msg_public,
            msg_height: 0,
            msg_ip: cfg_ip,
            msg_peer_list: self.get_ip_list(),
        }
    }

    pub async fn make_block(&self) -> Result<Block, NodeServiceError> {
        let blockchain = self.blockchain.read().await;
        let msg_previous_hash = blockchain.get_previous_hash_in_chain().await?;
        let msg_height = (blockchain.chain_height() + 1) as u32;
        let transactions = self.mempool.get_transactions();
        let transaction_data: Vec<Vec<u8>> = transactions
            .iter()
            .map(|transaction| {
                let mut bytes = Vec::new();
                transaction.encode(&mut bytes).unwrap();
                bytes
            })
            .collect();
        let merkle_tree = MerkleTree::from_list(&transaction_data);
        let merkle_root = merkle_tree.get_hash();
        let header = Header {
            msg_version: 1,
            msg_height,
            msg_previous_hash,
            msg_root_hash: merkle_root,
            msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        let block = Block {
            msg_header: Some(header),
            msg_transactions: transactions,
        };
        Ok(block)
    }

    pub async fn broadcast_block_hash(&self, hash_string: String) -> Result<(), NodeServiceError> {
        let peers_data = self.peers
                    .iter()
                    .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
                    .collect::<Vec<_>>();
        let mut tasks = Vec::new();
        for (ip, peer_client) in peers_data {
            let hash_clone = hash_string.clone();
            let self_clone = self.clone();
            let cfg_ip = {
                let server_config = self_clone.config.read().await;
                server_config.cfg_ip.to_string()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let message = PushBlockRequest {
                    msg_block_hash: hash_clone,
                    msg_ip: cfg_ip.clone(),
                };
                if let Err(e) = peer_client_lock.handle_block_push(message).await {
                    error!(
                        self_clone.logger, 
                        "{}: Broadcast error: {:?}", 
                        cfg_ip, 
                        e
                    );
                } else {
                    info!(
                        self_clone.logger, 
                        "{}: Broadcasted hash to: {:?}", 
                        cfg_ip, 
                        ip
                    );
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BroadcastTransactionError(format!("{:?}", err)))?;
        Ok(())
    }

    pub async fn broadcast_tx_hash(&self, hash_string: &String) -> Result<(), NodeServiceError> {
        let peers_data = self.peers
                    .iter()
                    .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
                    .collect::<Vec<_>>();
        let mut tasks = Vec::new();
        for (ip, peer_client) in peers_data {
            let hash_clone = hash_string.clone();
            let self_clone = self.clone();
            let cfg_ip = {
                let server_config = self_clone.config.read().await;
                server_config.cfg_ip.to_string()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let message = PushTxRequest {
                    msg_transaction_hash: hash_clone,
                    msg_ip: cfg_ip.clone(),
                };
                if let Err(e) = peer_client_lock.handle_tx_push(message).await {
                    error!(
                        self_clone.logger, 
                        "{}: Broadcast error: {:?}", 
                        cfg_ip, 
                        e
                    );
                } else {
                    info!(
                        self_clone.logger, 
                        "{}: Broadcasted hash to: {:?}", 
                        cfg_ip, 
                        ip
                    );
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BroadcastTransactionError(format!("{:?}", err)))?;
        Ok(())
    }

    pub async fn pull_transaction_from(&self, sender_ip: &str, transaction_hash: &str) -> Result<(), NodeServiceError> {
        if let Some(client_arc_mutex) = self.peers.get(sender_ip) {
            let client_arc = client_arc_mutex.clone();
            let mut client = client_arc.lock().await;
            let my_ip = {
                let server_config = self.config.read().await;
                server_config.cfg_ip.to_string()
            };
            let message = PullTxRequest {
                msg_transaction_hash: transaction_hash.to_string(),
                msg_ip: my_ip.to_string(),
            };
            let response = client.handle_tx_pull(message).await?;
            let transaction = response.into_inner();
            self.blockchain.write().await.verify_transaction(&transaction).await?;
            self.mempool.add(transaction.clone()).await;
            self.broadcast_tx_hash(&transaction_hash.to_string()).await?;
        }
        Ok(())
    }

    pub async fn pull_block_from(&self, sender_ip: &str, block_hash: &str) -> Result<(), NodeServiceError> {
        if let Some(client_arc_mutex) = self.peers.get(sender_ip) {
            let client_arc = client_arc_mutex.clone();
            let mut client = client_arc.lock().await;
            let my_ip = {
                let server_config = self.config.read().await;
                server_config.cfg_ip.to_string()
            };
            let message = PullBlockRequest {
                msg_block_hash: block_hash.to_string(),
                msg_ip: my_ip.to_string(),
            };
            let response = client.handle_block_pull(message).await?;
            let block = response.into_inner();
            self.process_incoming_block(block).await?;
            self.broadcast_block_hash(block_hash.to_string()).await?;
        }
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
            server_config.cfg_height
        };
        if let Some(header) = block.clone().msg_header {
            for transaction in &block.msg_transactions {
                self.blockchain.write().await.process_transaction(transaction).await?;
            }
            let mut server_config = self.config.write().await;
            let incoming_height = header.msg_height as u64;
            if local_height < incoming_height {
                server_config.cfg_height = incoming_height;
            }
            self.blockchain.write().await.add_block(block).await?;
            Ok(())
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn process_block(&self, block: Block, leader_address: &str) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.config.read().await;
            server_config.cfg_height
        };
        if let Some(header) = block.msg_header.clone() {
            let incoming_height = header.msg_height as u64;
            if incoming_height == local_height + 1 {
                for transaction in &block.msg_transactions {
                    self.blockchain.write().await.process_transaction(&transaction).await?;
                }
                let mut server_config = self.config.write().await;
                server_config.cfg_height = incoming_height;
                self.blockchain.write().await.add_block(block).await?;
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

    pub async fn pull_state_from(&self, ip: String) -> Result<(), NodeServiceError> {
        let cfg_ip = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.clone()
        };
        if !self.peers.contains_key(&ip) {
            match self.dial_remote_node(&ip).await {
                Ok((client, version)) => {
                    self.add_peer(client.clone(), version).await;
                    info!(self.logger, "{}: new validator peer added: {}", cfg_ip, ip);
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
            let client = self.peers.get(&ip).ok_or(NodeServiceError::PeerNotFound)?.clone();
            let mut client_lock = client.lock().await;
            self.pull_state_from_client(&mut client_lock).await?;
        }
        Ok(())
    }       
    
    pub async fn pull_state_from_client(&self, client: &mut NodeClient<Channel>) -> Result<(), NodeServiceError> {
        let height = {
            let server_config = self.config.read().await;
            server_config.cfg_height
        };
        let request = Request::new(LocalState { msg_last_block_height: height });
        let response = client.push_state(request).await?;
        let block_batch = response.into_inner();
        self.process_incoming_block_batch(block_batch).await?;
        Ok(())
    }
    
    pub async fn broadcast_peer_list(&self) -> Result<(), ValidatorServiceError> {
        let cfg_ip = {
            let server_config = self.config.read().await;
            server_config.cfg_ip.clone()
        };
        info!(self.logger, "{}: broadcasting peer list", cfg_ip);
        let my_ip = &cfg_ip;
        let mut peers_ips: Vec<String> = self.get_ip_list();
        peers_ips.push(my_ip.clone());
        let msg = PeerList {
            msg_peers_addresses: peers_ips,
        };
        let peers_data: Vec<_> = self.peers
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        let mut tasks = Vec::new();
        for (ip, peer_client) in peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let cfg_ip = {
                let server_config = self_clone.config.read().await;
                server_config.cfg_ip.clone()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if ip != cfg_ip {
                    if let Err(err) = peer_client_lock.handle_peer_list(req).await {
                        error!(
                            self_clone.logger,
                            "Failed to broadcast peer list to {}: {:?}",
                            ip,
                            err
                        );
                    } else {
                        info!(
                            self_clone.logger,
                            "{}: broadcasted peer list to {}",
                            cfg_ip,
                            ip
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

pub async fn make_node_client(ip: &str) -> Result<NodeClient<Channel>, NodeServiceError> {
    let uri = format!("http://{}", ip).parse().map_err(NodeServiceError::UriParseError)?;
    let channel = Channel::builder(uri)
        .connect()
        .await
        .map_err(NodeServiceError::TonicTransportError)?;
    let node_client = NodeClient::new(channel);
    Ok(node_client)
}

pub async fn shutdown(shutdown_tx: tokio::sync::oneshot::Sender<()>) -> Result<(), NodeServiceError> {
    shutdown_tx.send(()).map_err(|_| NodeServiceError::ShutdownError)
}