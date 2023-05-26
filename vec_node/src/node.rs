use crate::stake_pool::StakePool;
use crate::clock::Clock;
use vec_merkle::merkle::MerkleTree;
use vec_block::block::sign_block;
use vec_proto::messages::*;
use vec_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use vec_chain::chain::Chain;
use vec_storage::{block_db::{BlockDB, BlockStorer}, utxo_db::*};
use vec_mempool::mempool::*;
use vec_server::server::*;
use vec_transaction::transaction::hash_transaction;
use vec_errors::errors::*;
use std::{sync::Arc, net::SocketAddr};
use tonic::{transport::{Server, Channel, ClientTlsConfig, ServerTlsConfig, Identity, Certificate}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use futures::future::try_join_all;
use slog::{o, Logger, info, Drain, error};
use tokio::time::Duration;
use dashmap::DashMap;
use prost::Message;

#[derive(Clone)]
pub struct NodeService {
    pub config: Arc<RwLock<ServerConfig>>,
    pub peers: DashMap<String, Arc<Mutex<NodeClient<Channel>>>>,
    pub mempool: Arc<Mempool>,
    pub blockchain: Arc<RwLock<Chain>>,
    pub logger: Logger,
    pub clock: Arc<Clock>,
    pub stake_pool: Option<StakePool>,
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

    async fn handle_block(
        &self,
        request: Request<LeaderBlock>,
    ) -> Result<Response<Confirmed>, Status> {
        let leader_block = request.into_inner();
        if let Some(block) = leader_block.msg_block {
            let leader_address = leader_block.msg_leader_address;
            match self.process_block(block, &leader_address).await {
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

    async fn handle_time_req(
        &self,
        _request: Request<DelayRequest>,
    ) -> Result<Response<DelayResponse>, Status> {
        let time = self.clock.get_time();
        let response = DelayResponse { msg_time : time };
        Ok(Response::new(response))
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
        let utxo_db_th_oi = sled::open("PATH!!!").map_err(|_| NodeServiceError::SledOpenError)?;
        let utxo_db_pk = sled::open("PATH!!!").map_err(|_| NodeServiceError::SledOpenError)?;
        let blocks: Box<dyn BlockStorer> = Box::new(BlockDB::new(block_db));
        let utxos: Box<dyn UTXOStorer> = Box::new(UTXODB::new(utxo_db_th_oi, utxo_db_pk));
        let mempool = Arc::new(Mempool::new());
        let blockchain = Chain::new(blocks, utxos)
            .await
            .map_err(|e| NodeServiceError::ChainCreationError(format!("{:?}", e)))?;
        let clock = Arc::new(Clock::new());
        let config = Arc::new(RwLock::new(server_cfg.clone()));
        let stake_pool = Some(StakePool::new().await);
        Ok(NodeService {
            config,
            peers,
            logger,
            mempool,
            blockchain: Arc::new(RwLock::new(blockchain)),
            clock,
            stake_pool,
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
        self.start_clock().await;
        self.start_heartbeat().await;
        Ok(())
    }
    
    pub async fn setup_server(&self, node_service: NodeService, cfg_ip: SocketAddr) -> Result<(), NodeServiceError> {
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
            .serve(cfg_ip)
            .await
            .map_err(NodeServiceError::TonicTransportError)
    }

    async fn start_heartbeat(&self) {
        loop {
            let mut to_remove = Vec::new();
            {
                let peers_data = self.peers
                    .iter()
                    .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
                    .collect::<Vec<_>>();
                for (ip, peer_client) in peers_data {
                    let mut client = peer_client.lock().await;
                    match client.handle_heartbeat(Request::new(Confirmed {})).await {
                        Ok(_) => {
                            info!(self.logger, "Node {} is alive", ip);
                        }
                        Err(_) => {
                            info!(self.logger, "Removing non-responsive node {}", ip);
                            to_remove.push(ip.clone());
                        }
                    }
                }
            }
            {
                for ip in to_remove {
                    self.peers.remove(&ip);
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    pub async fn start_clock(&self) {
        self.clock.start().await;
    }
    
    async fn synchronize_clock_with(&self, client: &mut NodeClient<Channel>) -> Result<(), NodeServiceError> {
        let t1 = self.clock.get_time();
        let req = Request::new(DelayRequest { } );
        let res = client.handle_time_req(req).await?;
        let t2 = res.into_inner().msg_time; 
        let t3 = self.clock.get_time();
        let travel_delay = (t3 - t1) as i64;
        let average_delay = travel_delay / 2;
        let relative_offset = (t2 - t1) as i64;
        let offset = relative_offset - average_delay;
        if offset >= 0 {
            self.clock.add_to_time(offset as u64);
        }
        Ok(())
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
        let (cfg_keypair, cfg_version, cfg_ip) = {
            let server_config = self.config.read().await;
            (server_config.cfg_keypair.clone(), server_config.cfg_version.clone(), server_config.cfg_ip.clone())
        };
        let keypair = cfg_keypair;
        let msg_pk = keypair.pk.to_bytes().to_vec();
        Version {
            msg_version: cfg_version,
            msg_pk,
            msg_height: 0,
            msg_ip: cfg_ip,
            msg_peer_list: self.get_ip_list(),
        }
    }

    pub async fn make_block(&self) -> Result<Block, NodeServiceError> {
        let cfg_keypair = {
            let server_config = self.config.read().await;
            server_config.cfg_keypair.clone()
        };
        let blockchain = self.blockchain.read().await;
        let msg_previous_hash = blockchain.get_previous_hash_in_chain().await?;
        let msg_height = (blockchain.chain_height() + 1) as u32;
        let keypair = &cfg_keypair;
        let pk = keypair.pk.to_bytes().to_vec();
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
            msg_timestamp: self.clock.get_time(),
        };
        let mut block = Block {
            msg_header: Some(header),
            msg_transactions: transactions,
            msg_pk: pk,
            msg_sig: vec![],
        };
        let signature = sign_block(&block, keypair).await?;
        block.msg_sig = signature.to_vec();
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

    pub async fn make_tx(&self, to: &Vec<u8>, amount: u64) -> Result<(), NodeServiceError> {
        let (cfg_keypair, cfg_addr) = {
            let server_config = self.config.read().await;
            (server_config.cfg_keypair.clone(),  server_config.cfg_ip.clone())
        };
        let keypair = &cfg_keypair;
        let pk = keypair.pk.as_bytes().to_vec();
        let from = &pk;
        let blockchain = self.blockchain.read().await;
        let utxos = blockchain.utxos.collect_minimum_utxos(from, amount).await?;
        let mut inputs = Vec::new();
        let mut total_input = 0;
        let mut spent_utxo_keys = Vec::new();
        for utxo in &utxos {
            let msg_to_sign = format!("{}{}", utxo.transaction_hash, utxo.output_index);
            let msg_sig = keypair.sign(msg_to_sign.as_bytes());
            let input = TransactionInput {
                msg_previous_tx_hash: utxo.transaction_hash.clone().into_bytes(),
                msg_previous_out_index: utxo.output_index,
                msg_pk: pk.clone(),
                msg_sig: msg_sig.to_bytes().to_vec(),
            };
            inputs.push(input);
            total_input += utxo.amount;
            spent_utxo_keys.push((utxo.transaction_hash.clone(), utxo.output_index));
        }
        {
            let blockchain = self.blockchain.write().await;
            for key in spent_utxo_keys {
                blockchain.utxos.remove(&key).await?;
            }
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
            msg_inputs: inputs,
            msg_outputs: outputs,
            msg_timestamp: self.clock.get_time(),
        };
        info!(self.logger, "{}: Created transaction with {} to {:?}", cfg_addr, amount, to);
        let hash_string = hex::encode(hash_transaction(&tx).await);
        self.broadcast_tx_hash(hash_string).await?;
        Ok(())
    }

    pub async fn broadcast_tx_hash(&self, hash_string: String) -> Result<(), NodeServiceError> {
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
            self.mempool.add(transaction.clone()).await;
            self.process_transaction(&transaction).await?;
            self.broadcast_tx_hash(transaction_hash.to_string()).await?;
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
        if let Some(header) = block.msg_header {
            for transaction in block.msg_transactions {
                self.process_transaction(&transaction).await?;
            }
            let mut server_config = self.config.write().await;
            let incoming_height = header.msg_height as u64;
            if local_height < incoming_height {
                server_config.cfg_height = incoming_height;
            }
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
                    self.process_transaction(transaction).await?;
                }
                let mut server_config = self.config.write().await;
                server_config.cfg_height = incoming_height;
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
        let blockchain = self.blockchain.write().await;
        for input in &transaction.msg_inputs {
            let tx_hash = hex::encode(input.msg_previous_tx_hash.clone());
            blockchain.utxos.remove(&(tx_hash, input.msg_previous_out_index)).await?;
        }
        for (output_index, output) in transaction.msg_outputs.iter().enumerate() {
            let utxo = UTXO {
                transaction_hash: hex::encode(hash_transaction(transaction).await),
                output_index: output_index as u32,
                amount: output.msg_amount,
                pk: output.msg_to.clone(),
            };
            blockchain.utxos.put(&utxo).await?;
        }
        Ok(())
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
                    if let Err(err) = peer_client_lock.handle_peer_exchange(req).await {
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
    let (cli_pem_certificate, cli_pem_key, cli_root) = read_client_certs_and_keys().await.map_err(|_| NodeServiceError::FailedToReadCertificates)?;
    let uri = format!("https://{}", ip).parse().map_err(NodeServiceError::UriParseError)?;
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