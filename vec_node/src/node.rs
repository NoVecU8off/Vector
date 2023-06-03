use vec_block::block::hash_header_by_block;
use vec_merkle::merkle::MerkleTree;
use vec_proto::messages::*;
use vec_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use vec_cryptography::cryptography::Wallet;
use vec_chain::chain::Chain;
use vec_storage::{block_db::*, output_db::*, image_db::*, ip_db::*};
use vec_mempool::mempool::*;
use vec_server::server::*;
use vec_transaction::transaction::hash_transaction;
use vec_errors::errors::*;
use curve25519_dalek_ng::{scalar::Scalar, constants};
use std::{sync::Arc, net::SocketAddr};
use tonic::{transport::{Server, Channel}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use futures::future::try_join_all;
use slog::{o, Logger, info, Drain, error};
use dashmap::DashMap;
use prost::Message;
use std::time::{SystemTime, UNIX_EPOCH};
use sha3::{Keccak256, Digest};

#[derive(Clone)]
pub struct NodeService {
    pub config: Arc<RwLock<ServerConfig>>,
    pub peers: DashMap<String, Arc<Mutex<NodeClient<Channel>>>>,
    pub mempool: Arc<Mempool>,
    pub blockchain: Arc<RwLock<Chain>>,
    pub ips: Arc<IpDB>,
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
        let addr: String = version.msg_address.clone();
        let ip: String = version.msg_ip;
        info!(self.logger, "Recieved version, address: {}", addr);
        let connected_addrs = self.get_addr_list();
        if !self.contains(&addr, &connected_addrs).await {
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
            info!(self.logger, "Address already connected: {}", addr);
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
        info!(self.logger, "Recieved push block request");
        let push_request = request.into_inner();
        let sender_ip = push_request.msg_ip;
        let block_hash = push_request.msg_block_hash;
        let read_lock = self.blockchain.read().await;
        match read_lock.blocks.get(&block_hash).await {
            Ok(Some(_)) => {
                info!(self.logger, "Offered block allready exists");
                Ok(Response::new(Confirmed {}))
            },
            Ok(None) => {
                info!(self.logger, "Offered block allready exists");
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
        info!(self.logger, "Recieved pull block request");
        let pull_request = request.into_inner();
        let block_hash = pull_request.msg_block_hash;
        let read_lock = self.blockchain.read().await;
        match read_lock.blocks.get(&block_hash).await {
            Ok(Some(block)) => {
                info!(self.logger, "Block was successfully sent to requester");
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
        let peers = DashMap::new();
        let block_db = sled::open("C:/Vector/blocks").map_err(|_| NodeServiceError::SledOpenError)?;
        info!(logger, "Block DB was created in C:/Vector/blocks");
        let output_db = sled::open("C:/Vector/outputs").map_err(|_| NodeServiceError::SledOpenError)?;
        info!(logger, "Output DB was created in C:/Vector/outputs");
        let image_db = sled::open("C:/Vector/images").map_err(|_| NodeServiceError::SledOpenError)?;
        info!(logger, "Image DB was created in C:/Vector/images");
        let ip_db = sled::open("C:/Vector/ips").map_err(|_| NodeServiceError::SledOpenError)?;
        // info!(logger, "Image DB was created in C:/Vector/ips");
        
        let blocks: Box<dyn BlockStorer> = Box::new(BlockDB::new(block_db));
        let outputs: Box<dyn OutputStorer> = Box::new(OutputDB::new(output_db));
        let images: Box<dyn ImageStorer> = Box::new(ImageDB::new(image_db));
        // let ips: Box<dyn PeerStorer> = Box::new(IpDB::new(ip_db));
        let ips: Arc<IpDB> = Arc::new(IpDB::new(ip_db));
        let mempool = Arc::new(Mempool::new());
        let blockchain = Chain::new(blocks, images, outputs)
            .await
            .map_err(|e| NodeServiceError::ChainCreationError(format!("{:?}", e)))?;
        let config = Arc::new(RwLock::new(server_cfg.clone()));
        info!(logger, "NodeService {} created", server_cfg.cfg_ip);
        Ok(NodeService {
            config,
            peers,
            logger,
            mempool,
            ips,
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
        info!(self.logger, "Server was set up successfully");
        if !ips_to_bootstrap.is_empty() {
            self.bootstrap_network(ips_to_bootstrap).await?;
        }
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.block_creation_loop().await
        });
        Ok(())
    }

    async fn block_creation_loop(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(120)).await;
            info!(self.logger, "Trying to create new block");
            self.make_block().await.unwrap();
        }
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
        for ip in ips {
            info!(self.logger, "Trying to bootstrap with {:?}", ip);
            let node_service_clone = self.clone();
            let ip_clone = ip.clone();
            let task = tokio::spawn(async move {
                match node_service_clone.dial_remote_node(&ip_clone).await {
                    Ok((c, v)) => {
                        node_service_clone.add_peer(c, v).await;
                        info!(node_service_clone.logger, "Successfully bootstraped with {:?}", ip);
                    }
                    Err(e) => {
                        error!(node_service_clone.logger, "Failed bootstrap and dial: {:?}", e);
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BootstrapNetworkError(format!("{:?}", err)))?;
        Ok(())
    }

    pub async fn contains(&self, addr: &str, connected_addrs: &[String]) -> bool {
        let wallet = {
            let server_config = self.config.read().await;
            server_config.cfg_wallet.clone()
        };
        if wallet.address == addr {
            return false;
        }
        connected_addrs.iter().any(|connected_addr| addr == connected_addr)
    }

    pub fn get_addr_list(&self) -> Vec<String> {
        self.peers
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub async fn dial_remote_node(&self, ip: &str) -> Result<(NodeClient<Channel>, Version), NodeServiceError> {
        info!(self.logger, "Trying to dial with {:?}", ip);
        let mut c = make_node_client(ip)
            .await?;
        info!(self.logger, "Node client {:?} created successfully, requesting version", ip);
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(NodeServiceError::HandshakeError)?
            .into_inner();
        info!(self.logger, "Dialed remote node: {}", ip);
        Ok((c, v))
    }

    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let remote_address = v.msg_address.clone();
        if !self.peers.contains_key(&remote_address) {
            self.peers.insert(remote_address.clone(), Arc::new(c.into()));
            info!(self.logger, "New validator peer added: {}", remote_address);
        } else {
            info!(self.logger, "Peer already exists: {}", remote_address);
        }
    }

    pub async fn get_version(&self) -> Version {
        info!(self.logger, "Version request");
        let (cfg_wallet, cfg_version, cfg_ip) = {
            let server_config = self.config.read().await;
            (server_config.cfg_wallet.clone(), server_config.cfg_version.clone(), server_config.cfg_ip.clone())
        };
        let msg_address = cfg_wallet.address;
        Version {
            msg_version: cfg_version,
            msg_address,
            msg_ip: cfg_ip,
        }
    }

    pub async fn make_block(&self) -> Result<(), NodeServiceError> {
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
        self.blockchain.write().await.add_block(block.clone()).await?;
        let hash_string = hex::encode(hash_header_by_block(&block)?);
        info!(self.logger, "New block {:?} was created and added to the chain", hash_string);
        let self_clone = self.clone();
        tokio::spawn(async move {
            match self_clone.broadcast_block_hash(hash_string).await {
                Ok(_) => info!(self_clone.logger, "Transaction hash broadcasted successfully"),
                Err(e) => error!(self_clone.logger, "Failed to broadcast transaction hash: {:?}", e),
            }
        });
        Ok(())
    }

    pub async fn broadcast_block_hash(&self, hash_string: String) -> Result<(), NodeServiceError> {
        info!(self.logger, "Broadcasting block hash {:?}", hash_string);
        let peers_data = self.peers
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
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
                        "Broadcast error: {:?}",
                        e
                    );
                } else {
                    info!(
                        self_clone.logger, 
                        "Broadcasted hash to: {:?}", 
                        addr
                    );
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|err| NodeServiceError::BroadcastTransactionError(format!("{:?}", err)))?;
        Ok(())
    }

    // Currently only one output to destination point
    pub async fn make_transaction(
        &self, 
        recipient_address: &str,
        a: u64
    ) -> Result<(), NodeServiceError> {
        let wallet = {
            let server_config = self.config.read().await;
            server_config.cfg_wallet.clone()
        };

        let (inputs, total_input_amount) = wallet.prepare_inputs().await;

        // Add a check for insufficient funds
        if total_input_amount < a {
            return Err(NodeServiceError::InsufficientBalance);
        }

        let mut outputs = Vec::new();
        if total_input_amount > a {
            let change = total_input_amount - a;
            let change = wallet.prepare_change_output(change, 2);
            outputs.push(change);
        }    
        let output = wallet.prepare_output(recipient_address, 1, a);
        outputs.push(output);
        let transaction = Transaction {
            msg_inputs: inputs,
            msg_outputs: outputs,
        };
        info!(self.logger, "Created transaction, trying to broadcast");
        let self_clone = self.clone();
        tokio::spawn(async move {
            match self_clone.broadcast_tx_hash(&transaction).await {
                Ok(_) => info!(self_clone.logger, "Transaction hash broadcasted successfully!"),
                Err(e) => error!(self_clone.logger, "Failed to broadcast transaction hash: {:?}", e),
            }
        });
        Ok(())
    }

    pub async fn broadcast_tx_hash(&self, transaction: &Transaction) -> Result<(), NodeServiceError> {
        let hash = hash_transaction(transaction).await;
        let hash_string = hex::encode(hash);
        info!(self.logger, "Broadcasting transaction hash {:?}", hash_string);
        let peers_data = self.peers
                    .iter()
                    .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
                    .collect::<Vec<_>>();
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
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
                        "Broadcast error: {:?}",
                        e
                    );
                } else {
                    info!(
                        self_clone.logger, 
                        "Broadcasted hash to: {:?}",
                        addr
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
            info!(self.logger, "Pulling new transaction from {:?}", sender_ip);
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
            self.blockchain.write().await.validate_transaction(&transaction).await?;
            info!(self.logger, "Recieved transaction was successfully validated");
            self.mempool.add(transaction.clone()).await;
            info!(self.logger, "And was added to the mempool, starting broadcasting");
            self.broadcast_tx_hash(&transaction).await?;
        }
        Ok(())
    }

    pub async fn pull_block_from(&self, sender_ip: &str, block_hash: &str) -> Result<(), NodeServiceError> {
        if let Some(client_arc_mutex) = self.peers.get(sender_ip) {
            info!(self.logger, "Pulling new block from {:?}", sender_ip);
            let client_arc = client_arc_mutex.clone();
            let mut client = client_arc.lock().await;
            let (my_ip, wallet) = {
                let server_config = self.config.read().await;
                (server_config.cfg_ip.to_string(), server_config.cfg_wallet.clone())
            };
            let message = PullBlockRequest {
                msg_block_hash: block_hash.to_string(),
                msg_ip: my_ip.to_string(),
            };
            let response = client.handle_block_pull(message).await?;
            let block = response.into_inner();
            self.process_incoming_block(&wallet, block).await?;
            self.broadcast_block_hash(block_hash.to_string()).await?;
        }
        Ok(())
    }

    pub async fn process_incoming_block_batch(&self, wallet: &Wallet, block_batch: BlockBatch) -> Result<(), NodeServiceError> {
        for block in block_batch.msg_blocks {
            self.process_incoming_block(wallet, block).await?;
        }
        Ok(())
    }

    pub async fn process_incoming_block(&self, wallet: &Wallet, block: Block) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.config.read().await;
            server_config.cfg_height
        };
        info!(self.logger, "Processing recieved block");
        if let Some(header) = block.clone().msg_header {
            for transaction in &block.msg_transactions {
                info!(self.logger, "Processing transactions");
                self.blockchain.write().await.process_transaction(wallet, transaction).await?;
            }
            let mut server_config = self.config.write().await;
            let incoming_height = header.msg_height as u64;
            if local_height < incoming_height {                           //&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
                server_config.cfg_height = incoming_height;
            }
            self.blockchain.write().await.add_block(block).await?;
            info!(self.logger, "New block was added");
            Ok(())
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn process_block(&self, wallet: &Wallet, block: Block, leader_address: &str) -> Result<(), NodeServiceError> {
        let local_height = {
            let server_config = self.config.read().await;
            server_config.cfg_height
        };
        info!(self.logger, "Processing block");
        if let Some(header) = block.msg_header.clone() {
            let incoming_height = header.msg_height as u64;
            if incoming_height == local_height + 1 {
                for transaction in &block.msg_transactions {
                    self.blockchain.write().await.process_transaction(wallet, &transaction).await?;
                }
                let mut server_config = self.config.write().await;
                server_config.cfg_height = incoming_height;
                self.blockchain.write().await.add_block(block).await?;
                info!(self.logger, "New block added");
                Ok(())
            } else {
                info!(self.logger, "You are not synchronized, starting synchronisation");
                match self.pull_state_from(wallet, leader_address.to_string()).await {
                    Ok(_) => Err(NodeServiceError::PullStateError),
                    Err(e) => Err(e),
                }
            }
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn pull_state_from(&self, wallet: &Wallet, ip: String) -> Result<(), NodeServiceError> {
        if !self.peers.contains_key(&ip) {
            info!(self.logger, "Provided ip was not found in peer list ({:?}), sending dial request", ip);
            match self.dial_remote_node(&ip).await {
                Ok((client, version)) => {
                    self.add_peer(client.clone(), version).await;
                    info!(self.logger, "Dial success, new peer added: {}", ip);
                    let client_arc = Arc::new(Mutex::new(client));
                    let mut client_lock = client_arc.lock().await;
                    self.pull_state_from_client(wallet, &mut client_lock).await?;
                },
                Err(e) => {
                    error!(self.logger, "Failed to dial remote node: {:?}", e);
                    return Err(NodeServiceError::ConnectionFailed);
                },
            }
        } else {
            let client = self.peers.get(&ip).ok_or(NodeServiceError::PeerNotFound)?.clone();
            let mut client_lock = client.lock().await;
            self.pull_state_from_client(wallet, &mut client_lock).await?;
        }
        Ok(())
    }       
    
    pub async fn pull_state_from_client(&self, wallet: &Wallet, client: &mut NodeClient<Channel>) -> Result<(), NodeServiceError> {
        let height = {
            let server_config = self.config.read().await;
            server_config.cfg_height
        };
        info!(self.logger, "Sending request with current state {:?}", height);
        let request = Request::new(LocalState { msg_last_block_height: height });
        let response = client.push_state(request).await?;
        let block_batch = response.into_inner();
        self.process_incoming_block_batch(wallet, block_batch).await?;
        info!(self.logger, "Pulled blocks from client");
        Ok(())
    }
    
    pub async fn broadcast_peer_list(&self) -> Result<(), ValidatorServiceError> {
        let wallet = {
            let server_config = self.config.read().await;
            server_config.cfg_wallet.clone()
        };
        info!(self.logger, "Broadcasting peer list");
        let my_addr = &wallet.address;
        let mut peers_addrs: Vec<String> = self.get_addr_list();
        peers_addrs.push(my_addr.clone());
        let msg = PeerList {
            msg_peers_addresses: peers_addrs,
        };
        let peers_data: Vec<_> = self.peers
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let my_addr_clone = my_addr.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if addr != my_addr_clone {
                    if let Err(err) = peer_client_lock.handle_peer_list(req).await {
                        error!(
                            self_clone.logger,
                            "Failed to broadcast peer list to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            self_clone.logger,
                            "Broadcasted peer list to {}",
                            addr
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|_| ValidatorServiceError::PeerBroadcastFailed)?;
        info!(self.logger, "Successfully broadcasted peer list");
        Ok(())
    }

    // CLI commands
    pub async fn make_genesis_block(&self) -> Result<(), NodeServiceError> {
        let wallet = {
            let server_config = self.config.read().await;
            server_config.cfg_wallet.clone()
        };
        let transactions = vec![self.make_genesis_transaction(100000).await?];
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
            msg_height: 0 as u32,
            msg_previous_hash: vec![],
            msg_root_hash: merkle_root,
            msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        let block = Block {
            msg_header: Some(header),
            msg_transactions: transactions,
        };
        self.blockchain.write().await.add_genesis_block(&wallet, block).await?;
        info!(self.logger, "Genesis block with 100000 successfully created and added to the chain");
        Ok(())
    }

    pub async fn make_genesis_transaction(&self, amount: u64) -> Result<Transaction, NodeServiceError> {
        let wallet = {
            let server_config = self.config.read().await;
            server_config.cfg_wallet.clone()
        };
        let output_index: u64 = 1; 
        // 1. Stealth address
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        // 1.1 Output key
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress(); // <-- output key
        let view_key_point = &wallet.public_view_key.decompress().unwrap();
        let q = r * view_key_point; // rKvt
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
            hasher.update(&q_bytes);
            hasher.update(&output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let spend_key_point = &wallet.public_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + spend_key_point).compress(); // <-- stealth addr
        // 2. Encrypted amount
        let encrypted_amount = wallet.encrypt_amount(&q_bytes, output_index, amount);
        let output = TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: vec![],
            msg_commitment: vec![],
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        };
        let transaction = Transaction {
            msg_inputs: vec![],
            msg_outputs: vec![output],
        };
        info!(self.logger, "Genesis transaction was successfully created");
        Ok(transaction)
    }
    
    pub async fn get_balance(&self) -> u64 {
        info!(self.logger, "Balance requested");
        let chain_lock = self.blockchain.read().await;
        chain_lock.get_balance().await
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