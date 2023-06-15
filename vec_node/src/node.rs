use bs58;
use curve25519_dalek_ng::{constants, scalar::Scalar};
use dashmap::DashMap;
use futures::future::try_join_all;
use prost::Message;
use sha3::{Digest, Keccak256};
use slog::{error, info, o, Drain, Logger};
use std::fs;
use std::time::SystemTime;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use tonic::{
    transport::{Channel, Server},
    Request, Response, Status,
};
use vec_chain::chain::Chain;
use vec_crypto::cryptography::Wallet;
use vec_errors::errors::*;
use vec_mempool::mempool::*;
use vec_merkle::merkle::MerkleTree;
use vec_proto::messages::*;
use vec_proto::messages::{
    node_client::NodeClient,
    node_server::{Node, NodeServer},
};
use vec_storage::{block_db::*, image_db::*, ip_db::*, output_db::*};
use vec_utils::utils::hash_transaction;
use vec_utils::utils::{hash_block, mine};

#[derive(Clone)]
pub struct NodeService {
    pub wallet: Arc<Wallet>,
    pub ip: Arc<String>,
    pub ip_store: Arc<Box<dyn IPStorer>>,
    pub version: u32,
    pub peers: Arc<DashMap<String, Arc<RwLock<NodeClient<Channel>>>>>,
    pub mempool: Arc<Mempool>,
    pub blockchain: Arc<RwLock<Chain>>,
    pub logger: Arc<Logger>,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(&self, request: Request<Version>) -> Result<Response<Version>, Status> {
        let version = request.into_inner();
        let vec_address = version.msg_address.clone();
        let bs58_address = bs58::encode(vec_address.clone()).into_string();
        let remote_ip = version.msg_ip.clone();
        info!(self.logger, "\nReceived version, address: {}", bs58_address);
        let connected_addrs = self.get_addr_list();
        if !self.contains(&bs58_address, &connected_addrs).await && self.peers.len() < 20 {
            let self_clone = self.clone();
            tokio::spawn(async move {
                match make_node_client(&remote_ip).await {
                    Ok(c) => {
                        info!(self_clone.logger, "\nCreated node client successfully");
                        match self_clone.add_peer(c, version.clone()).await {
                            Ok(_) => {
                                info!(self_clone.logger, "\nNew peer added");
                            }
                            Err(e) => {
                                error!(self_clone.logger, "Failed to add peer: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!(self_clone.logger, "\nFailed to create node client: {:?}", e);
                    }
                }
            });
        } else {
            match self.ip_store.get_by_address(&vec_address).await {
                Ok(Some(stored_ip)) => {
                    if stored_ip != remote_ip {
                        match self.ip_store.update(&vec_address, &remote_ip).await {
                            Ok(_) => {
                                info!(
                                    self.logger,
                                    "\nIP for peer {} updated to: {}", bs58_address, remote_ip
                                );
                            }
                            Err(e) => {
                                let status = Status::internal(format!("IPStorageError: {:?}", e));
                                return Err(status);
                            }
                        }
                    }
                }
                Ok(None) => match self.ip_store.put(vec_address, remote_ip).await {
                    Ok(_) => {
                        info!(self.logger, "\nIP was inserted for: {}", bs58_address);
                    }
                    Err(e) => {
                        let status = Status::internal(format!("IPStorageError: {:?}", e));
                        return Err(status);
                    }
                },
                Err(_) => return Err(Status::internal("Failed to update peer_list")),
            }
            info!(self.logger, "\nAddress already connected: {}", bs58_address);
        }
        let reply = self.get_version().await;

        Ok(Response::new(reply))
    }

    async fn push_state(
        &self,
        request: Request<LocalState>,
    ) -> Result<Response<BlockBatch>, Status> {
        let state = request.into_inner();
        let requester_index = state.msg_max_local_index;
        let mut blocks = Vec::new();
        let chain_rlock = self.blockchain.read().await;

        let max_index = chain_rlock
            .max_index()
            .await
            .map_err(|e| Status::internal(format!("Failed to get max index: {:?}", e)))?;

        for index in (requester_index + 1)..=max_index {
            match chain_rlock.blocks.get_by_index(index).await {
                Ok(Some(block)) => blocks.push(block),
                Ok(None) => {
                    return Err(Status::internal(format!("No block at height {}", index)));
                }
                Err(e) => {
                    return Err(Status::internal(format!(
                        "Failed to get block at height {}, {:?}",
                        index, e
                    )));
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
        let peer_addresses = peer_list.msg_peers_ips;
        match self.bootstrap_network(peer_addresses).await {
            Ok(_) => {
                info!(self.logger, "\nPeer list updated successfully");
                Ok(Response::new(Confirmed {}))
            }
            Err(e) => {
                error!(self.logger, "\nFailed to update peer_list: {:?}", e);
                Err(Status::internal("Failed to update peer_list"))
            }
        }
    }

    async fn handle_tx_push(
        &self,
        request: Request<PushTxRequest>,
    ) -> Result<Response<Confirmed>, Status> {
        let push_request = request.into_inner();
        let sender_ip = push_request.msg_ip.clone();
        let transaction_hash = push_request.msg_transaction_hash.clone();
        let bs58_hash = bs58::encode(&transaction_hash).into_string();

        if self.mempool.has_hash(&bs58_hash) {
            Ok(Response::new(Confirmed {}))
        } else {
            let self_clone = self.clone();
            tokio::spawn(async move {
                match self_clone
                    .pull_transaction_from(&sender_ip, transaction_hash)
                    .await
                {
                    Ok(_) => (),
                    Err(e) => {
                        error!(
                            self_clone.logger,
                            "Failed to make transaction pull: {:?}", e
                        );
                    }
                }
            });

            Ok(Response::new(Confirmed {}))
        }
    }

    async fn handle_tx_pull(
        &self,
        request: Request<PullTxRequest>,
    ) -> Result<Response<Transaction>, Status> {
        let pull_request = request.into_inner();
        let transaction_hash = pull_request.msg_transaction_hash;
        let bs58_hash = bs58::encode(transaction_hash).into_string();
        if !self.mempool.has_hash(&bs58_hash) {
            if let Some(transaction) = self.mempool.get_by_hash(&bs58_hash) {
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
        info!(self.logger, "\nReceived push block request");
        let push_request = request.into_inner();
        let sender_ip = push_request.msg_ip;
        let block_hash = push_request.msg_block_hash;
        let read_lock = self.blockchain.read().await;
        match read_lock.blocks.get(block_hash.clone()).await {
            Ok(Some(_)) => {
                info!(self.logger, "\nOffered block already exists");
                Ok(Response::new(Confirmed {}))
            }
            Ok(None) => {
                info!(self.logger, "\nOffered block doesn't exist, starting pull");
                let self_clone = self.clone();
                let sender_ip_clone = sender_ip.clone();
                let block_hash_clone = block_hash.clone();
                tokio::spawn(async move {
                    match self_clone
                        .pull_block_from(&sender_ip_clone, block_hash_clone)
                        .await
                    {
                        Ok(_) => info!(self_clone.logger, "\nBlock pull successful"),
                        Err(e) => {
                            error!(self_clone.logger, "\nFailed to make block pull: {:?}", e);
                        }
                    }
                });
                Ok(Response::new(Confirmed {}))
            }
            Err(e) => {
                error!(self.logger, "\nFailed to check if block exists: {:?}", e);
                Err(Status::internal("Failed to check if block exists"))
            }
        }
    }

    async fn handle_block_pull(
        &self,
        request: Request<PullBlockRequest>,
    ) -> Result<Response<Block>, Status> {
        info!(self.logger, "\nRecieved pull block request");
        let pull_request = request.into_inner();
        let block_hash = pull_request.msg_block_hash;
        let read_lock = self.blockchain.read().await;
        match read_lock.blocks.get(block_hash).await {
            Ok(Some(block)) => {
                info!(self.logger, "\nBlock was successfully sent to requester");
                Ok(Response::new(block))
            }
            Ok(None) => Err(Status::not_found("Block not found")),
            Err(e) => {
                error!(self.logger, "\nFailed to get block: {:?}", e);
                Err(Status::internal("Failed to get block"))
            }
        }
    }
}

impl NodeService {
    pub async fn new(secret_key: String, _ip: String) -> Result<Self, NodeServiceError> {
        let _logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        let logger = Arc::new(_logger);
        let ip = Arc::new(_ip);

        let vec_secret = string_to_vec(&secret_key);
        let secret_spend_key = Wallet::secret_spend_key_from_vec(&vec_secret)?;
        let wallet = Arc::new(Wallet::reconstruct(secret_spend_key)?);

        let version: u32 = 1;

        let peers = Arc::new(DashMap::new());

        let block_db =
            sled::open("C:/Vector/blocks_db").map_err(|_| NodeServiceError::SledOpenError)?;
        let index_db =
            sled::open("C:/Vector/index_db").map_err(|_| NodeServiceError::SledOpenError)?;
        let output_db =
            sled::open("C:/Vector/outputs").map_err(|_| NodeServiceError::SledOpenError)?;
        let image_db =
            sled::open("C:/Vector/images").map_err(|_| NodeServiceError::SledOpenError)?;
        let ip_db = sled::open("C:/Vector/ips").map_err(|_| NodeServiceError::SledOpenError)?;

        let blocks: Box<dyn BlockStorer> = Box::new(BlockDB::new(block_db, index_db));
        let outputs: Box<dyn OutputStorer> = Box::new(OutputDB::new(output_db));
        let images: Box<dyn ImageStorer> = Box::new(ImageDB::new(image_db));
        let _blockchain = Chain::new(blocks, images, outputs)
            .await
            .map_err(|e| NodeServiceError::ChainCreationError(format!("{:?}", e)))?;
        let blockchain = Arc::new(RwLock::new(_blockchain));

        let _ip_store: Box<dyn IPStorer> = Box::new(IPDB::new(ip_db));
        let ip_store = Arc::new(_ip_store);

        let mempool = Arc::new(Mempool::new());

        info!(logger, "\nNodeService created");

        Ok(NodeService {
            wallet,
            ip,
            ip_store,
            version,
            peers,
            logger,
            mempool,
            blockchain,
        })
    }

    pub async fn start(&mut self) -> Result<(), NodeServiceError> {
        let node_service = self.clone();
        let ip = self.ip.parse().map_err(NodeServiceError::AddrParseError)?;
        info!(self.logger, "\nNodeServer starting listening on {}", ip);
        self.setup_server(node_service, ip).await?;

        Ok(())
    }

    pub async fn setup_server(
        &self,
        node_service: NodeService,
        cfg_ip: SocketAddr,
    ) -> Result<(), NodeServiceError> {
        Server::builder()
            .accept_http1(true)
            .add_service(NodeServer::new(node_service))
            .serve(cfg_ip)
            .await
            .map_err(NodeServiceError::TonicTransportError)
    }

    pub async fn bootstrap_network(&self, ips: Vec<String>) -> Result<(), NodeServiceError> {
        let mut tasks = Vec::new();
        for ip in ips {
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                match self_clone.dial_remote_node(&ip).await {
                    Ok((c, v)) => {
                        match self_clone.add_peer(c, v).await {
                            Ok(_) => {
                                info!(self_clone.logger, "\nNew peer added");
                            }
                            Err(e) => {
                                error!(self_clone.logger, "Failed to add peer: {:?}", e);
                            }
                        }
                        info!(
                            self_clone.logger,
                            "\nSuccessfully bootstraped with {:?}", ip
                        );
                    }
                    Err(e) => {
                        error!(self_clone.logger, "\nFailed bootstrap and dial: {:?}", e);
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks)
            .await
            .map_err(|err| NodeServiceError::BootstrapNetworkError(format!("{:?}", err)))?;

        Ok(())
    }

    pub async fn contains(&self, addr: &str, connected_addrs: &[String]) -> bool {
        if bs58::encode(&self.wallet.address).into_string() == addr {
            return false;
        }
        connected_addrs
            .iter()
            .any(|connected_addr| addr == connected_addr)
    }

    pub fn get_addr_list(&self) -> Vec<String> {
        self.peers.iter().map(|entry| entry.key().clone()).collect()
    }

    pub async fn dial_remote_node(
        &self,
        ip: &str,
    ) -> Result<(NodeClient<Channel>, Version), NodeServiceError> {
        let chain_rlock = self.blockchain.read().await;
        let local_index = match chain_rlock.max_index().await {
            Ok(index) => index,
            Err(_) => return Err(NodeServiceError::FailedToGetIndex),
        };
        drop(chain_rlock);
        let mut c = make_node_client(ip).await?;
        info!(
            self.logger,
            "\nNode client {:?} created successfully, requesting version", ip
        );
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(NodeServiceError::HandshakeError)?
            .into_inner();
        if v.msg_max_local_index > local_index {
            self.synchronize_with_client(&self.wallet, &mut c).await?;
            Ok((c, v))
        } else if v.msg_max_local_index < local_index {
            Err(NodeServiceError::LaggingNode)
        } else {
            info!(self.logger, "\nDialed remote node: {}", ip);
            Ok((c, v))
        }
    }

    pub async fn add_peer(
        &self,
        c: NodeClient<Channel>,
        v: Version,
    ) -> Result<(), NodeServiceError> {
        let vec_address = v.msg_address.clone();
        let bs58_address = bs58::encode(vec_address.clone()).into_string();
        let remote_ip = v.msg_ip.clone();

        if !self.peers.contains_key(&bs58_address) {
            self.ip_store
                .put(vec_address.clone(), remote_ip.clone())
                .await?;
            self.peers.insert(bs58_address.clone(), Arc::new(c.into()));
            info!(self.logger, "\nNew peer added: {}", bs58_address);
        } else {
            // Check if the IP is the same as the stored one
            match self.ip_store.get_by_address(&vec_address).await {
                Ok(Some(stored_ip)) => {
                    if stored_ip != remote_ip {
                        self.ip_store.update(&vec_address, &remote_ip).await?;
                        info!(
                            self.logger,
                            "\nIP for peer {} updated to: {}", bs58_address, remote_ip
                        );
                    }
                }
                Ok(None) => {
                    self.ip_store.put(vec_address, remote_ip).await?;
                }
                Err(_) => return Err(IPStorageError::ReadError)?,
            }
            info!(self.logger, "\nPeer already exists: {}", bs58_address);
        }
        Ok(())
    }

    pub async fn get_version(&self) -> Version {
        let ip = &self.ip;
        let msg_version = self.version;
        let chain_rlock = self.blockchain.read().await;
        let local_index = chain_rlock.max_index().await.unwrap();
        drop(chain_rlock);
        let address = &self.wallet.address;

        Version {
            msg_version,
            msg_address: address.clone(),
            msg_ip: ip.to_string(),
            msg_max_local_index: local_index,
        }
    }

    pub async fn make_block(&self) -> Result<(), NodeServiceError> {
        let chain_rlock = self.blockchain.read().await;
        let msg_previous_hash = chain_rlock.get_previous_hash_in_chain().await?;
        let local_index = match chain_rlock.max_index().await {
            Ok(index) => index,
            Err(_) => return Err(NodeServiceError::FailedToGetIndex),
        };
        let msg_index = local_index + 1;
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
            msg_index,
            msg_previous_hash,
            msg_root_hash: merkle_root,
            msg_timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs(),
            msg_nonce: 0,
        };
        let mut block = Block {
            msg_header: Some(header.clone()),
            msg_transactions: transactions,
        };
        drop(chain_rlock);
        let nonce = mine(block.clone())?;
        block.msg_header.as_mut().unwrap().msg_nonce = nonce;
        let mut chain_wlock = self.blockchain.write().await;
        chain_wlock.add_block(&self.wallet, block.clone()).await?;
        drop(chain_wlock);
        let bs58_hash = bs58::encode(hash_block(&block)?).into_string();
        info!(
            self.logger,
            "\nGenesis block {:?} with tx successfully created", bs58_hash
        );

        Ok(())
    }

    pub async fn broadcast_block_hash(&self, hash: Vec<u8>) -> Result<(), NodeServiceError> {
        if self.peers.is_empty() {
            return Err(NodeServiceError::NoRecipient);
        }
        info!(
            self.logger,
            "\nBroadcasting block hash {:?}",
            bs58::encode(&hash).into_string()
        );
        let peers_data = self
            .peers
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();

        for (addr, peer_client) in peers_data {
            let hash_clone = hash.clone();
            let ip = Arc::clone(&self.ip);
            let logger = Arc::clone(&self.logger);
            tokio::spawn(async move {
                let mut peer_client_lock = peer_client.write().await;
                let message = PushBlockRequest {
                    msg_block_hash: hash_clone,
                    msg_ip: ip.to_string(),
                };
                if let Err(e) = peer_client_lock.handle_block_push(message).await {
                    error!(logger.as_ref(), "\nBroadcast error: {:?}", e);
                } else {
                    info!(logger.as_ref(), "\nBroadcasted hash to: {:?}", addr);
                }
            });
        }

        Ok(())
    }

    pub async fn make_transaction(
        &self,
        recipient_address: &str,
        amount: u64,
        contract_path: Option<&str>,
    ) -> Result<(), NodeServiceError> {
        let (inputs, total_input_amount) = self
            .blockchain
            .write()
            .await
            .prepare_inputs(&self.wallet)
            .await?;
        if total_input_amount < amount {
            return Err(NodeServiceError::InsufficientBalance);
        }
        let mut outputs = Vec::new();
        if total_input_amount > amount {
            let change = total_input_amount - amount;
            let change =
                self.blockchain
                    .write()
                    .await
                    .prepare_change_output(&self.wallet, change, 2)?;
            outputs.push(change);
        }
        let output = self.blockchain.write().await.prepare_output(
            &self.wallet,
            recipient_address,
            1,
            amount,
        )?;
        outputs.push(output);

        let contract_code = match contract_path {
            Some(path) => {
                let code = fs::read(path).map_err(|_| NodeServiceError::ReadContractError)?;
                Some(Contract { msg_code: code })
            }
            None => None,
        };

        let transaction = Transaction {
            msg_inputs: inputs,
            msg_outputs: outputs,
            msg_contract: contract_code,
        };

        self.mempool.add(transaction.clone());
        info!(self.logger, "\nCreated transaction, trying to broadcast");

        self.broadcast_tx_hash(&transaction).await?;

        Ok(())
    }

    pub async fn broadcast_tx_hash(
        &self,
        transaction: &Transaction,
    ) -> Result<(), NodeServiceError> {
        let hash = hash_transaction(transaction);
        info!(
            self.logger,
            "\nBroadcasting transaction hash {:?}",
            bs58::encode(&hash).into_string()
        );
        let peers_data = self
            .peers
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect::<Vec<_>>();
        if peers_data.is_empty() {
            return Err(NodeServiceError::NoRecipient);
        }

        for (addr, peer_client) in peers_data {
            let hash_clone = hash.clone();
            let ip = Arc::clone(&self.ip);
            let logger = Arc::clone(&self.logger);
            tokio::spawn(async move {
                let mut peer_client_lock = peer_client.write().await;
                let message = PushTxRequest {
                    msg_transaction_hash: hash_clone,
                    msg_ip: ip.to_string(),
                };
                if let Err(e) = peer_client_lock.handle_tx_push(message).await {
                    error!(logger, "\nBroadcast error: {:?}", e);
                } else {
                    info!(logger, "\nBroadcasted hash to: {:?}", addr);
                }
            });
        }

        Ok(())
    }

    pub async fn pull_transaction_from(
        &self,
        sender_ip: &str,
        transaction_hash: Vec<u8>,
    ) -> Result<(), NodeServiceError> {
        if let Some(client_arc_mutex) = self.peers.get(sender_ip) {
            info!(
                self.logger,
                "\nPulling new transaction from {:?}", sender_ip
            );
            let client_arc = client_arc_mutex.clone();
            let mut client = client_arc.write().await;
            let ip = &self.ip;
            let message = PullTxRequest {
                msg_transaction_hash: transaction_hash,
                msg_ip: ip.to_string(),
            };
            let response = client.handle_tx_pull(message).await?;
            let transaction = response.into_inner();
            self.blockchain
                .write()
                .await
                .validate_transaction(&transaction)
                .await?;
            info!(
                self.logger,
                "\nRecieved transaction was successfully validated"
            );
            self.mempool.add(transaction.clone());
            self.broadcast_tx_hash(&transaction).await?;
        }

        Ok(())
    }

    pub async fn pull_block_from(
        &self,
        sender_ip: &str,
        block_hash: Vec<u8>,
    ) -> Result<(), NodeServiceError> {
        if let Some(client_arc_mutex) = self.peers.get(sender_ip) {
            info!(self.logger, "\nPulling new block from {:?}", sender_ip);
            let ip = &self.ip;
            let client_arc = client_arc_mutex.clone();
            let mut client = client_arc.write().await;
            let message = PullBlockRequest {
                msg_block_hash: block_hash.clone(),
                msg_ip: ip.to_string(),
            };
            let response = client.handle_block_pull(message).await?;
            let block = response.into_inner();
            self.process_block(&self.wallet, block, &self.ip).await?;
            self.broadcast_block_hash(block_hash).await?;
        }

        Ok(())
    }

    pub async fn process_synchronisation(
        &self,
        wallet: &Wallet,
        block_batch: BlockBatch,
    ) -> Result<(), NodeServiceError> {
        for block in block_batch.msg_blocks {
            for transaction in &block.msg_transactions {
                self.blockchain
                    .write()
                    .await
                    .process_transaction(wallet, transaction)
                    .await?;
            }
            self.blockchain
                .write()
                .await
                .add_block(wallet, block)
                .await?;
            info!(self.logger, "\nNew block added");
        }

        Ok(())
    }

    pub async fn process_block(
        &self,
        wallet: &Wallet,
        block: Block,
        sender_ip: &str,
    ) -> Result<(), NodeServiceError> {
        let chain_rlock = self.blockchain.read().await;
        let local_index = chain_rlock.max_index().await.unwrap();
        drop(chain_rlock);
        info!(self.logger, "\nProcessing block");
        if let Some(header) = &block.msg_header {
            if header.msg_index < local_index {
                Err(NodeServiceError::BlockIndexTooLow)
            } else if header.msg_index == local_index + 1 {
                for transaction in &block.msg_transactions {
                    self.blockchain
                        .write()
                        .await
                        .process_transaction(wallet, transaction)
                        .await?;
                }
                self.blockchain
                    .write()
                    .await
                    .add_block(wallet, block)
                    .await?;
                info!(self.logger, "\nNew block added");
                Ok(())
            } else {
                info!(
                    self.logger,
                    "\nYou are not synchronized, starting synchronisation"
                );
                match self.pull_blocks_from(wallet, sender_ip.to_string()).await {
                    Ok(_) => Err(NodeServiceError::PullStateError),
                    Err(e) => Err(e),
                }
            }
        } else {
            Err(BlockOpsError::MissingHeader)?
        }
    }

    pub async fn pull_blocks_from(
        &self,
        wallet: &Wallet,
        ip: String,
    ) -> Result<(), NodeServiceError> {
        if !self.peers.contains_key(&ip) {
            info!(
                self.logger,
                "\nProvided ip was not found in peer list ({:?}), sending dial request", ip
            );
            match self.dial_remote_node(&ip).await {
                Ok((client, version)) => {
                    match self.add_peer(client.clone(), version).await {
                        Ok(_) => {
                            info!(self.logger, "\nNew peer added");
                        }
                        Err(e) => {
                            error!(self.logger, "Failed to add peer: {:?}", e);
                        }
                    }
                    info!(self.logger, "\nDial success, new peer added: {}", ip);
                    let client_arc = Arc::new(Mutex::new(client));
                    let mut client_lock = client_arc.lock().await;
                    self.synchronize_with_client(wallet, &mut client_lock)
                        .await?;
                }
                Err(e) => {
                    error!(self.logger, "\nFailed to dial remote node: {:?}", e);
                    return Err(NodeServiceError::ConnectionFailed);
                }
            }
        } else {
            let client = self
                .peers
                .get(&ip)
                .ok_or(NodeServiceError::PeerNotFound)?
                .clone();
            let mut client_lock = client.write().await;
            self.synchronize_with_client(wallet, &mut client_lock)
                .await?;
            drop(client_lock);
        }

        Ok(())
    }

    pub async fn synchronize_with_client(
        &self,
        wallet: &Wallet,
        client: &mut NodeClient<Channel>,
    ) -> Result<(), NodeServiceError> {
        let chain_rlock = self.blockchain.read().await;
        let msg_max_local_index = chain_rlock.max_index().await.unwrap();
        drop(chain_rlock);
        info!(
            self.logger,
            "\nSending request with current index {:?}", msg_max_local_index
        );
        let request = Request::new(LocalState {
            msg_max_local_index,
        });
        let response = client.push_state(request).await?;
        let block_batch = response.into_inner();
        self.process_synchronisation(wallet, block_batch).await?;
        info!(self.logger, "\nPulled and processed blocks from client");

        Ok(())
    }

    pub async fn broadcast_peer_list(&self) -> Result<(), NodeServiceError> {
        info!(self.logger, "\nBroadcasting peer list");
        let my_addr = bs58::encode(&self.wallet.address).into_string();
        let mut peers_addrs: Vec<String> = self.get_addr_list();
        peers_addrs.push(my_addr.clone());
        let msg = PeerList {
            msg_peers_ips: peers_addrs,
        };
        let peers_data: Vec<_> = self
            .peers
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        for (addr, peer_client) in peers_data {
            let msg_clone = msg.clone();
            let logger = Arc::clone(&self.logger);
            let my_addr_clone = my_addr.clone();
            tokio::spawn(async move {
                let mut peer_client_lock = peer_client.write().await;
                let req = Request::new(msg_clone);
                if addr != my_addr_clone {
                    if let Err(e) = peer_client_lock.handle_peer_list(req).await {
                        error!(
                            logger,
                            "\nFailed to broadcast peer list to {}: {:?}", addr, e
                        );
                    } else {
                        info!(logger, "\nBroadcasted peer list to {}", addr);
                    }
                }
            });
        }

        Ok(())
    }

    // CLI commands
    pub async fn make_genesis_block(&self) -> Result<(), NodeServiceError> {
        let chain_rlock = self.blockchain.read().await;
        if chain_rlock.max_index().await? != 0 {
            return Err(NodeServiceError::ChainIsNotEmpty);
        }
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
            msg_index: 1_u64,
            msg_previous_hash: vec![],
            msg_root_hash: merkle_root,
            msg_timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("\nTime went backwards")
                .as_secs(),
            msg_nonce: 0,
        };
        let mut block = Block {
            msg_header: Some(header.clone()),
            msg_transactions: transactions,
        };
        drop(chain_rlock);
        let nonce = mine(block.clone())?;
        block.msg_header.as_mut().unwrap().msg_nonce = nonce;
        let mut chain_wlock = self.blockchain.write().await;
        chain_wlock
            .add_genesis_block(&self.wallet, block.clone())
            .await?;
        drop(chain_wlock);
        let bs58_hash = bs58::encode(hash_block(&block)?).into_string();
        info!(
            self.logger,
            "\nGenesis block {:?} with tx successfully created", bs58_hash
        );

        Ok(())
    }

    pub async fn make_genesis_transaction(
        &self,
        amount: u64,
    ) -> Result<Transaction, NodeServiceError> {
        let output_index: u64 = 1;
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let view_key_point = &self.wallet.public_view_key.decompress().unwrap();
        let q = r * view_key_point;
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let spend_key_point = &self.wallet.public_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + spend_key_point).compress();
        let encrypted_amount = self.wallet.encrypt_amount(&q_bytes, output_index, amount)?;
        let output = TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: vec![],
            msg_commitment: vec![],
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        };
        let contract = Contract::default();
        let transaction = Transaction {
            msg_inputs: vec![],
            msg_outputs: vec![output],
            msg_contract: Some(contract),
        };

        Ok(transaction)
    }

    pub async fn get_balance(&self) -> u64 {
        let chain_lock = self.blockchain.read().await;
        chain_lock.get_balance().await
    }

    pub async fn connect_to(&self, ip: String) -> Result<(), NodeServiceError> {
        info!(self.logger, "\nTrying to connect with {:?}", ip);

        match self.dial_remote_node(&ip).await {
            Ok((c, v)) => {
                match self.add_peer(c, v).await {
                    Ok(_) => {
                        info!(self.logger, "\nNew peer added");
                    }
                    Err(e) => {
                        error!(self.logger, "Failed to add peer: {:?}", e);
                    }
                }
                info!(self.logger, "\nSuccessfully bootstraped with {:?}", ip);
            }
            Err(e) => {
                error!(self.logger, "\nFailed to bootstrap and dial: {:?}", e);
            }
        }

        Ok(())
    }

    pub async fn get_address(&self) -> Result<String, NodeServiceError> {
        let address = bs58::encode(&self.wallet.address).into_string();

        Ok(address)
    }

    pub async fn get_last_index(&self) -> Result<u64, NodeServiceError> {
        let chain_lock = self.blockchain.read().await;
        let height = chain_lock.max_index().await.unwrap();

        Ok(height)
    }
}

pub async fn make_node_client(ip: &str) -> Result<NodeClient<Channel>, NodeServiceError> {
    let uri = format!("http://{}", ip)
        .parse()
        .map_err(NodeServiceError::UriParseError)?;
    let channel = Channel::builder(uri)
        .connect()
        .await
        .map_err(NodeServiceError::TonicTransportError)?;
    let node_client = NodeClient::new(channel);

    Ok(node_client)
}

pub fn string_to_vec(string: &str) -> Vec<u8> {
    bs58::decode(string).into_vec().unwrap()
}

pub async fn shutdown(
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
) -> Result<(), NodeServiceError> {
    shutdown_tx
        .send(())
        .map_err(|_| NodeServiceError::ShutdownError)
}
