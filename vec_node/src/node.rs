use bs58;
use curve25519_dalek_ng::{constants, scalar::Scalar};
use dashmap::DashMap;
use futures::future::try_join_all;
use prost::Message;
use sha3::{Digest, Keccak256};
use slog::{error, info, o, Drain, Logger};
use std::cmp::Ordering;
use std::fs;
use std::time::SystemTime;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{Mutex, RwLock};
use tonic::{
    transport::{Channel, Server},
    Request, Response, Status,
};
use vec_chain::chain::*;
use vec_crypto::crypto::Wallet;
use vec_errors::errors::*;
use vec_macros::hash;
use vec_mempool::mempool::*;
use vec_merkle::merkle::MerkleTree;
use vec_proto::messages::*;
use vec_proto::messages::{
    node_client::NodeClient,
    node_server::{Node, NodeServer},
};
use vec_storage::block_db::BlockStorer;
use vec_storage::ip_db::IPStorer;
use vec_storage::lazy_traits::{BLOCK_STORER, IP_STORER};
use vec_utils::utils::hash_transaction;
use vec_utils::utils::{hash_block, mine};

const VERSION: u8 = 1;

#[derive(Clone)]
pub struct NodeService {
    pub wallet: Arc<Wallet>,
    pub ip: Arc<String>,
    pub peers: DashMap<String, Arc<RwLock<NodeClient<Channel>>>>,
    pub mempool: Arc<Mempool>,
    pub log: Arc<Logger>,
}

pub struct ArcNodeService {
    pub ns: Arc<NodeService>,
}

#[tonic::async_trait]
impl Node for ArcNodeService {
    async fn handshake(&self, request: Request<Version>) -> Result<Response<Version>, Status> {
        let version = request.into_inner();
        let vec_address = version.msg_address.clone();
        let bs58_address = bs58::encode(vec_address.clone()).into_string();
        let remote_ip = version.msg_ip.clone();
        info!(self.ns.log, "\nReceived version, address: {}", bs58_address);
        let connected_addrs = self.ns.get_addr_list();
        if !self.ns.contains(&bs58_address, &connected_addrs).await && self.ns.peers.len() < 20 {
            let ns_arc = Arc::clone(&self.ns);
            tokio::spawn(async move {
                match make_node_client(&remote_ip).await {
                    Ok(c) => {
                        info!(ns_arc.log, "\nCreated node client successfully");
                        match ns_arc.add_peer(c, version.clone()).await {
                            Ok(_) => {
                                info!(ns_arc.log, "\nNew peer added");
                            }
                            Err(e) => {
                                error!(ns_arc.log, "Failed to add peer: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!(ns_arc.log, "\nFailed to create node client: {:?}", e);
                    }
                }
            });
        } else {
            match IP_STORER.get_by_address(&vec_address).await {
                Ok(Some(stored_ip)) => {
                    if stored_ip != remote_ip {
                        match IP_STORER.update(&vec_address, &remote_ip).await {
                            Ok(_) => {
                                info!(
                                    self.ns.log,
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
                Ok(None) => match IP_STORER.put(vec_address, remote_ip).await {
                    Ok(_) => {
                        info!(self.ns.log, "\nIP was inserted for: {}", bs58_address);
                    }
                    Err(e) => {
                        let status = Status::internal(format!("IPStorageError: {:?}", e));
                        return Err(status);
                    }
                },
                Err(_) => return Err(Status::internal("Failed to update peer_list")),
            }
            info!(self.ns.log, "\nAddress already connected: {}", bs58_address);
        }
        let reply = self.ns.get_version().await;

        Ok(Response::new(reply))
    }

    async fn push_state(
        &self,
        request: Request<LocalState>,
    ) -> Result<Response<BlockBatch>, Status> {
        let state = request.into_inner();
        let requester_index = state.msg_local_index;
        let mut blocks = Vec::new();

        let max_index = max_index()
            .await
            .map_err(|e| Status::internal(format!("Failed to get max index: {:?}", e)))?;

        for index in (requester_index + 1)..=max_index {
            match BLOCK_STORER.get_by_index(index).await {
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
        match bootstrap_network(self, peer_addresses).await {
            Ok(_) => {
                info!(self.ns.log, "\nPeer list updated successfully");
                Ok(Response::new(Confirmed {}))
            }
            Err(e) => {
                error!(self.ns.log, "\nFailed to update peer_list: {:?}", e);
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
        let transaction_hash = push_request.msg_transaction_hash;
        let bs58_hash = bs58::encode(&transaction_hash).into_string();

        if self.ns.mempool.has_hash(&bs58_hash) {
            Ok(Response::new(Confirmed {}))
        } else {
            let ns_arc = Arc::clone(&self.ns);
            tokio::spawn(async move {
                match ns_arc
                    .pull_transaction_from(&sender_ip, transaction_hash)
                    .await
                {
                    Ok(_) => (),
                    Err(e) => {
                        error!(ns_arc.log, "Failed to make transaction pull: {:?}", e);
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
        if !self.ns.mempool.has_hash(&bs58_hash) {
            if let Some(transaction) = self.ns.mempool.get_by_hash(&bs58_hash) {
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
        info!(self.ns.log, "\nReceived push block request");
        let push_request = request.into_inner();
        let sender_ip = push_request.msg_ip;
        let block_hash = push_request.msg_block_hash;
        match BLOCK_STORER.get(block_hash.clone()).await {
            Ok(Some(_)) => {
                info!(self.ns.log, "\nOffered block already exists");
                Ok(Response::new(Confirmed {}))
            }
            Ok(None) => {
                info!(self.ns.log, "\nOffered block doesn't exist, starting pull");
                let ns_arc = Arc::clone(&self.ns);
                let sender_ip_clone = sender_ip.clone();
                let block_hash_clone = block_hash.clone();
                tokio::spawn(async move {
                    match ns_arc
                        .pull_block_from(&sender_ip_clone, block_hash_clone)
                        .await
                    {
                        Ok(_) => info!(ns_arc.log, "\nBlock pull successful"),
                        Err(e) => {
                            error!(ns_arc.log, "\nFailed to make block pull: {:?}", e);
                        }
                    }
                });
                Ok(Response::new(Confirmed {}))
            }
            Err(e) => {
                error!(self.ns.log, "\nFailed to check if block exists: {:?}", e);
                Err(Status::internal("Failed to check if block exists"))
            }
        }
    }

    async fn handle_block_pull(
        &self,
        request: Request<PullBlockRequest>,
    ) -> Result<Response<Block>, Status> {
        info!(self.ns.log, "\nRecieved pull block request");
        let pull_request = request.into_inner();
        let block_hash = pull_request.msg_block_hash;
        match BLOCK_STORER.get(block_hash).await {
            Ok(Some(block)) => {
                info!(self.ns.log, "\nBlock was successfully sent to requester");
                Ok(Response::new(block))
            }
            Ok(None) => Err(Status::not_found("Block not found")),
            Err(e) => {
                error!(self.ns.log, "\nFailed to get block: {:?}", e);
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
        let log = Arc::new(_logger);
        let ip = Arc::new(_ip);

        let vec_secret = string_to_vec(&secret_key);
        let secret_spend_key = Wallet::secret_spend_key_from_vec(&vec_secret)?;
        let wallet = Arc::new(Wallet::reconstruct(secret_spend_key)?);

        let peers = DashMap::new();

        let mempool = Arc::new(Mempool::new());

        info!(log, "\nNodeService created");

        Ok(NodeService {
            wallet,
            ip,
            peers,
            log,
            mempool,
        })
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
        let local_index = match max_index().await {
            Ok(index) => index,
            Err(_) => return Err(NodeServiceError::FailedToGetIndex),
        };
        let mut c = make_node_client(ip).await?;
        info!(
            self.log,
            "\nNode client {:?} created successfully, requesting version", ip
        );
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(NodeServiceError::HandshakeError)?
            .into_inner();

        match v.msg_local_index.cmp(&local_index) {
            Ordering::Greater => {
                self.synchronize_with_client(&self.wallet, &mut c).await?;
                Ok((c, v))
            }
            Ordering::Less => Err(NodeServiceError::LaggingNode),
            Ordering::Equal => {
                info!(self.log, "\nDialed remote node: {}", ip);
                Ok((c, v))
            }
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
            IP_STORER
                .put(vec_address.clone(), remote_ip.clone())
                .await?;
            self.peers.insert(bs58_address.clone(), Arc::new(c.into()));
            info!(self.log, "\nNew peer added: {}", bs58_address);
        } else {
            match IP_STORER.get_by_address(&vec_address).await {
                Ok(Some(stored_ip)) => {
                    if stored_ip != remote_ip {
                        IP_STORER.update(&vec_address, &remote_ip).await?;
                        info!(
                            self.log,
                            "\nIP for peer {} updated to: {}", bs58_address, remote_ip
                        );
                    }
                }
                Ok(None) => {
                    IP_STORER.put(vec_address, remote_ip).await?;
                }
                Err(_) => return Err(IPStorageError::ReadError)?,
            }
            info!(self.log, "\nPeer already exists: {}", bs58_address);
        }
        Ok(())
    }

    pub async fn get_version(&self) -> Version {
        let ip = &self.ip;
        let msg_version = VERSION as u32;
        let local_index = max_index().await.unwrap();
        let address = &self.wallet.address;

        Version {
            msg_version,
            msg_address: address.to_vec(),
            msg_ip: ip.to_string(),
            msg_local_index: local_index,
        }
    }

    pub async fn make_block(&self) -> Result<(), NodeServiceError> {
        let msg_previous_hash = get_previous_hash_in_chain().await?;
        let local_index = match max_index().await {
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
        let nonce = mine(block.clone())?;
        block.msg_header.as_mut().unwrap().msg_nonce = nonce;
        add_block(&self.wallet, block.clone()).await?;
        let bs58_hash = bs58::encode(hash_block(&block)?).into_string();
        info!(
            self.log,
            "\nGenesis block {:?} with tx successfully created", bs58_hash
        );

        Ok(())
    }

    pub async fn broadcast_block_hash(&self, hash: Vec<u8>) -> Result<(), NodeServiceError> {
        if self.peers.is_empty() {
            return Err(NodeServiceError::NoRecipient);
        }
        info!(
            self.log,
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
            let log = Arc::clone(&self.log);
            tokio::spawn(async move {
                let mut peer_client_lock = peer_client.write().await;
                let message = PushBlockRequest {
                    msg_block_hash: hash_clone,
                    msg_ip: ip.to_string(),
                };
                if let Err(e) = peer_client_lock.handle_block_push(message).await {
                    error!(log.as_ref(), "\nBroadcast error: {:?}", e);
                } else {
                    info!(log.as_ref(), "\nBroadcasted hash to: {:?}", addr);
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
        let wallet = &self.wallet;
        let (inputs, total_input_amount) = wallet.prepare_inputs().await?;
        if total_input_amount < amount {
            return Err(NodeServiceError::InsufficientBalance);
        }
        let mut outputs = Vec::new();
        if total_input_amount > amount {
            let change = total_input_amount - amount;
            let change = wallet.prepare_change_output(change, 2)?;
            outputs.push(change);
        }
        let output = wallet.prepare_output(recipient_address, 1, amount)?;
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
        info!(self.log, "\nCreated transaction, trying to broadcast");

        self.broadcast_tx_hash(&transaction).await?;

        Ok(())
    }

    pub async fn broadcast_tx_hash(
        &self,
        transaction: &Transaction,
    ) -> Result<(), NodeServiceError> {
        let hash = hash_transaction(transaction);
        info!(
            self.log,
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
            let log = Arc::clone(&self.log);
            tokio::spawn(async move {
                let mut peer_client_lock = peer_client.write().await;
                let message = PushTxRequest {
                    msg_transaction_hash: hash_clone,
                    msg_ip: ip.to_string(),
                };
                if let Err(e) = peer_client_lock.handle_tx_push(message).await {
                    error!(log, "\nBroadcast error: {:?}", e);
                } else {
                    info!(log, "\nBroadcasted hash to: {:?}", addr);
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
            info!(self.log, "\nPulling new transaction from {:?}", sender_ip);
            let client_arc = client_arc_mutex.clone();
            let mut client = client_arc.write().await;
            let ip = &self.ip;
            let message = PullTxRequest {
                msg_transaction_hash: transaction_hash,
                msg_ip: ip.to_string(),
            };
            let response = client.handle_tx_pull(message).await?;
            let transaction = response.into_inner();
            validate_transaction(&transaction).await?;
            info!(
                self.log,
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
            info!(self.log, "\nPulling new block from {:?}", sender_ip);
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
                wallet.process_transaction(transaction).await?;
            }
            add_block(wallet, block).await?;
            info!(self.log, "\nNew block added");
        }

        Ok(())
    }

    pub async fn process_block(
        &self,
        wallet: &Wallet,
        block: Block,
        sender_ip: &str,
    ) -> Result<(), NodeServiceError> {
        let local_index = max_index().await.unwrap();
        info!(self.log, "\nProcessing block");
        if let Some(header) = &block.msg_header {
            if header.msg_index < local_index {
                Err(NodeServiceError::BlockIndexTooLow)
            } else if header.msg_index == local_index + 1 {
                for transaction in &block.msg_transactions {
                    wallet.process_transaction(transaction).await?;
                }
                add_block(wallet, block).await?;
                info!(self.log, "\nNew block added");
                Ok(())
            } else {
                info!(
                    self.log,
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
                self.log,
                "\nProvided ip was not found in peer list ({:?}), sending dial request", ip
            );
            match self.dial_remote_node(&ip).await {
                Ok((client, version)) => {
                    match self.add_peer(client.clone(), version).await {
                        Ok(_) => {
                            info!(self.log, "\nNew peer added");
                        }
                        Err(e) => {
                            error!(self.log, "Failed to add peer: {:?}", e);
                        }
                    }
                    info!(self.log, "\nDial success, new peer added: {}", ip);
                    let client_arc = Arc::new(Mutex::new(client));
                    let mut client_lock = client_arc.lock().await;
                    self.synchronize_with_client(wallet, &mut client_lock)
                        .await?;
                }
                Err(e) => {
                    error!(self.log, "\nFailed to dial remote node: {:?}", e);
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
        let msg_local_index = max_index().await.unwrap();
        info!(
            self.log,
            "\nSending request with current index {:?}", msg_local_index
        );
        let request = Request::new(LocalState { msg_local_index });
        let response = client.push_state(request).await?;
        let block_batch = response.into_inner();
        self.process_synchronisation(wallet, block_batch).await?;
        info!(self.log, "\nPulled and processed blocks from client");

        Ok(())
    }

    pub async fn broadcast_peer_list(&self) -> Result<(), NodeServiceError> {
        info!(self.log, "\nBroadcasting peer list");
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
            let log = Arc::clone(&self.log);
            let my_addr_clone = my_addr.clone();
            tokio::spawn(async move {
                let mut peer_client_lock = peer_client.write().await;
                let req = Request::new(msg_clone);
                if addr != my_addr_clone {
                    if let Err(e) = peer_client_lock.handle_peer_list(req).await {
                        error!(log, "\nFailed to broadcast peer list to {}: {:?}", addr, e);
                    } else {
                        info!(log, "\nBroadcasted peer list to {}", addr);
                    }
                }
            });
        }

        Ok(())
    }

    // CLI commands
    pub async fn make_genesis_block(&self) -> Result<(), NodeServiceError> {
        if max_index().await? != 0 {
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
            msg_index: 1,
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
        let nonce = mine(block.clone())?;
        block.msg_header.as_mut().unwrap().msg_nonce = nonce;
        add_genesis_block(&self.wallet, block.clone()).await?;
        let bs58_hash = bs58::encode(hash_block(&block)?).into_string();
        info!(
            self.log,
            "\nGenesis block {:?} with tx successfully created", bs58_hash
        );

        Ok(())
    }

    pub async fn make_genesis_transaction(
        &self,
        amount: u64,
    ) -> Result<Transaction, NodeServiceError> {
        let output_index: u32 = 1;
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let view_key_point = &self.wallet.public_view_key.decompress().unwrap();
        let q = r * view_key_point;
        let q_bytes = q.compress().to_bytes();
        let hash = hash!(q_bytes, output_index.to_le_bytes());
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
        get_balance().await
    }

    pub async fn connect_to(&self, ip: String) -> Result<(), NodeServiceError> {
        info!(self.log, "\nTrying to connect with {:?}", ip);

        match self.dial_remote_node(&ip).await {
            Ok((c, v)) => {
                match self.add_peer(c, v).await {
                    Ok(_) => {
                        info!(self.log, "\nNew peer added");
                    }
                    Err(e) => {
                        error!(self.log, "Failed to add peer: {:?}", e);
                    }
                }
                info!(self.log, "\nSuccessfully bootstraped with {:?}", ip);
            }
            Err(e) => {
                error!(self.log, "\nFailed to bootstrap and dial: {:?}", e);
            }
        }

        Ok(())
    }

    pub async fn get_address(&self) -> Result<String, NodeServiceError> {
        let address = bs58::encode(&self.wallet.address).into_string();

        Ok(address)
    }

    pub async fn get_last_index(&self) -> Result<u32, NodeServiceError> {
        let height = max_index().await.unwrap();

        Ok(height)
    }
}

pub async fn new(secret_key: String, ip: String) -> Result<ArcNodeService, NodeServiceError> {
    let ns = NodeService::new(secret_key, ip).await?;
    Ok(ArcNodeService { ns: Arc::new(ns) })
}

pub async fn start(arc_ns: &Arc<NodeService>) -> Result<(), NodeServiceError> {
    let ip = arc_ns
        .ip
        .parse()
        .map_err(NodeServiceError::AddrParseError)?;
    info!(arc_ns.log, "\nNodeServer starting listening on {}", ip);
    setup_server(arc_ns, ip).await?;

    Ok(())
}

pub async fn setup_server(
    arc_ns: &Arc<NodeService>,
    cfg_ip: SocketAddr,
) -> Result<(), NodeServiceError> {
    let ans = ArcNodeService {
        ns: Arc::clone(arc_ns),
    };
    Server::builder()
        .accept_http1(true)
        .add_service(NodeServer::new(ans))
        .serve(cfg_ip)
        .await
        .map_err(NodeServiceError::TonicTransportError)
}

pub async fn bootstrap_network(
    ans: &ArcNodeService,
    ips: Vec<String>,
) -> Result<(), NodeServiceError> {
    let mut tasks = Vec::new();
    for ip in ips {
        let ns_arc = Arc::clone(&ans.ns);
        let task = tokio::spawn(async move {
            match ns_arc.dial_remote_node(&ip).await {
                Ok((c, v)) => {
                    match ns_arc.add_peer(c, v).await {
                        Ok(_) => {
                            info!(ns_arc.log, "\nNew peer added");
                        }
                        Err(e) => {
                            error!(ns_arc.log, "Failed to add peer: {:?}", e);
                        }
                    }
                    info!(ns_arc.log, "\nSuccessfully bootstraped with {:?}", ip);
                }
                Err(e) => {
                    error!(ns_arc.log, "\nFailed bootstrap and dial: {:?}", e);
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
