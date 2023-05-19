use crate::node::*;
use vec_proto::messages::*;
use vec_transaction::transaction::*;
use vec_mempool::mempool::*;
use vec_merkle::merkle::MerkleTree;
use vec_chain::chain::Chain;
use vec_block::block::*;
use vec_errors::errors::*;
use tokio::sync::{Mutex, RwLock, broadcast};
use std::{collections::{HashMap, HashSet}, time::{Duration, SystemTime}};
use tonic::{Request, Response, Status, codegen::Arc};
use futures::future::try_join_all;
use rand::{Rng};
use slog::{info, error};

#[derive(Clone)]
pub struct ValidatorService {
    pub validator_id: i32,
    pub node_service: Arc<NodeService>,
    pub mempool: Arc<Mempool>,
    pub round_transactions: Arc<Mutex<Vec<Transaction>>>,
    pub created_block: Arc<Mutex<Option<(Block, Vec<u8>)>>>,
    pub agreement_count: Arc<Mutex<HashMap<Vec<u8>, HashSet<String>>>>,
    pub vote_count: Arc<Mutex<HashMap<u64, usize>>>,
    pub received_responses_count: Arc<Mutex<usize>>,
    pub chain: Arc<RwLock<Chain>>,
    pub mempool_signal: Arc<RwLock<broadcast::Sender<()>>>,
    pub broadcast_signal: Arc<RwLock<broadcast::Sender<()>>>,
    pub bt_loop_signal: Arc<RwLock<broadcast::Sender<()>>>,
}

#[tonic::async_trait]
pub trait Validator: Sync + Send {
    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
    ) -> Result<Response<Confirmed>, Status>;

    async fn handle_agreement(
        &self,
        request: Request<HashAgreement>,
    ) -> Result<Response<Agreement>, Status>;

    async fn handle_vote(
        &self,
        request: Request<Vote>,
    ) -> Result<Response<Confirmed>, Status>;

    async fn push_state(
        &self,
        request: Request<LocalState>,
    ) -> Result<Response<BlockBatch>, Status>;
}

#[tonic::async_trait]
impl Validator for ValidatorService {
    async fn push_state(
        &self,
        request: Request<LocalState>,
    ) -> Result<Response<BlockBatch>, Status> {
        let current_state = request.into_inner();
        let requested_height = current_state.msg_last_block_height;
        let mut blocks = Vec::new();
        let chain_lock = self.chain.read().await;
        for height in (requested_height + 1)..=chain_lock.chain_height() as u64 {
            match chain_lock.get_block_by_height(height as usize).await {
                Ok(block) => blocks.push(block),
                Err(e) => {
                    error!(self.node_service.logger, "Failed to get block at height {}: {:?}", height, e);
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
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        if !self.mempool.contains_transaction(&transaction).await && self.mempool.add(transaction.clone()).await {
                info!(self.node_service.logger, "{}: received and added transaction: {}", cfg_addr, hash_str);
                let self_clone = self.clone();
                let mempool_signal = self.mempool_signal.write().await;
                mempool_signal.send(()).unwrap();
                tokio::spawn(async move {
                    if let Err(e) = self_clone.node_service.broadcast_tx(transaction).await {
                        error!(self_clone.node_service.logger, "Error broadcasting transaction: {}", e);
                    }
                });
            }
        Ok(Response::new(Confirmed {}))
    }

    async fn handle_agreement(
        &self,
        request: Request<HashAgreement>,
    ) -> Result<Response<Agreement>, Status> {
        let hash_agreement = request.into_inner();
        let hash = hash_agreement.msg_block_hash;
        let agreement = hash_agreement.msg_agreement;
        let is_response = hash_agreement.msg_is_responce;
        let sender_addr = hash_agreement.msg_sender_addr;
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        if !is_response {
            let agreed = match self.compare_hashes(&hash).await {
                Ok(result) => result,
                Err(e) => {
                    error!(self.node_service.logger, "Error comparing block hashes: {}", e);
                    return Err(Status::internal("Failed to compare block hashes"));
                }
            };
    
            let msg = HashAgreement {
                msg_validator_id: self.validator_id as u64,
                msg_block_hash: hash.clone(),
                msg_agreement: agreed,
                msg_is_responce: true,
                msg_sender_addr: cfg_addr.clone(),
            };
    
            if let Err(e) = self.respond_hash(&msg, sender_addr).await {
                error!(self.node_service.logger, "Error responding to hash agreement message: {}", e);
            }
        } else {
            let num_validators = {
                let peers = self.node_service.peer_lock.read().await;
                peers
                    .iter()
                    .filter(|(_, (_, _, is_validator))| *is_validator)
                    .count()
            };
            if agreement {
                self.update_agreement_count(hash, sender_addr).await;
            }
            let mut received_responses_count = self.received_responses_count.lock().await;
            *received_responses_count += 1;
            if *received_responses_count == num_validators - 1 {
                let agreement_count = self.agreement_count.lock().await;
                let supermajority = (2 * num_validators / 3) + 1;
                let supermajority_addresses = agreement_count
                    .values()
                    .filter(|addresses| addresses.len() >= supermajority)
                    .flatten()
                    .cloned()
                    .collect::<HashSet<String>>();
                if supermajority_addresses.contains(&cfg_addr) {
                    if let Err(e) = self.initialize_voting(supermajority_addresses).await {
                        error!(self.node_service.logger, "Failed to initialize voting during hash agreement: {}", e);
                    }
                } else {
                    if let Err(e) = self.wait_for_voting_completion().await {
                        error!(self.node_service.logger, "Failed to reinitialize consensus after hash agreement failure: {}", e);
                    }
                }
            }
        }
        Ok(Response::new(Agreement { agreed: agreement }))
    }

    async fn handle_vote(
        &self,
        request: Request<Vote>,
    ) -> Result<Response<Confirmed>, Status> {
        let vote = request.into_inner();
        let target_validator_id = vote.msg_target_validator_id;
        self.update_vote_count(target_validator_id).await;
        if let Err(e) = self.wait_for_voting_completion().await {
            error!(self.node_service.logger, "Failed to wait for voting completion: {}", e);
        }
        Ok(Response::new(Confirmed {}))
    }
}

impl ValidatorService {
    pub async fn initialize_validating(&self) -> Result<(), ValidatorServiceError> {
        {
            let signal = self.bt_loop_signal.write().await;
            let _ = signal.send(());
        }
        let mut mempool_rx = {
            let mempool_signal = self.mempool_signal.read().await;
            mempool_signal.subscribe()
        };
        while (mempool_rx.recv().await).is_ok() 
        {
            let num_transactions = self.mempool.len().await;
            if num_transactions == 5 {
                self.initialize_consensus().await?;
            }
        }
        Ok(())
    }

    pub async fn start_broadcast_cascade(&self) -> Result<(), ValidatorServiceError> {
        let mut signal_receiver = {
            let signal = self.bt_loop_signal.read().await;
            signal.subscribe()
        };
        signal_receiver.recv().await?;
        let mut interval = tokio::time::interval(Duration::from_secs(61));
        loop {
            self.broadcast_peer_list().await?;
            interval.tick().await;
        }
    }

    pub async fn initialize_consensus(&self) -> Result<(), ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        info!(self.node_service.logger, "{}: Consensus initialized", cfg_addr);
        let my_addr = cfg_addr.clone();
        let mut created_block_lock = self.created_block.lock().await;
        *created_block_lock = None;
        self.accept_round_transactions().await?;
        self.mempool.clear().await;
        self.create_unsigned_block().await?;
        let (_, block_hash) = {
            let created_block_lock = self.created_block.lock().await;
            created_block_lock.as_ref().ok_or(ValidatorServiceError::NoCreatedBlockFound)?.clone()
        };
        self.update_agreement_count(block_hash, my_addr).await;
        Ok(())
    }

    pub async fn accept_round_transactions(&self) -> Result<(), ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        let transactions = self.mempool.get_transactions().await;
        {
            let mut round_transactions = self.round_transactions.lock().await;
            for transaction in transactions {
                round_transactions.push(transaction);
            }
            info!(self.node_service.logger, "{}: round transactions accepted", cfg_addr);
        }
        Ok(())
    }

    pub async fn create_unsigned_block(&self) -> Result<(), ValidatorServiceError> {
        let (cfg_keypair, cfg_addr) = {
            let server_config = self.node_service.server_config.read().await;
            (server_config.cfg_keypair.clone(), server_config.cfg_addr.clone())
        };
        info!(self.node_service.logger, "{}: unsigned block creation", cfg_addr);
        let chain = &self.chain;
        let chain_read_lock = chain.read().await;
        let msg_previous_hash = Chain::get_previous_hash_in_chain(&chain_read_lock).await?;
        let height = Chain::chain_height(&chain_read_lock) as i32;
        let keypair = &cfg_keypair;
        let public_key = keypair.public.to_bytes().to_vec();
        let transactions = {
            let round_transactions = self.round_transactions.lock().await;
            round_transactions.clone()
        };
        let merkle_tree = MerkleTree::new(&transactions)?;
        let merkle_root = merkle_tree.root.to_vec();
        let header = Header {
            msg_version: 1,
            msg_height: height + 1,
            msg_previous_hash,
            msg_root_hash: merkle_root,
            msg_timestamp: 0,
        };
        let block = Block {
            msg_header: Some(header),
            msg_transactions: transactions,
            msg_public_key: public_key,
            msg_signature: vec![],
        };
        let hash = self.hash_unsigned_block(&block).await?;
        let mut created_block_lock = self.created_block.lock().await;
        *created_block_lock = Some((block, hash.clone()));
        self.broadcast_hash(&hash).await?;
        Ok(())
    }    

    pub async fn hash_unsigned_block(&self, block: &Block) -> Result<Vec<u8>, ValidatorServiceError> {
        let hash = hash_header_by_block(block)?.to_vec();
        Ok(hash)
    }

    pub async fn broadcast_hash(&self, block_hash: &[u8]) -> Result<(), ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        info!(self.node_service.logger, "{}: broadcasting block", cfg_addr);
        let my_addr = &cfg_addr;
        let msg = HashAgreement {
            msg_validator_id: self.validator_id as u64,
            msg_block_hash: block_hash.to_owned(),
            msg_agreement: true,
            msg_is_responce: false,
            msg_sender_addr: my_addr.to_string(),
        };
        let peers_data = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .filter(|(_, (_, _, is_validator))| *is_validator)
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.node_service.server_config.read().await;
                server_config.cfg_addr.clone()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if addr != cfg_addr {
                    if let Err(err) = peer_client_lock.handle_agreement(req).await {
                        error!(
                            self_clone.node_service.logger,
                            "Failed to broadcast unsigned block hash to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            self_clone.node_service.logger,
                            "{}: broadcasted unsigned block hash to  {}",
                            cfg_addr,
                            addr
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|_| ValidatorServiceError::HashBroadcastFailed)?;
        Ok(())
    }

    pub async fn compare_hashes(&self, received_block_hash: &Vec<u8>) -> Result<bool, ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        info!(self.node_service.logger, "{}: hashes are being compared", cfg_addr);
        let (_, local_block_hash) = {
            let local_block_hash = self.created_block.lock().await;
            local_block_hash.as_ref().ok_or(ValidatorServiceError::NoCreatedBlockFound)?.clone()
        };
        Ok(received_block_hash == &local_block_hash)
    }

    pub async fn respond_hash(&self, msg: &HashAgreement, target: String) -> Result<(), ValidatorServiceError> {
        let peers_data = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .get(&target)
                .map(|(peer_client, _, _)| (target.clone(), Arc::clone(peer_client)))
        };
        if let Some((addr, peer_client)) = peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.node_service.server_config.read().await;
                server_config.cfg_addr.clone()
            };
            let mut peer_client_lock = peer_client.lock().await;
            let req = Request::new(msg_clone);
            if addr != cfg_addr {
                if let Err(err) = peer_client_lock.handle_agreement(req).await {
                    error!(
                        self_clone.node_service.logger,
                        "Failed to send response to {}: {:?}",
                        addr,
                        err
                    );
                } else {
                    info!(
                        self_clone.node_service.logger,
                        "{}: sent response to  {}",
                        cfg_addr,
                        addr
                    );
                }
            }
        } else {
            error!(self.node_service.logger, "Target address not found in the list of peers: {}", target);
        }
        Ok(())
    }

    pub async fn update_agreement_count(&self, block_hash: Vec<u8>, sender_addr: String) {
        let mut agreement_count = self.agreement_count.lock().await;
        let entry = agreement_count.entry(block_hash).or_insert(HashSet::new());
        entry.insert(sender_addr);
    }

    async fn initialize_voting(&self, supermajority_addresses: HashSet<String>) -> Result<(), ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        self.clear_round_transactions().await?;
        let mut received_responses_count = self.received_responses_count.lock().await;
        *received_responses_count = 0;
        if let Some(random_validator_id) = self.get_validator().await {
            let vote = Vote {
                msg_validator_id: self.validator_id as u64,
                msg_voter_addr: cfg_addr,
                msg_target_validator_id: random_validator_id,
            };
            self.broadcast_vote(vote, supermajority_addresses).await?;
        }
        Ok(())
    }

    pub async fn clear_round_transactions(&self) -> Result<(), ValidatorServiceError> {
        let mut round_transactions = self.round_transactions.lock().await;
        round_transactions.clear();
        Ok(())
    }

    pub async fn broadcast_vote(&self, vote: Vote, supermajority_addresses: HashSet<String>) -> Result<(), ValidatorServiceError> {
        let peers_data = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .filter(|(addr, (_, _, _))| supermajority_addresses.contains(*addr))
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let vote_clone = vote.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(vote_clone);
                let res = peer_client_lock.handle_vote(req).await;
                match res {
                    Ok(_) => {
                        info!(
                            self_clone.node_service.logger,
                            "Vote counter updated"
                        );
                        self_clone.update_vote_count(vote.msg_target_validator_id).await;
                    }
                    Err(e) => {
                        error!(
                            self_clone.node_service.logger,
                            "Failed to broadcast vote to validator {}: {:?}",
                            addr, e
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|_| ValidatorServiceError::VoteBroadcastFailed)?;
        Ok(())
    }

    pub async fn update_vote_count(&self, target_validator_id: u64) -> usize {
        let mut vote_count = self.vote_count.lock().await;
        let count = vote_count.entry(target_validator_id).or_insert(0);
        *count += 1;
        *count
    }

    pub async fn wait_for_voting_completion(&self) -> Result<(), ValidatorServiceError> {
        let validators_count = {
            let peers = self.node_service.peer_lock.read().await;
            peers.iter().filter(|(_, (_, _, is_validator))| *is_validator).count()
        };
        loop {
            let total_votes: usize = self.vote_count.lock().await.values().sum();
            if total_votes == validators_count - 1 {
                let mut chain_write_lock = self.chain.write().await;
                self.finalize_block_if_winner(&mut chain_write_lock).await?;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }    

    pub async fn get_validator(&self) -> Option<u64> {
        let peers = self.node_service.peer_lock.read().await;
        let validators: Vec<u64> = peers
            .iter()
            .filter(|(_, (_, _, is_validator))| *is_validator)
            .map(|(_, (_, validator_id, _))| validator_id.msg_validator_id as u64)
            .collect();
    
        if validators.is_empty() {
            None
        } else {
            let mut rng = rand::thread_rng();
            let random_index = rng.gen_range(0..validators.len()); // ?????
            Some(validators[random_index])
        }
    }    

    async fn finalize_block_if_winner(&self, chain: &mut Chain) -> Result<(), ValidatorServiceError> {
        let mut vote_count = self.vote_count.lock().await;
        let highest_vote_count = vote_count.values().max().unwrap_or(&0);
        if let Some(own_vote_count) = vote_count.get(&(self.validator_id as u64)) {
            if own_vote_count == highest_vote_count {
                self.finalize_block(chain).await?;
            }
        }
        vote_count.clear();
        Ok(())
    }

    pub async fn finalize_block(&self, chain: &mut Chain) -> Result<(), ValidatorServiceError> {
        let cfg_keypair = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_keypair.clone()
        };
        let created_block_tuple = {
            let created_block_lock = self.created_block.lock().await;
            created_block_lock.clone()
        };
        if let Some((mut block, _)) = created_block_tuple {
            let timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            if let Some(header) = block.msg_header.as_mut() {
                header.msg_timestamp = timestamp as i64;
            }
            let keypair = &cfg_keypair;
            let signature = sign_block(&block, keypair).await?;
            block.msg_signature = signature.to_vec();
            chain.add_block(block.clone()).await?;
            self.broadcast_block(block).await?;
            let mut created_block_lock = self.created_block.lock().await;
            *created_block_lock = None;
        }
        Ok(())
    }

    pub async fn broadcast_block(&self, block: Block) -> Result<(), ValidatorServiceError> {
        let peers_data = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let block_clone = block.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(block_clone);
                let res = peer_client_lock.handle_block(req).await;
                match res {
                    Ok(_) => {
                        info!(self_clone.node_service.logger, "Successfully broadcasted block to {}", addr);
                    }
                    Err(e) => {
                        error!(
                            self_clone.node_service.logger, 
                            "Failed to broadcast block to {}: {:?}",
                            addr, e
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.map_err(|_| ValidatorServiceError::LeaderBlockBroadcastFailed)?;
        Ok(())
    }

    pub async fn broadcast_peer_list(&self) -> Result<(), ValidatorServiceError> {
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        info!(self.node_service.logger, "{}: broadcasting peer list", cfg_addr);
        let my_addr = &cfg_addr;
        let mut peers_addresses = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .map(|(addr, (_, _, _))| (addr.clone()))
                .collect::<Vec<_>>()
        };
        peers_addresses.push(my_addr.clone());
        let msg = PeerList {
            msg_peers_addresses: peers_addresses,
        };
        let peers_data = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .filter(|(_, (_, _, is_validator))| *is_validator)
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.node_service.server_config.read().await;
                server_config.cfg_addr.clone()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if addr != cfg_addr {
                    if let Err(err) = peer_client_lock.handle_peer_exchange(req).await {
                        error!(
                            self_clone.node_service.logger,
                            "Failed to broadcast peer list to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            self_clone.node_service.logger,
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
        {
            let signal = self.broadcast_signal.write().await;
            let _ = signal.send(());
        }
        Ok(())
    }

    pub async fn broadcast_validator_list(&self) -> Result<(), ValidatorServiceError> {
        let mut signal_receiver = {
            let signal = self.broadcast_signal.read().await;
            signal.subscribe()
        };
        let cfg_addr = {
            let server_config = self.node_service.server_config.read().await;
            server_config.cfg_addr.clone()
        };
        signal_receiver.recv().await?;
        info!(self.node_service.logger, "{}: broadcasting validator peer list", cfg_addr);
        let my_addr = &cfg_addr;
        let mut validator_peers = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .filter(|(_, (_, _, is_validator))| *is_validator)
                .map(|(addr, (_, _, _))| addr.clone())
                .collect::<Vec<_>>()
        };
        validator_peers.push(my_addr.clone());
        let msg = PeerList {
            msg_peers_addresses: validator_peers,
        };
        let common_nodes = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .iter()
                .filter(|(_, (_, _, is_validator))| !*is_validator)
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in common_nodes {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let cfg_addr = {
                let server_config = self_clone.node_service.server_config.read().await;
                server_config.cfg_addr.clone()
            };
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if addr != cfg_addr {
                    if let Err(err) = peer_client_lock.handle_peer_exchange(req).await {
                        error!(
                            self_clone.node_service.logger,
                            "Failed to broadcast validator peer list to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            self_clone.node_service.logger,
                            "{}: broadcasted validator peer list to {}",
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