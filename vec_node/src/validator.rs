use crate::node::*;
use vec_proto::messages::*;
use vec_transaction::transaction::*;
use vec_mempool::mempool::*;
use vec_merkle::merkle::MerkleTree;
use vec_chain::chain::Chain;
use vec_block::block::*;
use vec_errors::errors::*;
use tokio::sync::{Mutex, RwLock, oneshot};
use std::{collections::HashMap, time::{Duration, SystemTime}};
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
    pub agreement_count: Arc<Mutex<usize>>,
    pub vote_count: Arc<Mutex<HashMap<u64, usize>>>,
    pub received_responses_count: Arc<Mutex<usize>>,
    pub chain: Arc<RwLock<Chain>>,
    pub trigger_sender: Arc<Mutex<Option<oneshot::Sender<()>>>>,
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

    async fn handle_block(
        &self,
        request: Request<Block>,
    ) -> Result<Response<Confirmed>, Status>;
}

#[tonic::async_trait]
impl Validator for ValidatorService {
    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
    ) -> Result<Response<Confirmed>, Status> {
        let transaction = request.into_inner();
        let hash = hash_transaction(&transaction).await;
        let hash_str = hex::encode(&hash);
        if !self.mempool.contains_transaction(&transaction).await {
            if self.mempool.add(transaction.clone()).await {
                info!(self.node_service.logger, "{}: received transaction: {}", self.node_service.server_config.cfg_addr, hash_str);
                let self_clone = self.clone();
                tokio::spawn(async move {
                    if let Err(_err) = self_clone.broadcast_transaction(transaction).await {
                    }
                });
            }
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
        if !is_response {
            let agreed = self.compare_block_hashes(&hash).await;
            let msg = HashAgreement {
                msg_validator_id: self.validator_id as u64,
                msg_block_hash: hash.clone(),
                msg_agreement: agreed,
                msg_is_responce: true,
                msg_sender_addr: self.node_service.server_config.cfg_addr.clone(),
            };
            self.respond_to_received_block_hash(&msg, sender_addr).await.unwrap();
        } else {
            let num_validators = {
                let peers = self.node_service.peer_lock.read().await;
                peers
                    .iter()
                    .filter(|(_, (_, _, is_validator))| *is_validator)
                    .count()
            };
            if agreement {
                self.update_agreement_count().await;
            }
            let mut received_responses_count = self.received_responses_count.lock().await;
            *received_responses_count += 1;
            if *received_responses_count == num_validators - 1 {
                let mut agreement_count = self.agreement_count.lock().await;
                let required_agreements = (2 * num_validators) / 3 + 1;
                if *agreement_count >= required_agreements {
                    self.initialize_voting().await.unwrap();
                } else {
                    *agreement_count = 0;
                    *received_responses_count = 0;
                    self.initialize_consensus().await;
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
        self.wait_for_voting_completion().await;
        Ok(Response::new(Confirmed {}))
    }

    async fn handle_block(
        &self,
        request: Request<Block>,
    ) -> Result<Response<Confirmed>, Status> {
        let new_block = request.into_inner();
        let mut chain_lock = self.chain.write().await;
        chain_lock.add_leader_block(new_block).await.unwrap();
        Ok(Response::new(Confirmed {}))
    }
}

impl ValidatorService {
    pub async fn initialize_validating(&self) {
        let node_clone = self.clone();
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            let num_transactions = node_clone.mempool.len().await;
            if num_transactions == 5 {
                node_clone.initialize_consensus().await;
            }
        }
    }

    pub async fn broadcast_transaction(&self, transaction: Transaction) -> Result<(), ValidatorServiceError> {
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
            let transaction_clone = transaction.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(transaction_clone.clone());
                if addr != self_clone.node_service.server_config.cfg_addr {
                    if let Err(err) = peer_client_lock.handle_transaction(req).await {
                        eprintln!(
                            "Failed to broadcast transaction to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        println!(
                            "{}: broadcasted transaction to  {}",
                            self_clone.node_service.server_config.cfg_addr,
                            addr
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.unwrap();
        Ok(())
    }

    pub async fn initialize_consensus(&self) {
        info!(self.node_service.logger, "{}: Consensus initialized", self.node_service.server_config.cfg_addr);
        let mut created_block_lock = self.created_block.lock().await;
            { *created_block_lock = None; }
        self.accept_round_transactions().await.unwrap();
        self.mempool.clear().await;
        self.create_unsigned_block().await.unwrap();
        let (_, block_hash) = {
            let created_block_lock = self.created_block.lock().await;
            created_block_lock.as_ref().unwrap().clone()
        };
        self.update_agreement_count().await;
        self.broadcast_unsigned_block_hash(&block_hash).await.unwrap();
    }

    pub async fn accept_round_transactions(&self) -> Result<(), ValidatorServiceError> {
        let transactions = self.mempool.get_transactions().await;
        {
            let mut round_transactions = self.round_transactions.lock().await;
            for transaction in transactions {
                round_transactions.push(transaction);
            }
            info!(self.node_service.logger, "{}: round transactions accepted", self.node_service.server_config.cfg_addr);
        }
        Ok(())
    }

    pub async fn create_unsigned_block(&self) -> Result<Block, ValidatorServiceError> {
        info!(self.node_service.logger, "{}: unsigned block creation", self.node_service.server_config.cfg_addr);
        let chain = &self.chain;
        let chain_read_lock = chain.read().await;
        let msg_previous_hash = Chain::get_previous_hash_in_chain(&chain_read_lock).await.unwrap();
        let height = Chain::chain_height(&chain_read_lock) as i32;
        let keypair = &self.node_service.server_config.cfg_keypair;
        let public_key = keypair.public.to_bytes().to_vec();
        let transactions = {
            let round_transactions = self.round_transactions.lock().await;
            round_transactions.clone()
        };
        let merkle_tree = MerkleTree::new(&transactions).unwrap();
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
        let hash = self.hash_unsigned_block(&block).await.unwrap();
        let mut created_block_lock = self.created_block.lock().await;
        *created_block_lock = Some((block.clone(), hash));
        Ok(block)
    }    

    pub async fn hash_unsigned_block(&self, block: &Block) -> Result<Vec<u8>, ValidatorServiceError> {
        let hash = hash_header_by_block(block).unwrap().to_vec();
        Ok(hash)
    }

    pub async fn broadcast_unsigned_block_hash(&self, block_hash: &Vec<u8>) -> Result<(), ValidatorServiceError> {
        info!(self.node_service.logger, "{}: broadcasting block", self.node_service.server_config.cfg_addr);
        let my_addr = &self.node_service.server_config.cfg_addr;
        let msg = HashAgreement {
            msg_validator_id: self.validator_id as u64,
            msg_block_hash: block_hash.clone(),
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
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(msg_clone);
                if addr != self_clone.node_service.server_config.cfg_addr {
                    if let Err(err) = peer_client_lock.handle_agreement(req).await {
                        eprintln!(
                            "Failed to broadcast unsigned block hash to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        println!(
                            "{}: broadcasted unsigned block hash to  {}",
                            self_clone.node_service.server_config.cfg_addr,
                            addr
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.unwrap();
        Ok(())
    }

    pub async fn compare_block_hashes(&self, received_block_hash: &Vec<u8>) -> bool {
        info!(self.node_service.logger, "{}: hashes are being compared", self.node_service.server_config.cfg_addr);
        let (_, local_block_hash) = {
            let local_block_hash = self.created_block.lock().await;
            local_block_hash.as_ref().unwrap().clone()
        };
        received_block_hash == &local_block_hash
    }

    pub async fn respond_to_received_block_hash(&self, msg: &HashAgreement, target: String) -> Result<(), ValidatorServiceError> {
        let peers_data = {
            let peers = self.node_service.peer_lock.read().await;
            peers
                .get(&target)
                .map(|(peer_client, _, _)| (target.clone(), Arc::clone(peer_client)))
        };
        if let Some((addr, peer_client)) = peers_data {
            let msg_clone = msg.clone();
            let self_clone = self.clone();
            let mut peer_client_lock = peer_client.lock().await;
            let req = Request::new(msg_clone);
            if addr != self_clone.node_service.server_config.cfg_addr {
                if let Err(err) = peer_client_lock.handle_agreement(req).await {
                    eprintln!(
                        "Failed to send response to {}: {:?}",
                        addr,
                        err
                    );
                } else {
                    println!(
                        "{}: sent response to  {}",
                        self_clone.node_service.server_config.cfg_addr,
                        addr
                    );
                }
            }
        } else {
            error!(self.node_service.logger, "Target address not found in the list of peers: {}", target);
        }
        Ok(())
    }

    pub async fn update_agreement_count(&self) {
        info!(self.node_service.logger, "{}: updating agrement count", self.node_service.server_config.cfg_addr);
        let mut agreement_count = self.agreement_count.lock().await;
        *agreement_count += 1;
    }

    async fn initialize_voting(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.clear_round_transactions().await.unwrap();
        if let Some(random_validator_id) = self.select_random_validator().await {
            let vote = Vote {
                msg_validator_id: self.validator_id as u64,
                msg_voter_addr: self.node_service.server_config.cfg_addr.clone(),
                msg_target_validator_id: random_validator_id,
            };
            self.broadcast_vote(vote).await?;
        }
        Ok(())
    }

    pub async fn clear_round_transactions(&self) -> Result<(), ValidatorServiceError> {
        let mut round_transactions = self.round_transactions.lock().await;
        round_transactions.clear();
        Ok(())
    }

    pub async fn broadcast_vote(&self, vote: Vote) -> Result<(), ValidatorServiceError> {
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
            let vote_clone = vote.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(vote_clone);
                let res = peer_client_lock.handle_vote(req).await;
                match res {
                    Ok(_) => {
                        self_clone.update_vote_count(vote.msg_target_validator_id).await;
                    }
                    Err(e) => {
                        eprintln!(
                            "Failed to broadcast vote to validator {}: {:?}",
                            addr, e
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.unwrap();
        Ok(())
    }

    pub async fn update_vote_count(&self, target_validator_id: u64) -> usize {
        let mut vote_count = self.vote_count.lock().await;
        let count = vote_count.entry(target_validator_id).or_insert(0);
        *count += 1;
        *count
    }

    async fn wait_for_voting_completion(&self) {
        let validators_count = {
            let peers = self.node_service.peer_lock.read().await;
            peers.iter().filter(|(_, (_, _, is_validator))| *is_validator).count()
        };
        loop {
            let total_votes: usize = self.vote_count.lock().await.values().sum();
            if total_votes == validators_count - 1 {
                let mut chain_write_lock = self.chain.write().await;
                self.finalize_block_if_winner(&mut chain_write_lock).await;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }    

    pub async fn select_random_validator(&self) -> Option<u64> {
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
            let random_index = rng.gen_range(0..validators.len());
            Some(validators[random_index])
        }
    }    

    async fn finalize_block_if_winner(&self, chain: &mut Chain) {
        let vote_count = self.vote_count.lock().await;
        let highest_vote_count = vote_count.values().max().unwrap_or(&0);
        if let Some(own_vote_count) = vote_count.get(&(self.validator_id as u64)) {
            if own_vote_count == highest_vote_count {
                self.finalize_block(chain).await;
            }
        }
    }

    pub async fn finalize_block(&self, chain: &mut Chain) {
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
            let keypair = &self.node_service.server_config.cfg_keypair;
            let signature = sign_block(&block, keypair).await.unwrap();
            block.msg_signature = signature.to_vec();
            chain.add_block(block.clone()).await.unwrap();
            self.broadcast_block(block).await.unwrap();
            let mut created_block_lock = self.created_block.lock().await;
            *created_block_lock = None;
        }
    }

    pub async fn broadcast_block(&self, block: Block) -> Result<(), ValidatorServiceError> {
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
                            "Failed to broadcast block to validator {}: {:?}",
                            addr, e
                        );
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.unwrap();
        Ok(())
    }
}