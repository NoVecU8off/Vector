use crate::node::*;
use sn_proto::messages::*;
use sn_transaction::transaction::*;
use sn_mempool::mempool::*;
use sn_merkle::merkle::MerkleTree;
use sn_chain::chain::Chain;
use sn_block::block::*;
use tokio::sync::{Mutex, RwLock, oneshot};
use std::time::{Duration, SystemTime};
use tonic::{Request, Response, Status, codegen::Arc};
use anyhow::Result;
use futures::future::try_join_all;
use log::{info, error};

#[derive(Clone)]
pub struct ValidatorService {
    pub validator_id: i32,
    pub node_service: Arc<NodeService>,
    pub mempool: Arc<Mempool>,
    pub created_block: Arc<Mutex<Option<(Block, Vec<u8>)>>>,
    pub agreement_count: Arc<Mutex<usize>>,
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
                info!("\n{}: received transaction: {}", self.node_service.server_config.cfg_addr, hash_str);
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
            self.update_agreement_count(agreement).await;
        }
        Ok(Response::new(Agreement { agreed: agreement }))
    }
}

impl ValidatorService {
    pub async fn start_validator_tick(&self) {
        let node_clone = self.clone();
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        loop {
            interval.tick().await;
            let num_transactions = node_clone.mempool.len().await;
            if num_transactions == 100 {
                node_clone.initialize_consensus().await;
            }
        }
    }

    pub async fn initialize_consensus(&self) {
        let public_key_hex = hex::encode(&self.node_service.server_config.cfg_keypair.public.as_bytes());
        self.create_unsigned_block().await.unwrap();
        let (_, block_hash) = {
            let created_block_lock = self.created_block.lock().await;
            created_block_lock.as_ref().unwrap().clone()
        };
        self.broadcast_unsigned_block_hash(&block_hash).await.unwrap();
        self.wait_for_agreement().await;
        info!("\n{}: new block created by {}", self.node_service.server_config.cfg_addr, public_key_hex);
    }

    pub async fn wait_for_agreement(&self) {
        let (sender, receiver) = oneshot::channel();
        *self.trigger_sender.lock().await = Some(sender);
        if let Err(_) = receiver.await {
            error!("Failed to get agreements");
        }
        let mut chain_write_lock = self.chain.write().await;
        self.finalize_block(&mut chain_write_lock).await;
        *self.agreement_count.lock().await = 0;
    }

    pub async fn create_unsigned_block(&self) -> Result<Block> {
        let chain = &self.chain;
        let chain_read_lock = chain.read().await;
        let msg_previous_hash = Chain::get_previous_hash_in_chain(&chain_read_lock).await.unwrap();
        let height = Chain::chain_height(&chain_read_lock) as i32;
        let keypair = &self.node_service.server_config.cfg_keypair;
        let public_key = keypair.public.to_bytes().to_vec();
        let transactions = self.mempool.clear().await;
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

    pub async fn hash_unsigned_block(&self, block: &Block) -> Result<Vec<u8>> {
        let hash = hash_header_by_block(block).unwrap().to_vec();
        Ok(hash)
    }

    pub async fn broadcast_unsigned_block_hash(&self, block_hash: &Vec<u8>) -> Result<()> {
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
                        error!(
                            "Failed to broadcast unsigned block hash to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            "\n{}: broadcasted unsigned block hash to \n {}",
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
        let unsigned_block = self.create_unsigned_block().await.unwrap();
        let local_block_hash = self.hash_unsigned_block(&unsigned_block).await.unwrap();
        received_block_hash == &local_block_hash
    }

    pub async fn update_agreement_count(&self, agreement: bool) {
        let mut agreement_count = self.agreement_count.lock().await;
        if agreement {
            *agreement_count += 1;
            let num_validators = {
                let peers = self.node_service.peer_lock.read().await;
                peers
                    .iter()
                    .filter(|(_, (_, _, is_validator))| *is_validator)
                    .count()
            };
            let required_agreements = 3 * num_validators / 4;
            if *agreement_count >= required_agreements {
                if let Some(sender) = self.trigger_sender.lock().await.take() {
                    let _ = sender.send(());
                }
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
            chain.add_block(block).await.unwrap();
            let mut created_block_lock = self.created_block.lock().await;
            *created_block_lock = None;
        }
    }

    pub async fn respond_to_received_block_hash(&self, msg: &HashAgreement, target: String) -> Result<()> {
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
                    error!(
                        "Failed to send response to {}: {:?}",
                        addr,
                        err
                    );
                } else {
                    info!(
                        "\n{}: sent response to \n {}",
                        self_clone.node_service.server_config.cfg_addr,
                        addr
                    );
                }
            }
        } else {
            error!("Target address not found in the list of peers: {}", target);
        }
        Ok(())
    }

    pub async fn broadcast_transaction(&self, transaction: Transaction) -> Result<()> {
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
                        error!(
                            "Failed to broadcast transaction to {}: {:?}",
                            addr,
                            err
                        );
                    } else {
                        info!(
                            "\n{}: broadcasted transaction to \n {}",
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
}