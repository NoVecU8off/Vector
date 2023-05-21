use crate::node::*;
use vec_proto::messages::*;
use vec_transaction::transaction::*;
use vec_mempool::mempool::*;
use vec_chain::chain::Chain;
use vec_errors::errors::*;
use tokio::sync::{Mutex, RwLock};
use tonic::{Request, Response, Status, codegen::Arc};
use futures::future::try_join_all;
use futures::stream::{self, StreamExt};
use slog::{info, error};

#[derive(Clone)]
pub struct ValidatorService {
    pub validator_id: i32,
    pub node_service: Arc<NodeService>,
    pub mempool: Arc<Mempool>,
    pub round_transactions: Arc<Mutex<Vec<Transaction>>>,
    pub chain: Arc<RwLock<Chain>>,
}

#[tonic::async_trait]
pub trait Validator: Sync + Send {
    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
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
                tokio::spawn(async move {
                    if let Err(e) = self_clone.node_service.broadcast_tx(transaction).await {
                        error!(self_clone.node_service.logger, "Error broadcasting transaction: {}", e);
                    }
                });
            }
        Ok(Response::new(Confirmed {}))
    }
}

impl ValidatorService {
    pub async fn make_decision(&self, block: &Block) -> Result<(), ValidatorServiceError> {
        self.broadcast_peer_list().await?;
        let mempool = self.mempool.clone();
        let transactions = block.msg_transactions.clone();
        stream::iter(transactions).for_each_concurrent(None, move |transaction| {
            let mempool = mempool.clone();
            async move {
                mempool.remove(&transaction).await;
            }
        }).await;
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
                let leader_block = LeaderBlock {
                    msg_block: Some(block_clone),
                    msg_leader_address: self_clone.node_service.server_config.read().await.cfg_addr.clone(),
                };
                let req = Request::new(leader_block);
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
        Ok(())
    }
}