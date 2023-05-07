use crate::node::*;
use sn_merkle::merkle::MerkleTree;
use sn_block::block::*;
use std::time::{Duration};
use tonic::codegen::Arc;
use tokio::sync::Mutex;
use log::{info, error};
use sha3::{Sha3_512, Digest};
use sn_proto::messages::*;
use anyhow::Result;
use sn_chain::chain::Chain;
use tonic::Request;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct PoHEntry {
    pub relative_timestamp: i64,
    pub transaction_hash: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Validator {
    pub validator_id: i32,
    pub poh_sequence: Arc<Mutex<Vec<PoHEntry>>>,
    pub node_service: Arc<NodeService>,
    pub created_block: Arc<Mutex<Option<Block>>>,
    pub agreement_count: Arc<Mutex<usize>>,
}

impl Validator {
    pub async fn start_validator_tick(&self) {
        let node_clone = self.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let num_transactions = node_clone.node_service.mempool.len().await;
            if num_transactions >= 100 {
                node_clone.initialize_validation().await;
            }
        }
    }

    pub async fn initialize_validation(&self) {
        let public_key_hex = hex::encode(&self.node_service.server_config.cfg_keypair.public.as_bytes());
        let txx = self.node_service.mempool.clear().await;
        info!("\n{}: new block created by {} with {} transactions", self.node_service.server_config.cfg_addr, public_key_hex, txx.len());
    }

    pub async fn start_poh_tick(&self) {
        let node_clone = self.clone();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            node_clone.generate_poh_entry(None).await;
        }
    }

    pub async fn generate_poh_entry(&self, transaction_hash: Option<Vec<u8>>) {
        let mut poh_sequence = self.poh_sequence.lock().await;
        let relative_timestamp = match poh_sequence.last() {
            Some(last_entry) => last_entry.relative_timestamp + 1,
            None => 0,
        };
        let entry_hash = match transaction_hash {
            Some(hash) => {
                let prev_hash = poh_sequence.last().unwrap().transaction_hash.clone();
                let mut combined_hash = prev_hash;
                combined_hash.extend(hash);
                hash_poh_entering_transaction(&combined_hash).await
            }
            None => Vec::new(),
        };
        let entry = PoHEntry {
            relative_timestamp,
            transaction_hash: entry_hash,
        };
        poh_sequence.push(entry);
    }

    pub async fn create_unsigned_block(&self) -> Result<Block> {
        let keypair = &self.node_service.server_config.cfg_keypair;
        let public_key = keypair.public.to_bytes().to_vec();
        let transactions = self.node_service.mempool.clear().await;
        let merkle_tree = MerkleTree::new(&transactions).unwrap();
        let merkle_root = merkle_tree.root.to_vec();
        let header = Header {
            msg_version: 1,
            msg_height: 0,
            msg_previous_hash: vec![],
            msg_root_hash: merkle_root,
            msg_timestamp: 0,
        };
        let block = Block {
            msg_header: Some(header),
            msg_transactions: transactions,
            msg_public_key: public_key,
            msg_signature: vec![],
        };
        let mut created_block_lock = self.created_block.lock().await;
        *created_block_lock = Some(block.clone());
        Ok(block)
    }

    pub async fn finalize_block(&self, chain: &mut Chain) {
        let created_block = {
            let created_block_lock = self.created_block.lock().await;
            created_block_lock.clone()
        };
        if let Some(block) = created_block {
            chain.add_block(block).await.unwrap();
            let mut created_block_lock = self.created_block.lock().await;
            *created_block_lock = None;
        }
    }

    pub async fn hash_unsigned_block(&self, block: &Block) -> Result<Vec<u8>> {
        let hash = hash_header_by_block(block).unwrap().to_vec();
        Ok(hash)
    }

    pub async fn broadcast_unsigned_block_hash(&self, block_hash: &Vec<u8>) -> Result<()> {
        let msg = HashAgreement {
            msg_validator_id: self.validator_id as u64,
            msg_block_hash: block_hash.clone(),
            msg_agreement: true,
            msg_is_responce: false,
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
                let mut req = Request::new(msg_clone);
                req.metadata_mut().insert("peer", addr.parse().unwrap());
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
        for task in tasks {
            task.await?;
        }
        Ok(())
    }

    pub async fn broadcast_received_block_hash(&self, received_block_hash: &Vec<u8>) -> Result<()> {
        let msg = HashAgreement {
            msg_validator_id: self.validator_id as u64,
            msg_block_hash: received_block_hash.clone(),
            msg_agreement: false,
            msg_is_responce: false,
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
                let mut req = Request::new(msg_clone);
                req.metadata_mut().insert("peer", addr.parse().unwrap());
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
        for task in tasks {
            task.await?;
        }
        Ok(())
    }

    pub async fn compare_block_hashes(&self, received_block_hash: &Vec<u8>) -> bool {
        let unsigned_block = self.create_unsigned_block().await.unwrap();
        let local_block_hash = self.hash_unsigned_block(&unsigned_block).await.unwrap();
        received_block_hash == &local_block_hash
    }

    pub async fn tally_agreements(&self, agreements: Vec<(Vec<u8>, bool)>) -> Vec<u8> {
        let mut hash_votes: HashMap<Vec<u8>, usize> = HashMap::new();
        for (hash, agreement) in agreements {
            if agreement {
                *hash_votes.entry(hash).or_insert(0) += 1;
            }
        }
        hash_votes.into_iter()
            .max_by_key(|(_, votes)| *votes)
            .map(|(winning_hash, _)| winning_hash)
            .unwrap_or_else(|| vec![])
    }
}

pub async fn hash_poh_entering_transaction(extended_hash: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(&extended_hash);
    hasher.finalize().to_vec()
}