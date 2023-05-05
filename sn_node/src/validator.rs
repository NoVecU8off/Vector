use crate::node::*;
use sn_transaction::transaction::*;
use std::time::{Duration};
use tonic::codegen::Arc;
use tokio::sync::Mutex;
use log::{info, error};
use std::collections::HashMap;
use sha3::{Sha3_512, Digest};
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::*;
use ed25519_dalek::{PublicKey, Verifier, Signature};

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
    pub tower: Arc<Mutex<Tower>>,
}

impl Validator {
    pub async fn start_validator_tick(&self) {
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                let num_transactions = node_clone.node_service.mempool.len().await;
                if num_transactions >= 100 {
                    node_clone.initialize_validation().await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    pub async fn initialize_validation(&self) {
        let public_key_hex = hex::encode(&self.node_service.server_config.cfg_keypair.public.as_bytes());
        let txx = self.node_service.mempool.clear().await;
        info!("\n{}: new block created by {} with {} transactions", self.node_service.server_config.cfg_addr, public_key_hex, txx.len());
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    pub async fn start_poh_tick(&self) {
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                node_clone.generate_poh_entry(None).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
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

    pub async fn propose_block(&self, block_id: u64) {
        let vote = Vote {
            msg_validator_id: self.validator_id as u64,
            msg_block_id: block_id,
            msg_fingerprint: Self::sign_vote(
                self.validator_id as u64,
                block_id,
                &self.node_service.server_config.cfg_keypair,
            ),
        };
        let mut tower = self.tower.lock().await;
    
        self.process_vote(&vote, &mut *tower).await;
        let vote_batch = VoteBatch { votes: vec![vote] };
        self.broadcast_vote_batch(&vote_batch).await;
    }
    
    // Call this function when a new block is created by the validator
    pub async fn on_block_created(&self, block_id: u64) {
        self.propose_block(block_id).await;
    }

    // Add this to the NodeService struct
    pub async fn broadcast_vote_batch(&self, vote_batch: &VoteBatch) {
        let vote_batch = vote_batch.clone();
        let peers = self.node_service.peer_lock.read().await;
        for (_, (peer, _)) in peers.iter() {
            let mut peer = peer.lock().await;
            let _ = peer.handle_votes(vote_batch.clone()).await;
        }
    }

    pub fn sign_vote(validator_id: u64, block_id: u64, keypair: &Keypair) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(validator_id.to_le_bytes());
        hasher.update(block_id.to_le_bytes());
        let message_hash = hasher.finalize();
        keypair.sign(&message_hash).to_bytes().to_vec()
    }
    
    pub fn verify_vote(validator_id: u64, block_id: u64, fingerprint: [u8; 64], public_key: &[u8]) -> bool {
        let mut hasher = Sha3_512::new();
        hasher.update(validator_id.to_le_bytes());
        hasher.update(block_id.to_le_bytes());
        let message_hash = hasher.finalize();
        let signature = Signature::from_bytes(&fingerprint).unwrap();
        let public_key = PublicKey::from_bytes(public_key).unwrap();
        public_key.verify(&message_hash, &signature).is_ok()
    }

    pub async fn process_vote(&self, vote: &Vote, tower: &mut Tower) {
        let validator_id = vote.msg_validator_id;
        let block_id = vote.msg_block_id;
        let fingerprint = &vote.msg_fingerprint;
        let all_peers = self.node_service.peer_lock.read().await;
        if let Some((_, version)) = all_peers.get(&validator_id.to_string()) {
            let peer_public_key = &version.msg_public_key;
            let fingerprint_array = match fingerprint.as_slice().try_into() {
                Ok(array) => array,
                Err(e) => {
                    error!("Failed to convert fingerprint Vec<u8> to [u8; 64]: {:?}", e);
                    return;
                }
            };
            if Self::verify_vote(validator_id, block_id, fingerprint_array, &peer_public_key) {
                tower.update_lock(vote);
                info!("Processed vote from validator {}: block_id={}, fingerprint={:?}", validator_id, block_id, fingerprint);
                let vote_batch = VoteBatch { votes: vec![vote.clone()] };
                self.broadcast_vote_batch(&vote_batch).await;
            } else {
                error!("Failed to verify vote from validator {}: block_id={}, fingerprint={:?}", validator_id, block_id, fingerprint);
            }
        } else {
            error!("Validator {} not found in the peer list", validator_id);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Tower {
    pub locks: HashMap<u64, u64>, // block ID => lock level
}

impl Tower {
    pub fn update_lock(&mut self, vote: &Vote) {
        let validator_id = vote.msg_validator_id;
        let block_id = vote.msg_block_id;
        if let Some(current_lock) = self.locks.get_mut(&validator_id) {
            if *current_lock < block_id {
                *current_lock = block_id;
            }
        } else {
            self.locks.insert(validator_id, block_id);
        }
    }

    pub fn get_finalized_blocks(&self) -> Vec<u64> {
        self.locks.iter().filter_map(|(_, &lock_level)| {
            if lock_level >= self.locks.len() as u64 - 1 {
                Some(lock_level)
            } else {
                None
            }
        }).collect()
    }
}

