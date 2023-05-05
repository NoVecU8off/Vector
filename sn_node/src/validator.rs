use crate::node::*;
use sn_transaction::transaction::*;
use std::time::{Duration};
use tonic::codegen::Arc;
use tokio::sync::Mutex;
use log::{info};
use std::collections::HashMap;
use sha3::{Sha3_512, Digest};
use sn_cryptography::cryptography::Keypair;
use sn_cryptography::cryptography::Signature;
use sn_proto::messages::*;

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
}

pub fn process_vote(vote: &Vote, tower: &mut Tower) {
    // Update the validator's lock in the Tower based on the received vote
    tower.update_lock(vote);

    // ... Add any other necessary code here to process the vote, for example:
    // 1. Check if the vote is valid (e.g., the vote is for a block that the local validator is aware of).
    // 2. If a threshold of votes for a specific block is reached, finalize the block and apply it to the local chain.
    // 3. If a block is finalized, propagate the finalized block to other nodes in the network.
    // 4. If the local validator's lock has changed, it should also cast a new vote for the updated lock/block.

    info!("Processed vote from validator {}: block_id={}", vote.msg_validator_id, vote.msg_block_id);
}

#[derive(Clone, Debug)]
pub struct Tower {
    pub locks: HashMap<u64, u64>, // block ID => lock level
}

impl Tower {
    fn update_lock(&mut self, vote: &Vote) {
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
}

fn sign_vote(validator_id: u64, block_id: u64, keypair: &Keypair) -> Vec<u8> {
    let mut hasher = Sha3_512::new();
    hasher.update(validator_id.to_le_bytes());
    hasher.update(block_id.to_le_bytes());
    let message_hash = hasher.finalize();
    keypair.sign(&message_hash).to_bytes().to_vec()
}

fn verify_vote(validator_id: u64, block_id: u64, fingerprint: [u8; 64], keypair: &Keypair) -> bool {
    let mut hasher = Sha3_512::new();
    hasher.update(validator_id.to_le_bytes());
    hasher.update(block_id.to_le_bytes());
    let message_hash = hasher.finalize();
    let signature = Signature::from_bytes(fingerprint);
    keypair.verify(&message_hash, &signature)
}
