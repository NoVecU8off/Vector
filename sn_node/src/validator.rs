use crate::node::*;
use sn_transaction::transaction::*;
use std::time::{Duration};
use tonic::codegen::Arc;
use tokio::sync::Mutex;
use log::info;
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
}

impl Validator {
    pub async fn start_poh_tick(&self) {
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                node_clone.generate_poh_entry(None).await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    pub async fn start_validator_tick(&self) {
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                let num_transactions = node_clone.node_service.mempool.len().await;
                if num_transactions >= 100 {
                    node_clone.validator_tick().await;
                }
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
    
    pub async fn validator_tick(&self) {
        let public_key_hex = hex::encode(&self.node_service.server_config.cfg_keypair.public.as_bytes());
        let txx = self.node_service.mempool.clear().await;
        info!("\n{}: new block created by {} with {} transactions", self.node_service.server_config.cfg_addr, public_key_hex, txx.len());
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}