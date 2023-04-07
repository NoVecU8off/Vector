use std::collections::HashMap;
use std::sync::RwLock;
use hex::encode;
use sn_proto::messages::{Block, Transaction};
use sn_transaction::{transaction::hash_transaction};
use sn_block::{block::hash_header_by_block};
use std::sync::Arc;

#[derive(Clone, PartialEq, Debug)]
pub struct UTXO {
    pub hash: String,
    pub out_index: u32, // Changed from i32 to u32
    pub amount: i64,
    pub spent: bool,
}

pub trait UTXOStorer {
    fn put(&mut self, utxo: UTXO) -> Result<(), String>;
    fn get(&self, hash: &str, out_index: u32) -> Result<Option<UTXO>, String>; // Add the out_index parameter
}

pub struct MemoryUTXOStore {
    data: Arc<RwLock<HashMap<String, UTXO>>>,
}

impl MemoryUTXOStore {
    pub fn new() -> MemoryUTXOStore {
        MemoryUTXOStore {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Clone for MemoryUTXOStore {
    fn clone(&self) -> Self {
        MemoryUTXOStore {
            data: self.data.clone(),
        }
    }
}

impl UTXOStorer for MemoryUTXOStore {
    fn put(&mut self, utxo: UTXO) -> Result<(), String> {
        let key = format!("{}_{}", utxo.hash, utxo.out_index);
        let mut data = self.data.write().unwrap();
        data.insert(key, utxo);
        Ok(())
    }

    fn get(&self, hash: &str, out_index: u32) -> Result<Option<UTXO>, String> {
        let key = format!("{}_{}", hash, out_index);
        println!("Debug: get key: {}", key); // Add debug print
        let data = self.data.read().unwrap();
        Ok(data.get(&key).cloned()) // Cloning the UTXO
    }
}

pub trait TXStorer {
    fn put(&mut self, tx: Transaction) -> Result<(), String>;
    fn get(&self, hash: &str) -> Result<Option<Transaction>, String>; // Updated return type
}

pub struct MemoryTXStore {
    lock: Arc<RwLock<HashMap<String, Transaction>>>,
}

impl MemoryTXStore {
    pub fn new() -> MemoryTXStore {
        MemoryTXStore {
            lock: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl TXStorer for MemoryTXStore {
    fn put(&mut self, tx: Transaction) -> Result<(), String> {
        let hash = encode(hash_transaction(&tx));
        let mut data = self.lock.write().unwrap();
        data.insert(hash, tx);
        Ok(())
    }

    fn get(&self, hash: &str) -> Result<Option<Transaction>, String> {
        let data = self.lock.read().unwrap();
        Ok(data.get(hash).cloned())
    }
}

pub trait BlockStorer {
    fn put(&self, block: &Block) -> Result<(), String>;
    fn get(&self, hash: &str) -> Result<Option<Block>, String>;
}

pub struct MemoryBlockStore {
    blocks: Arc<RwLock<HashMap<String, Block>>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self {
        MemoryBlockStore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl BlockStorer for MemoryBlockStore {
    fn put(&self, block: &Block) -> Result<(), String> {
        let mut blocks = self.blocks.write().map_err(|e| e.to_string())?;
        let hash = hash_header_by_block(block).map_err(|e| e.to_string())?;
        let hash_str = hex::encode(&hash); 
        blocks.insert(hash_str, block.clone());
        Ok(())
    }

    fn get(&self, hash: &str) -> Result<Option<Block>, String> {
        let blocks = self.blocks.read().map_err(|e| e.to_string())?;
        Ok(blocks.get(hash).cloned())  
    }
}
