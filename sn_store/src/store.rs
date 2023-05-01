use std::collections::HashMap;
use std::sync::RwLock;
use hex::encode;
use sn_proto::messages::{Block, Transaction};
use sn_transaction::{transaction::hash_transaction};
use sn_block::{block::hash_header_by_block};
use std::sync::Arc;
use anyhow::{Error, Result};
use async_trait::async_trait;

#[derive(Clone, PartialEq, Debug)]
pub struct UTXO {
    pub hash: String,
    pub out_index: u32, // Changed from i32 to u32
    pub amount: i64,
    pub spent: bool,
}

// #[async_trait]
pub trait UTXOStorer: Send + Sync {
    fn put(&mut self, utxo: UTXO) -> Result<(), Error>;
    fn get(&self, hash: &str, out_index: u32) -> Result<Option<UTXO>, Error>;
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

#[async_trait]
impl Clone for MemoryUTXOStore {
    fn clone(&self) -> Self {
        MemoryUTXOStore {
            data: self.data.clone(),
        }
    }
}

#[async_trait]
impl Default for MemoryUTXOStore {
    fn default() -> Self {
        Self::new()
    }
}

// #[async_trait]
impl UTXOStorer for MemoryUTXOStore {
    fn put(&mut self, utxo: UTXO) -> Result<()> {
        let key = format!("{}_{}", utxo.hash, utxo.out_index);
        let mut data = self.data.write().unwrap();
        data.insert(key, utxo);
        Ok(())
    }
    fn get(&self, hash: &str, out_index: u32) -> Result<Option<UTXO>> {
        let key = format!("{}_{}", hash, out_index);
        let data = self.data.read().unwrap();
        Ok(data.get(&key).cloned()) // Cloning the UTXO
    }
}

#[async_trait]
pub trait TXStorer: Send + Sync {
    async fn put(&mut self, tx: Transaction) -> Result<(), Error>;
    async fn get(&self, hash: &str) -> Result<Option<Transaction>, Error>;
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

#[async_trait]
impl TXStorer for MemoryTXStore {
    async fn put(&mut self, tx: Transaction) -> Result<()> {
        let hash = encode(hash_transaction(&tx).await);
        let mut data = self.lock.write().unwrap();
        data.insert(hash, tx);
        Ok(())
    }
    async fn get(&self, hash: &str) -> Result<Option<Transaction>> {
        let data = self.lock.read().unwrap();
        Ok(data.get(hash).cloned())
    }
}

#[async_trait]
impl Default for MemoryTXStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait BlockStorer: Send + Sync {
    async fn put(&self, block: &Block) -> Result<(), Error>;
    async fn get(&self, hash: &str) -> Result<Option<Block>, Error>;
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

#[async_trait]
impl BlockStorer for MemoryBlockStore {
    async fn put(&self, block: &Block) -> Result<()> {
        let mut blocks = self.blocks.write().map_err(|e| anyhow::Error::msg(e.to_string()))?;
        let hash = hash_header_by_block(block).unwrap();
        let hash_str = encode(hash); 
        blocks.insert(hash_str, block.clone());
        Ok(())
    }
    async fn get(&self, hash: &str) -> Result<Option<Block>> {
        let blocks = self.blocks.read().map_err(|e| e.to_string()).unwrap();
        Ok(blocks.get(hash).cloned())  
    }
}

impl Default for MemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}