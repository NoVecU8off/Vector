use std::collections::HashMap;
use std::sync::{RwLock};
use hex::encode;
use vec_proto::messages::{Block};
use vec_block::block::*;
use vec_errors::errors::*;
use std::sync::Arc;
use async_trait::async_trait;

#[async_trait]
pub trait BlockStorer: Send + Sync {
    async fn put(&self, block: &Block) -> Result<(), BlockStorageError>;
    async fn get(&self, hash: &str) -> Result<Option<Block>, BlockStorageError>;
}

#[derive(Debug)]
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
    async fn put(&self, block: &Block) -> Result<(), BlockStorageError> {
        let mut blocks = self.blocks.write().map_err(|_| BlockStorageError::WriteLockError)?;
        let hash = hash_header_by_block(block)?;
        let hash_str = encode(hash); 
        blocks.insert(hash_str, block.clone());
        Ok(())
    }
    async fn get(&self, hash: &str) -> Result<Option<Block>, BlockStorageError> {
        let blocks = self.blocks.read().map_err(|_| BlockStorageError::ReadLockError)?;
        Ok(blocks.get(hash).cloned())  
    }
}

impl Default for MemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}
