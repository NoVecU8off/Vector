use std::collections::HashMap;
use std::sync::{RwLock, PoisonError};
use hex::encode;
use vec_proto::messages::{Block};
use vec_block::block::*;
use std::sync::Arc;
use async_trait::async_trait;

#[derive(Debug)]
pub enum StoreError {
    PoisonError(String),
    BlockHashError(BlockError),
}

impl<T> From<PoisonError<T>> for StoreError {
    fn from(err: PoisonError<T>) -> StoreError {
        StoreError::PoisonError(err.to_string())
    }
}

impl From<BlockError> for StoreError {
    fn from(err: BlockError) -> StoreError {
        StoreError::BlockHashError(err)
    }
}

#[async_trait]
pub trait BlockStorer: Send + Sync {
    async fn put(&self, block: &Block) -> Result<(), StoreError>;
    async fn get(&self, hash: &str) -> Result<Option<Block>, StoreError>;
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
    async fn put(&self, block: &Block) -> Result<(), StoreError> {
        let mut blocks = self.blocks.write()?;
        let hash = hash_header_by_block(block)?;
        let hash_str = encode(hash); 
        blocks.insert(hash_str, block.clone());
        Ok(())
    }
    async fn get(&self, hash: &str) -> Result<Option<Block>, StoreError> {
        let blocks = self.blocks.read()?;
        Ok(blocks.get(hash).cloned())  
    }
}

impl Default for MemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}
