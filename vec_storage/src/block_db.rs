use hex::encode;
use vec_proto::messages::{Block};
use vec_errors::errors::*;
use async_trait::async_trait;
use sled::Db;
use prost::Message;

#[async_trait]
pub trait BlockStorer: Send + Sync {
    async fn put(&self, hash: Vec<u8>, block: &Block) -> Result<(), BlockStorageError>;
    async fn get(&self, hash: &str) -> Result<Option<Block>, BlockStorageError>;
}

pub struct BlockDB {
    db: Db,
}

impl BlockDB {
    pub fn new(db: Db) -> Self {
        BlockDB {
            db,
        }
    }
}

#[async_trait]
impl BlockStorer for BlockDB {
    async fn put(&self, hash: Vec<u8>, block: &Block) -> Result<(), BlockStorageError> {
        let hash_str = encode(hash);
        let mut block_data = vec![];
        block.encode(&mut block_data).map_err(|_| BlockStorageError::SerializationError)?;
        self.db.insert(hash_str, block_data).map_err(|_| BlockStorageError::WriteError)?;
        Ok(())
    }
    async fn get(&self, hash: &str) -> Result<Option<Block>, BlockStorageError> {
        match self.db.get(hash) {
            Ok(Some(data)) => {
                let block = Block::decode(&*data).map_err(|_| BlockStorageError::DeserializationError)?;
                Ok(Some(block))
            },
            Ok(None) => Ok(None),
            Err(_) => Err(BlockStorageError::ReadError),
        }
    }
}
