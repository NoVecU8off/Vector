use async_trait::async_trait;
use prost::Message;
use sled::{Db, IVec};
use vec_errors::errors::*;
use vec_proto::messages::Block;

#[async_trait]
pub trait BlockStorer: Send + Sync {
    async fn put_block(
        &self,
        index: u64,
        hash: Vec<u8>,
        block: &Block,
    ) -> Result<(), BlockStorageError>;
    async fn get(&self, hash: Vec<u8>) -> Result<Option<Block>, BlockStorageError>;
    async fn get_by_index(&self, index: u64) -> Result<Option<Block>, BlockStorageError>;
    async fn get_hash_by_index(&self, index: u64) -> Result<Option<Vec<u8>>, BlockStorageError>;
    async fn get_highest_index(&self) -> Result<Option<u64>, BlockStorageError>;
    async fn is_empty(&self) -> Result<bool, BlockStorageError>;
}

pub struct BlockDB {
    blocks_db: Db,
    index_db: Db,
}

impl BlockDB {
    pub fn new(blocks_db: Db, index_db: Db) -> Self {
        BlockDB {
            blocks_db,
            index_db,
        }
    }
}

#[async_trait]
impl BlockStorer for BlockDB {
    async fn put_block(
        &self,
        index: u64,
        hash: Vec<u8>,
        block: &Block,
    ) -> Result<(), BlockStorageError> {
        let mut block_data = vec![];
        block
            .encode(&mut block_data)
            .map_err(|_| BlockStorageError::SerializationError)?;

        self.blocks_db
            .insert(&hash, block_data)
            .map_err(|_| BlockStorageError::WriteError)?;
        self.index_db
            .insert(&index.to_be_bytes(), IVec::from(hash))
            .map_err(|_| BlockStorageError::WriteError)?;

        Ok(())
    }

    async fn get(&self, hash: Vec<u8>) -> Result<Option<Block>, BlockStorageError> {
        match self.blocks_db.get(&hash) {
            Ok(Some(data)) => {
                let block =
                    Block::decode(&*data).map_err(|_| BlockStorageError::DeserializationError)?;
                Ok(Some(block))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(BlockStorageError::ReadError),
        }
    }

    async fn get_by_index(&self, index: u64) -> Result<Option<Block>, BlockStorageError> {
        match self.index_db.get(&index.to_be_bytes()) {
            Ok(Some(hash)) => self.get(hash.to_vec()).await,
            Ok(None) => Ok(None),
            Err(_) => Err(BlockStorageError::ReadError),
        }
    }

    async fn get_hash_by_index(&self, index: u64) -> Result<Option<Vec<u8>>, BlockStorageError> {
        match self.index_db.get(&index.to_be_bytes()) {
            Ok(Some(hash)) => Ok(Some(hash.to_vec())),
            Ok(None) => Ok(None),
            Err(_) => Err(BlockStorageError::ReadError),
        }
    }

    async fn get_highest_index(&self) -> Result<Option<u64>, BlockStorageError> {
        let mut max_index = None;

        for result in self.index_db.iter() {
            let (key, _) = result.map_err(|_| BlockStorageError::ReadError)?;
            let index = u64::from_be_bytes(
                <[u8; 8]>::try_from(key.as_ref())
                    .map_err(|_| BlockStorageError::DeserializationError)?,
            );

            max_index = max_index.map_or(Some(index), |max: u64| Some(max.max(index)));
        }

        Ok(max_index)
    }

    async fn is_empty(&self) -> Result<bool, BlockStorageError> {
        Ok(self.blocks_db.iter().next().is_none())
    }
}
