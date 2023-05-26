use async_trait::async_trait;
use vec_errors::errors::*;
use sled::Db;
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use std::collections::HashMap;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct StakePool {
    pub id: String,
    pub operator: String,
    pub delegator_stakes: HashMap<String, u64>,
}

#[async_trait]
pub trait StakePoolStorer: Send + Sync {
    async fn put(&self, pool: &StakePool) -> Result<(), StakePoolStorageError>;
    async fn get(&self, id: &str) -> Result<Option<StakePool>, StakePoolStorageError>;
    async fn update_delegator_stake(&self, id: &str, delegator: &str, stake: u64) -> Result<(), StakePoolStorageError>; // New method
}

pub struct StakePoolDB {
    db_id: Db,
}

impl StakePoolDB {
    pub fn new(db_id: Db) -> Self {
        StakePoolDB {
            db_id,
        }
    }
}

#[async_trait]
impl StakePoolStorer for StakePoolDB {
    async fn put(&self, pool: &StakePool) -> Result<(), StakePoolStorageError> {
        let id = pool.id.clone();
        let id_bin = bincode::serialize(&id).map_err(|_| StakePoolStorageError::SerializationError)?;
        let pool_bin = bincode::serialize(pool).map_err(|_| StakePoolStorageError::SerializationError)?;
        self.db_id.insert(id_bin.clone(), pool_bin).map_err(|_| StakePoolStorageError::WriteError)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<StakePool>, StakePoolStorageError> {
        let id_bin = bincode::serialize(&id).map_err(|_| StakePoolStorageError::SerializationError)?;
        match self.db_id.get(&id_bin) {
            Ok(Some(data)) => {
                let pool: StakePool = bincode::deserialize(&data).map_err(|_| StakePoolStorageError::DeserializationError)?;
                Ok(Some(pool))
            },
            Ok(None) => Ok(None),
            Err(_) => Err(StakePoolStorageError::ReadError),
        }
    }

    async fn update_delegator_stake(&self, id: &str, delegator: &str, stake: u64) -> Result<(), StakePoolStorageError> {
        let id_bin = bincode::serialize(&id).map_err(|_| StakePoolStorageError::SerializationError)?;
        self.db_id.transaction(|db| {
            match db.get(&id_bin) {
                Ok(Some(data)) => {
                    let pool: Result<StakePool, _> = bincode::deserialize(&data);
                    match pool {
                        Ok(mut pool) => {
                            // Update stake
                            pool.delegator_stakes.insert(delegator.to_string(), stake);
                            // Serialize and store pool
                            let pool_bin = bincode::serialize(&pool).map_err(|_| sled::transaction::ConflictableTransactionError::Abort(StakePoolStorageError::SerializationError))?;
                            db.insert(id_bin.clone(), pool_bin).map_err(|_| sled::transaction::ConflictableTransactionError::Abort(StakePoolStorageError::WriteError))?;
                            Ok(())
                        },
                        Err(_) => Err(sled::transaction::ConflictableTransactionError::Abort(StakePoolStorageError::DeserializationError)),
                    }
                },
                Ok(None) => Err(sled::transaction::ConflictableTransactionError::Abort(StakePoolStorageError::NonexistentPool)),
                Err(_) => Err(sled::transaction::ConflictableTransactionError::Abort(StakePoolStorageError::ReadError)),
            }
        }).map_err(|err| {
            match err {
                sled::transaction::TransactionError::Abort(e) => e,
                sled::transaction::TransactionError::Storage(e) => StakePoolStorageError::SledError(e),
            }
        })
    }
}
