use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sled::Db;
use vec_errors::errors::*;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Output {
    pub stealth: Vec<u8>,
    pub output_key: Vec<u8>,
    pub amount: Vec<u8>,
    pub commitment: Vec<u8>,
    pub range_proof: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct OwnedOutput {
    pub output: Output,
    pub decrypted_amount: u64,
}

#[async_trait]
pub trait OutputStorer: Send + Sync {
    async fn put(&self, owned_output: &OwnedOutput) -> Result<(), OutputStorageError>;
    async fn remove(&self, key: &[u8]) -> Result<(), OutputStorageError>;
    async fn get(&self) -> Result<Vec<OwnedOutput>, OutputStorageError>;
}

pub struct OutputDB {
    owned_db: Db,
}

impl OutputDB {
    pub fn new(owned_db: Db) -> Self {
        OutputDB { owned_db }
    }
}

#[async_trait]
impl OutputStorer for OutputDB {
    async fn put(&self, owned_output: &OwnedOutput) -> Result<(), OutputStorageError> {
        let owned_bin =
            bincode::serialize(owned_output).map_err(|_| OutputStorageError::SerializationError)?;
        self.owned_db
            .insert(&owned_output.output.stealth, owned_bin)
            .map_err(|_| OutputStorageError::WriteError)?;
        Ok(())
    }

    async fn remove(&self, key: &[u8]) -> Result<(), OutputStorageError> {
        self.owned_db
            .remove(key)
            .map_err(|_| OutputStorageError::WriteError)?;
        Ok(())
    }

    async fn get(&self) -> Result<Vec<OwnedOutput>, OutputStorageError> {
        let mut outputs = vec![];
        for result in self.owned_db.iter() {
            let (_key, value) = result.map_err(|_| OutputStorageError::ReadError)?;
            let owned_output: OwnedOutput = bincode::deserialize(&value)
                .map_err(|_| OutputStorageError::DeserializationError)?;
            outputs.push(owned_output);
        }
        Ok(outputs)
    }
}
