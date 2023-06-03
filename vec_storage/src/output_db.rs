use vec_errors::errors::*;
use sled::{Db, IVec};
use serde::{Serialize, Deserialize};
use async_trait::async_trait;

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
    pub decrypted_amount: u32,
}

#[async_trait]
pub trait OutputStorer: Send + Sync {
    async fn put(&self, owned_output: &OwnedOutput) -> Result<(), UTXOStorageError>;
    async fn remove(&self, key: &Vec<u8>) -> Result<(), UTXOStorageError>;
    async fn get(&self) -> Result<Vec<OwnedOutput>, UTXOStorageError>;
}

pub struct OutputDB {
    owned_db: Db,
}

impl OutputDB {
    pub fn new(owned_db: Db) -> Self {
        OutputDB {
            owned_db,
        }
    }
}

#[async_trait]
impl OutputStorer for OutputDB {
    async fn put(&self, owned_output: &OwnedOutput) -> Result<(), UTXOStorageError> {
        let owned_bin = bincode::serialize(owned_output).map_err(|_| UTXOStorageError::SerializationError)?;
        self.owned_db.insert(&owned_output.output.stealth, owned_bin).map_err(|_| UTXOStorageError::WriteError)?;
        Ok(())
    }

    async fn remove(&self, key: &Vec<u8>) -> Result<(), UTXOStorageError> {
        self.owned_db.remove(key).map_err(|_| UTXOStorageError::WriteError)?;
        Ok(())
    }

    async fn get(&self) -> Result<Vec<OwnedOutput>, UTXOStorageError> {
        let mut outputs = vec![];
        for result in self.owned_db.iter() {
            let (key, value) = result.map_err(|_| UTXOStorageError::ReadError)?;
            let owned_output: OwnedOutput = bincode::deserialize(&value).map_err(|_| UTXOStorageError::DeserializationError)?;
            outputs.push(owned_output);
        }
        Ok(outputs)
    }
}
