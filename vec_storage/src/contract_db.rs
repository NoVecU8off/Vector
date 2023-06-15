use async_trait::async_trait;
use prost::Message;
use sled::Db;
use vec_errors::errors::*;
use vec_proto::messages::Contract;

pub struct ContractDB {
    db: Db,
}

#[async_trait]
pub trait ContractStorer: Send + Sync {
    async fn put(&self, contract: &Contract, address: &str) -> Result<(), ContractStorageError>;
    async fn get(&self, address: &str) -> Result<Option<Contract>, ContractStorageError>;
}

impl ContractDB {
    pub fn new(db: Db) -> Self {
        ContractDB { db }
    }
}

#[async_trait]
impl ContractStorer for ContractDB {
    async fn put(&self, contract: &Contract, address: &str) -> Result<(), ContractStorageError> {
        let mut buf = vec![];
        contract
            .encode(&mut buf)
            .map_err(|_| ContractStorageError::SerializationError)?;

        self.db
            .insert(&address, buf)
            .map_err(|_| ContractStorageError::WriteError)?;

        Ok(())
    }

    async fn get(&self, address: &str) -> Result<Option<Contract>, ContractStorageError> {
        match self.db.get(address) {
            Ok(Some(data)) => {
                let contract = Contract::decode(&*data)
                    .map_err(|_| ContractStorageError::DeserializationError)?;
                Ok(Some(contract))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(ContractStorageError::ReadError),
        }
    }
}
