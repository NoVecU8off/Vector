use async_trait::async_trait;
use sled::Db;
use vec_errors::errors::*;

#[async_trait]
pub trait IPStorer: Send + Sync {
    async fn put(&self, address: Vec<u8>, ip: String) -> Result<(), IPStorageError>;
    async fn remove(&self, key: &[u8]) -> Result<(), IPStorageError>;
    async fn get(&self) -> Result<Vec<(Vec<u8>, String)>, IPStorageError>;
    async fn get_by_address(&self, address: &[u8]) -> Result<Option<String>, IPStorageError>;
    async fn update(&self, address: &[u8], new_ip: &str) -> Result<(), IPStorageError>;
}

pub struct IPDB {
    ip_db: Db,
}

impl IPDB {
    pub fn new(ip_db: Db) -> Self {
        IPDB { ip_db }
    }
}

#[async_trait]
impl IPStorer for IPDB {
    async fn put(&self, address: Vec<u8>, ip: String) -> Result<(), IPStorageError> {
        let data = (address.clone(), ip);
        let bin = bincode::serialize(&data).map_err(|_| IPStorageError::SerializationError)?;
        self.ip_db
            .insert(&address, bin)
            .map_err(|_| IPStorageError::WriteError)?;
        Ok(())
    }

    async fn remove(&self, key: &[u8]) -> Result<(), IPStorageError> {
        self.ip_db
            .remove(key)
            .map_err(|_| IPStorageError::WriteError)?;
        Ok(())
    }

    async fn get(&self) -> Result<Vec<(Vec<u8>, String)>, IPStorageError> {
        let mut ips = vec![];
        for result in self.ip_db.iter() {
            let (_key, value) = result.map_err(|_| IPStorageError::ReadError)?;
            let data: (Vec<u8>, String) =
                bincode::deserialize(&value).map_err(|_| IPStorageError::DeserializationError)?;
            ips.push(data);
        }
        Ok(ips)
    }

    async fn get_by_address(&self, address: &[u8]) -> Result<Option<String>, IPStorageError> {
        match self.ip_db.get(address) {
            Ok(Some(value)) => {
                let (_stored_address, ip): (Vec<u8>, String) = bincode::deserialize(&value)
                    .map_err(|_| IPStorageError::DeserializationError)?;
                Ok(Some(ip))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(IPStorageError::ReadError),
        }
    }

    async fn update(&self, address: &[u8], new_ip: &str) -> Result<(), IPStorageError> {
        match self.ip_db.get(address) {
            Ok(Some(old_value)) => {
                let (old_address, _old_ip): (Vec<u8>, String) = bincode::deserialize(&old_value)
                    .map_err(|_| IPStorageError::DeserializationError)?;
                let new_data = (old_address, new_ip.to_string());
                let new_data_bin = bincode::serialize(&new_data)
                    .map_err(|_| IPStorageError::SerializationError)?;
                self.ip_db
                    .insert(address, new_data_bin)
                    .map_err(|_| IPStorageError::WriteError)?;
                Ok(())
            }
            Ok(None) => Err(IPStorageError::NotFound),
            Err(_) => Err(IPStorageError::ReadError),
        }
    }
}
