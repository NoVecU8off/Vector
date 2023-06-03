use sled::Db;
use bincode::{serialize, deserialize};
use async_trait::async_trait;
use vec_errors::errors::*;

pub struct IpDB {
    db: Db,
}

#[async_trait]
pub trait PeerStorer: Send + Sync {
    async fn put_peer_ip(&self, address: String, ip: String) -> Result<(), PeerStorageError>;
    async fn get_peer_ip(&self, address: String) -> Result<Option<String>, PeerStorageError>;
    async fn exist(&self, ip: String) -> Result<bool, PeerStorageError>;
}

impl IpDB {
    pub fn new(db: Db) -> Self {
        IpDB { db }
    }
}

#[async_trait]
impl PeerStorer for IpDB {
    async fn put_peer_ip(&self, address: String, ip: String) -> Result<(), PeerStorageError> {
        let serialized = serialize(&ip).map_err(|_| PeerStorageError::SerializationError)?;
        self.db.insert(address, serialized).map_err(|_| PeerStorageError::WriteError)?;
        Ok(())
    }

    async fn get_peer_ip(&self, address: String) -> Result<Option<String>, PeerStorageError> {
        match self.db.get(address).map_err(|_| PeerStorageError::ReadError)? {
            Some(ivec) => {
                let deserialized: String = deserialize(&*ivec).map_err(|_| PeerStorageError::DeserializationError)?;
                Ok(Some(deserialized))
            },
            None => Ok(None),
        }
    }

    async fn exist(&self, ip: String) -> Result<bool, PeerStorageError> {
        let serialized = serialize(&ip).map_err(|_| PeerStorageError::SerializationError)?;
        for result in self.db.iter() {
            match result {
                Ok((_, value)) => {
                    if &*value == serialized.as_slice() {
                        return Ok(true);
                    }
                },
                Err(_) => return Err(PeerStorageError::ReadError),
            }
        }
        Ok(false)
    }
}
