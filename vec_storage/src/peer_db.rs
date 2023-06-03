use sled::Db;
use prost::Message;
use async_trait::async_trait;
use vec_errors::errors::*;
use vec_proto::messages::Version;

pub struct PeerDB {
    db: Db,
}

#[async_trait]
pub trait PeerStorer: Send + Sync {
    async fn put(&self, public_view_key: Vec<u8>, public_spend_key: Vec<u8>, version: Version) -> Result<(), PeerStorageError>;
    async fn get(&self, public_view_key: Vec<u8>, public_spend_key: Vec<u8>) -> Result<Option<Version>, PeerStorageError>;
}

impl PeerDB {
    pub fn new(db: Db) -> Self {
        PeerDB {
            db,
        }
    }
}

#[async_trait]
impl PeerStorer for PeerDB {
    async fn put(&self, public_view_key: Vec<u8>, public_spend_key: Vec<u8>, version: Version) -> Result<(), PeerStorageError> {
        let key = [public_view_key.as_slice(), public_spend_key.as_slice()].concat();
        
        // Serialize the version message to bytes
        let mut buf = Vec::new();
        version.encode(&mut buf).map_err(|_| PeerStorageError::SerializationError)?;

        self.db.insert(key, buf).map_err(|_| PeerStorageError::WriteError)?;
        Ok(())
    }

    async fn get(&self, public_view_key: Vec<u8>, public_spend_key: Vec<u8>) -> Result<Option<Version>, PeerStorageError> {
        let key = [public_view_key.as_slice(), public_spend_key.as_slice()].concat();

        match self.db.get(&key).map_err(|_| PeerStorageError::ReadError)? {
            Some(ivec) => {
                let version = Version::decode(&*ivec).map_err(|_| PeerStorageError::DeserializationError)?;
                Ok(Some(version))
            },
            None => Ok(None),
        }
    }
}