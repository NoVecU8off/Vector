use async_trait::async_trait;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use sled::Db;
use vec_errors::errors::*;

pub struct ImageDB {
    db: Db,
}

#[async_trait]
pub trait ImageStorer: Send + Sync {
    async fn put(&self, key_image: Vec<u8>) -> Result<(), UTXOStorageError>;
    async fn contains(&self, key_image: Vec<u8>) -> Result<bool, UTXOStorageError>;
}

impl ImageDB {
    pub fn new(db: Db) -> Self {
        ImageDB { db }
    }
}

#[async_trait]
impl ImageStorer for ImageDB {
    async fn put(&self, key_image: Vec<u8>) -> Result<(), UTXOStorageError> {
        let db = self.db.clone();
        let key_image = CompressedRistretto::from_slice(&key_image);
        let key_image_bytes = key_image.as_bytes();
        db.insert(key_image_bytes, &[])
            .map_err(|_| UTXOStorageError::WriteError)?;
        Ok(())
    }

    async fn contains(&self, key_image: Vec<u8>) -> Result<bool, UTXOStorageError> {
        let db = self.db.clone();
        let key_image = CompressedRistretto::from_slice(&key_image);
        let key_image_bytes = key_image.as_bytes();
        match db
            .get(key_image_bytes)
            .map_err(|_| UTXOStorageError::ReadError)?
        {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
}
