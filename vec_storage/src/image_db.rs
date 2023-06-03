use sled::{Db, IVec};
use curve25519_dalek_ng::{traits::Identity, constants, scalar::Scalar, ristretto::RistrettoPoint, ristretto::CompressedRistretto};

pub struct KeyImageDB {
    db: Db,
}

impl KeyImageDB {
    pub fn new(db: Db) -> Self {
        KeyImageDB {
            db,
        }
    }

    pub fn put(&self, key_image: CompressedRistretto) -> sled::Result<()> {
        let key_image_bytes = key_image.as_bytes();
        self.db.insert(key_image_bytes, &[])?;
        Ok(())
    }

    pub fn contains(&self, key_image: CompressedRistretto) -> sled::Result<bool> {
        let key_image_bytes = key_image.as_bytes();
        match self.db.get(key_image_bytes)? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
}
