use async_trait::async_trait;
use vec_errors::errors::*;
use sled::Db;
use serde::{Serialize, Deserialize};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct UTXO {
    pub transaction_hash: String,
    pub output_index: u32,
    pub amount: u64,
    pub pk: Vec<u8>,
}

#[async_trait]
pub trait UTXOStorer: Send + Sync {
    async fn put(&self, utxo: &UTXO) -> Result<(), UTXOStorageError>;
    async fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError>;
    async fn remove(&self, key: &(String, u32)) -> Result<(), UTXOStorageError>;
    async fn find_by_pk(&self, pk: &[u8]) -> Result<Vec<UTXO>, UTXOStorageError>;
    async fn collect_minimum_utxos(&self, pk: &[u8], amount_needed: u64) -> Result<Vec<UTXO>, UTXOStorageError>;
}

pub struct UTXODB {
    db_th_oi: Db,
    db_pk: Db,
}

impl UTXODB {
    pub fn new(db_th_oi: Db, db_pk: Db) -> Self {
        UTXODB {
            db_th_oi,
            db_pk,
        }
    }
}

#[async_trait]
impl UTXOStorer for UTXODB {
    async fn put(&self, utxo: &UTXO) -> Result<(), UTXOStorageError> {
        let key = (utxo.transaction_hash.clone(), utxo.output_index);
        let key = bincode::serialize(&key).map_err(|_| UTXOStorageError::SerializationError)?;
        let utxo_bin = bincode::serialize(utxo).map_err(|_| UTXOStorageError::SerializationError)?;
        self.db_th_oi.insert(key.clone(), utxo_bin).map_err(|_| UTXOStorageError::WriteError)?;
        let pk = utxo.pk.clone();
        match self.db_pk.get(&pk) {
            Ok(Some(data)) => {
                let mut keys: Vec<Vec<u8>> = bincode::deserialize(&*data).map_err(|_| UTXOStorageError::DeserializationError)?;
                keys.push(key);
                let keys_bin = bincode::serialize(&keys).map_err(|_| UTXOStorageError::SerializationError)?;
                self.db_pk.insert(pk, keys_bin).map_err(|_| UTXOStorageError::WriteError)?;
            },
            Ok(None) => {
                let keys_bin = bincode::serialize(&vec![key]).map_err(|_| UTXOStorageError::SerializationError)?;
                self.db_pk.insert(pk, keys_bin).map_err(|_| UTXOStorageError::WriteError)?;
            },
            Err(_) => return Err(UTXOStorageError::ReadError),
        }
        Ok(())
    }

    async fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError> {
        let key = (transaction_hash.to_string(), output_index);
        let key = bincode::serialize(&key).map_err(|_| UTXOStorageError::SerializationError)?;
        match self.db_th_oi.get(&key) {
            Ok(Some(data)) => {
                let utxo: UTXO = bincode::deserialize(&data).map_err(|_| UTXOStorageError::DeserializationError)?;
                Ok(Some(utxo))
            },
            Ok(None) => Ok(None),
            Err(_) => Err(UTXOStorageError::ReadError),
        }
    }

    async fn remove(&self, key: &(String, u32)) -> Result<(), UTXOStorageError> {
        let key_bin = bincode::serialize(key).map_err(|_| UTXOStorageError::SerializationError)?;
        match self.db_th_oi.get(&key_bin) {
            Ok(Some(data)) => {
                let utxo: UTXO = bincode::deserialize(&*data).map_err(|_| UTXOStorageError::DeserializationError)?;
                self.db_th_oi.remove(key_bin.clone()).map_err(|_| UTXOStorageError::WriteError)?;
                let pk = utxo.pk;
                match self.db_pk.get(&pk) {
                    Ok(Some(data)) => {
                        let mut keys: Vec<Vec<u8>> = bincode::deserialize(&*data).map_err(|_| UTXOStorageError::DeserializationError)?;
                        keys.retain(|k| *k != key_bin);
                        let keys_bin = bincode::serialize(&keys).map_err(|_| UTXOStorageError::SerializationError)?;
                        self.db_pk.insert(pk, keys_bin).map_err(|_| UTXOStorageError::WriteError)?;
                    },
                    Ok(None) => (),
                    Err(_) => return Err(UTXOStorageError::ReadError),
                }
                Ok(())
            },
            Ok(None) => Ok(()),
            Err(_) => Err(UTXOStorageError::ReadError),
        }
    }

    async fn find_by_pk(&self, pk: &[u8]) -> Result<Vec<UTXO>, UTXOStorageError> {
        match self.db_pk.get(pk) {
            Ok(Some(data)) => {
                let keys: Vec<Vec<u8>> = bincode::deserialize(&*data).map_err(|_| UTXOStorageError::DeserializationError)?;
                let mut utxos = Vec::new();
                for key in keys {
                    match self.db_th_oi.get(&key) {
                        Ok(Some(data)) => {
                            let utxo: UTXO = bincode::deserialize(&data).map_err(|_| UTXOStorageError::DeserializationError)?;
                            utxos.push(utxo);
                        },
                        Ok(None) => (),
                        Err(_) => return Err(UTXOStorageError::ReadError),
                    }
                }
                Ok(utxos)
            },
            Ok(None) => Ok(Vec::new()),
            Err(_) => Err(UTXOStorageError::ReadError),
        }
    }

    async fn collect_minimum_utxos(&self, pk: &[u8], amount_needed: u64) -> Result<Vec<UTXO>, UTXOStorageError> {
        let mut utxos = self.find_by_pk(pk).await?;
        utxos.sort_by_key(|utxo| utxo.amount);
        let mut total: u64 = 0;
        let mut collected_utxos = Vec::new();
        for utxo in utxos {
            total += utxo.amount;
            collected_utxos.push(utxo);
            if total >= amount_needed {
                return Ok(collected_utxos);
            }
        }
        Err(UTXOStorageError::InsufficientUtxos)
    }
}