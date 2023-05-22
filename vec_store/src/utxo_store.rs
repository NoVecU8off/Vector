use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::Arc;
use async_trait::async_trait;
use vec_errors::errors::*;

#[derive(Clone, PartialEq, Debug)]
pub struct UTXO {
    pub transaction_hash: String,
    pub output_index: u32,
    pub amount: i64,
    pub public: Vec<u8>,
}

#[async_trait]
pub trait UTXOSetStorer: Send + Sync {
    async fn put(&self, utxo: &UTXO) -> Result<(), UTXOStorageError>;
    async fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError>;
    async fn remove(&self, key: &(String, u32)) -> Result<(), UTXOStorageError>;
    async fn find_by_public_key(&self, public: &[u8]) -> Result<Vec<UTXO>, UTXOStorageError>;
    async fn collect_minimum_utxos(&self, public: &[u8], amount_needed: i64) -> Result<Vec<UTXO>, UTXOStorageError>;
}

#[derive(Debug)]
pub struct MemoryUTXOSet {
    utxos: Arc<RwLock<HashMap<(String, u32), UTXO>>>,
}

impl MemoryUTXOSet {
    pub fn new() -> Self {
        MemoryUTXOSet {
            utxos: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UTXOSetStorer for MemoryUTXOSet {
    async fn put(&self, utxo: &UTXO) -> Result<(), UTXOStorageError> {
        let mut utxos = self.utxos.write().map_err(|_| UTXOStorageError::WriteLockError)?;
        let key = (utxo.transaction_hash.clone(), utxo.output_index);
        utxos.insert(key, utxo.clone());
        Ok(())
    }
    async fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError> {
        let key = (transaction_hash.to_string(), output_index);
        let utxos = self.utxos.read().map_err(|_| UTXOStorageError::ReadLockError)?;
        Ok(utxos.get(&key).cloned())
    }
    async fn remove(&self, key: &(String, u32)) -> Result<(), UTXOStorageError> {
        let mut utxos = self.utxos.write().map_err(|_| UTXOStorageError::WriteLockError)?;
        utxos.remove(key);
        Ok(())
    }
    async fn find_by_public_key(&self, public: &[u8]) -> Result<Vec<UTXO>, UTXOStorageError> {
        let utxos = self.utxos.read().map_err(|_| UTXOStorageError::ReadLockError)?;
        let mut utxos_by_public = Vec::new();
        for utxo in utxos.values() {
            if utxo.public == public {
                utxos_by_public.push(utxo.clone());
            }
        }
        Ok(utxos_by_public)
    }
    async fn collect_minimum_utxos(&self, public: &[u8], amount_needed: i64) -> Result<Vec<UTXO>, UTXOStorageError> {
        let mut utxos = self.find_by_public_key(public).await?;
        utxos.sort_by_key(|utxo| utxo.amount);
        let mut total = 0;
        let mut collected_utxos = vec![];
        for utxo in utxos {
            total += utxo.amount;
            collected_utxos.push(utxo);

            if total >= amount_needed {
                break;
            }
        }
        if total < amount_needed {
            return Err(UTXOStorageError::InsufficientUtxos);
        }
        Ok(collected_utxos)
    }
}

impl Default for MemoryUTXOSet {
    fn default() -> Self {
        Self::new()
    }
}