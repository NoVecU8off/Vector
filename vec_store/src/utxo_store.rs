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

pub trait UTXOStorer: Send + Sync {
    fn put(&mut self, utxo: UTXO) -> Result<(), UTXOStorageError>;
    fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError>;
    fn find_utxos(&self, address: &[u8], amount_needed: i64) -> Result<Vec<UTXO>, UTXOStorageError>;
    fn remove_utxo(&mut self, key: &(String, u32)) -> Result<(), UTXOStorageError>;
}

#[derive(Debug)]
pub struct MemoryUTXOStore {
    data: Arc<RwLock<HashMap<(String, u32), UTXO>>>,
    user_utxos: Arc<RwLock<HashMap<Vec<u8>, Vec<UTXO>>>>,
}

impl MemoryUTXOStore {
    pub fn new() -> MemoryUTXOStore {
        MemoryUTXOStore {
            data: Arc::new(RwLock::new(HashMap::new())),
            user_utxos: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Clone for MemoryUTXOStore {
    fn clone(&self) -> Self {
        MemoryUTXOStore {
            data: self.data.clone(),
            user_utxos: self.user_utxos.clone(),
        }
    }
}

#[async_trait]
impl Default for MemoryUTXOStore {
    fn default() -> Self {
        Self::new()
    }
}

impl UTXOStorer for MemoryUTXOStore {
    fn put(&mut self, utxo: UTXO) -> Result<(), UTXOStorageError> {
        let key = (utxo.transaction_hash.clone(), utxo.output_index);
        let mut data = self.data.write().map_err(|_| UTXOStorageError::WriteLockError)?;
        data.insert(key, utxo.clone());
        let mut user_utxos = self.user_utxos.write().map_err(|_| UTXOStorageError::WriteLockError)?;
        user_utxos.entry(utxo.public.clone()).or_insert_with(Vec::new).push(utxo);
        Ok(())
    }
    fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError> {
        let key = (transaction_hash.to_string(), output_index);
        let data = self.data.read().map_err(|_| UTXOStorageError::ReadLockError)?;
        Ok(data.get(&key).cloned())
    }
    fn find_utxos(&self, address: &[u8], amount_needed: i64) -> Result<Vec<UTXO>, UTXOStorageError> {
        let user_utxos = self.user_utxos.read().map_err(|_| UTXOStorageError::ReadLockError)?;        if let Some(utxos) = user_utxos.get(address) {
            let mut sorted_utxos = utxos.clone();
            sorted_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
            let mut total = 0;
            let mut selected_utxos = Vec::new();
            for utxo in sorted_utxos {
                total += utxo.amount;
                selected_utxos.push(utxo);
                if total >= amount_needed {
                    return Ok(selected_utxos);
                }
            }
        }
        Err(UTXOStorageError::InsufficientUtxos)
    }
    fn remove_utxo(&mut self, key: &(String, u32)) -> Result<(), UTXOStorageError> {
        let mut data = self.data.write().map_err(|_| UTXOStorageError::WriteLockError)?;
        if let Some(utxo) = data.remove(key) {
            let mut user_utxos = self.user_utxos.write().map_err(|_| UTXOStorageError::WriteLockError)?;
            if let Some(utxos) = user_utxos.get_mut(&utxo.public) {
                utxos.retain(|u| u.transaction_hash != utxo.transaction_hash || u.output_index != utxo.output_index);
            }
            Ok(())
        } else {
            Err(UTXOStorageError::UtxoNotFound)
        }
    }
}

#[async_trait]
pub trait UTXOSetStorer: Send + Sync {
    async fn put(&self, utxo: &UTXO) -> Result<(), UTXOStorageError>;
    async fn get(&self, transaction_hash: &str, output_index: u32) -> Result<Option<UTXO>, UTXOStorageError>;
    async fn remove(&self, key: &(String, u32)) -> Result<(), UTXOStorageError>;
    async fn find_utxos_by_public_key(&self, public: &[u8]) -> Result<Vec<UTXO>, UTXOStorageError>;
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
    async fn find_utxos_by_public_key(&self, public: &[u8]) -> Result<Vec<UTXO>, UTXOStorageError> {
        let utxos = self.utxos.read().map_err(|_| UTXOStorageError::ReadLockError)?;
        let mut utxos_by_public = Vec::new();
        for utxo in utxos.values() {
            if utxo.public == public {
                utxos_by_public.push(utxo.clone());
            }
        }
        Ok(utxos_by_public)
    }
}

impl Default for MemoryUTXOSet {
    fn default() -> Self {
        Self::new()
    }
}