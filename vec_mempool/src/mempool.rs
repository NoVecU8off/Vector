use hex::encode;
use slog::{o, Logger, info, Drain};
use tokio::sync::{RwLock};
use std::collections::HashMap;
use vec_proto::messages::{Transaction};
use vec_transaction::transaction::hash_transaction;


#[derive(Debug)]
pub struct Mempool {
    pub lock: RwLock<HashMap<String, Transaction>>,
    pub logger: Logger,
}

impl Mempool {
    pub fn new() -> Self {
        let logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        info!(logger, "Mempool created");
        Mempool {
            lock: RwLock::new(HashMap::new()),
            logger,
        }
    }

    pub async fn get_transactions(&self) -> Vec<Transaction> {
        let lock = self.lock.read().await;
        lock.values().cloned().collect::<Vec<_>>()
    }

    pub async fn clear(&self) {
        let mut lock = self.lock.write().await;
        lock.clear();
        info!(self.logger, "Mempool cleared");
    }

    pub async fn len(&self) -> usize {
        let lock = self.lock.read().await;
        lock.len()
    }

    pub async fn has(&self, tx: &Transaction) -> bool {
        let lock = self.lock.read().await;
        let hex_hash = encode(hash_transaction(tx).await);
        lock.contains_key(&hex_hash)
    }

    pub async fn add(&self, tx: Transaction) -> bool {
        if self.has(&tx).await {
            return false;
        }
        let mut lock = self.lock.write().await;
        let hash = hex::encode(hash_transaction(&tx).await);
        lock.insert(hash.clone(), tx);
        info!(self.logger, "Transaction added to mempool: {}", hash);
        true
    }

    pub async fn remove(&self, tx: &Transaction) -> bool {
        let hash = hex::encode(hash_transaction(tx).await);
        let mut lock = self.lock.write().await;
        if lock.contains_key(&hash) {
            lock.remove(&hash);
            info!(self.logger, "Transaction removed from mempool: {}", hash);
            true
        } else {
            false
        }
    }

    pub async fn contains_transaction(&self, transaction: &Transaction) -> bool {
        self.has(transaction).await
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}