use hex::encode;
use slog::{o, Logger, info, Drain};
use tokio::sync::{RwLock};
use std::collections::HashMap;
use sn_proto::messages::Transaction;
use sn_transaction::transaction::hash_transaction;

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
        info!(logger, "\nMempool created");
        Mempool {
            lock: RwLock::new(HashMap::new()),
            logger,
        }
    }

    pub async fn clear(&self) -> Vec<Transaction> {
        let mut lock = self.lock.write().await;
        let txx = lock.values().cloned().collect::<Vec<_>>();
        lock.clear();
        info!(self.logger, "\nMempool cleared, {} transactions removed", txx.len());
        txx
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
        info!(self.logger, "\nTransaction added to mempool: {}", hash);
        true
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}