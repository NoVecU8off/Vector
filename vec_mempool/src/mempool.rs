use slog::{o, Logger, info, Drain};
use vec_proto::messages::{Transaction};
use vec_transaction::transaction::hash_transaction;
use dashmap::DashMap;


#[derive(Debug)]
pub struct Mempool {
    pub transactions: DashMap<String, Transaction>,
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
            transactions: DashMap::new(),
            logger,
        }
    }

    pub fn get_transactions(&self) -> Vec<Transaction> {
        self.transactions.iter().map(|entry| entry.value().clone()).collect::<Vec<_>>()
    }

    pub fn clear(&self) {
        self.transactions.clear();
        info!(self.logger, "Mempool cleared");
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub async fn has(&self, tx: &Transaction) -> bool {
        let hex_hash = hex::encode(hash_transaction(tx).await);
        self.transactions.contains_key(&hex_hash)
    }

    pub async fn add(&self, tx: Transaction) -> bool {
        if self.has(&tx).await {
            return false;
        }
        let hash = hex::encode(hash_transaction(&tx).await);
        self.transactions.insert(hash.clone(), tx);
        info!(self.logger, "Transaction added to mempool: {}", hash);
        true
    }

    pub async fn remove(&self, tx: &Transaction) -> bool {
        let hash = hex::encode(hash_transaction(tx).await);
        if self.transactions.contains_key(&hash) {
            self.transactions.remove(&hash);
            info!(self.logger, "Transaction removed from mempool: {}", hash);
            true
        } else {
            false
        }
    }

    pub async fn contains_transaction(&self, transaction: &Transaction) -> bool {
        self.has(transaction).await
    }

    pub fn has_hash(&self, hash: &str) -> bool {
        self.transactions.contains_key(hash)
    }

    pub async fn add_with_hash(&self, hash: String, tx: Transaction) -> bool {
        if self.has_hash(&hash) {
            return false;
        }
        self.transactions.insert(hash.clone(), tx);
        info!(self.logger, "Transaction added to mempool: {}", hash);
        true
    }

    pub fn remove_with_hash(&self, hash: &str) -> bool {
        if self.transactions.contains_key(hash) {
            self.transactions.remove(hash);
            info!(self.logger, "Transaction removed from mempool: {}", hash);
            true
        } else {
            false
        }
    }

    pub fn contains_hash(&self, hash: &str) -> bool {
        self.has_hash(hash)
    }

    pub fn get_by_hash(&self, hash: &str) -> Option<Transaction> {
        self.transactions.get(hash).map(|entry| entry.value().clone())
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}