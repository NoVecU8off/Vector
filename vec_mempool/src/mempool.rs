use dashmap::DashMap;
use slog::{info, o, Drain, Logger};
use vec_proto::messages::Transaction;
use vec_transaction::transaction::hash_transaction;

#[derive(Debug)]
pub struct Mempool {
    pub transactions: DashMap<String, Transaction>,
    pub logger: Logger,
}

impl Mempool {
    // Initialisation
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

    // Returns transactions stored in mempool
    pub fn get_transactions(&self) -> Vec<Transaction> {
        self.transactions
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>()
    }

    // Clears the mempool
    pub fn clear(&self) {
        self.transactions.clear();
        info!(self.logger, "Mempool cleared");
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    // Checks if transaction is stored in mempool
    pub async fn has(&self, tx: &Transaction) -> bool {
        let hex_hash = hex::encode(hash_transaction(tx).await);
        self.transactions.contains_key(&hex_hash)
    }

    // Adds transaction to the mempool
    pub async fn add(&self, tx: Transaction) -> bool {
        if self.has(&tx).await {
            return false;
        }
        let hash = hex::encode(hash_transaction(&tx).await);
        self.transactions.insert(hash.clone(), tx);
        info!(self.logger, "Transaction added to mempool: {}", hash);
        true
    }

    // Removes the specific transaction
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

    // Chaecks if the transaction is stored in the mempool by its hash
    pub fn has_hash(&self, hash: &str) -> bool {
        self.transactions.contains_key(hash)
    }

    // Adds a transaction to the mempool via it
    pub async fn add_with_hash(&self, hash: String, tx: Transaction) -> bool {
        if self.has_hash(&hash) {
            return false;
        }
        self.transactions.insert(hash.clone(), tx);
        info!(self.logger, "Transaction added to mempool: {}", hash);
        true
    }

    // Removes transaction by its hash (key)
    pub fn remove_with_hash(&self, hash: &str) -> bool {
        if self.transactions.contains_key(hash) {
            self.transactions.remove(hash);
            info!(self.logger, "Transaction removed from mempool: {}", hash);
            true
        } else {
            false
        }
    }

    // Return the transaction by its hash
    pub fn get_by_hash(&self, hash: &str) -> Option<Transaction> {
        self.transactions
            .get(hash)
            .map(|entry| entry.value().clone())
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use vec_proto::messages::{Transaction, TransactionInput, TransactionOutput};

    #[test]
    fn test_mempool_new() {
        let mempool = Mempool::new();
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_add() {
        let mempool = Mempool::new();
        let transaction = create_test_transaction();
        let result = block_on(mempool.add(transaction.clone()));
        assert_eq!(result, true);
        assert_eq!(block_on(mempool.has(&transaction)), true);
    }

    #[test]
    fn test_mempool_remove() {
        let mempool = Mempool::new();
        let transaction = create_test_transaction();
        let _ = block_on(mempool.add(transaction.clone()));
        assert_eq!(block_on(mempool.has(&transaction)), true);
        let result = block_on(mempool.remove(&transaction));
        assert_eq!(result, true);
        assert_eq!(block_on(mempool.has(&transaction)), false);
    }

    fn create_test_transaction() -> Transaction {
        Transaction {
            msg_inputs: vec![TransactionInput {
                msg_ring: vec![vec![]],
                msg_blsag: vec![],
                msg_message: vec![],
                msg_key_image: vec![],
            }],
            msg_outputs: vec![TransactionOutput {
                msg_stealth_address: vec![],
                msg_output_key: vec![],
                msg_proof: vec![],
                msg_commitment: vec![],
                msg_amount: vec![],
                msg_index: 1,
            }],
        }
    }
}
