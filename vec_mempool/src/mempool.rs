use dashmap::DashMap;
use slog::{info, o, Drain, Logger};
use vec_proto::messages::Transaction;
use vec_utils::utils::hash_transaction;

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
        info!(self.logger, "\nMempool cleared");
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    // Checks if transaction is stored in mempool
    pub fn has(&self, tx: &Transaction) -> bool {
        let bs58_hash = bs58::encode(hash_transaction(tx)).into_string();
        self.transactions.contains_key(&bs58_hash)
    }

    // Adds transaction to the mempool
    pub fn add(&self, tx: Transaction) -> bool {
        if self.has(&tx) {
            return false;
        }
        let bs58_hash = bs58::encode(hash_transaction(&tx)).into_string();
        self.transactions.insert(bs58_hash.clone(), tx);
        info!(self.logger, "\nTransaction added to mempool: {}", bs58_hash);
        true
    }

    // Removes the specific transaction
    pub fn remove(&self, tx: &Transaction) -> bool {
        let bs58_hash = bs58::encode(hash_transaction(tx)).into_string();
        if self.transactions.contains_key(&bs58_hash) {
            self.transactions.remove(&bs58_hash);
            info!(
                self.logger,
                "\nTransaction removed from mempool: {}", bs58_hash
            );
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
    pub fn add_with_hash(&self, hash: String, tx: Transaction) -> bool {
        if self.has_hash(&hash) {
            return false;
        }
        self.transactions.insert(hash.clone(), tx);
        info!(self.logger, "\nTransaction added to mempool: {}", hash);
        true
    }

    // Removes transaction by its hash (key)
    pub fn remove_with_hash(&self, hash: &str) -> bool {
        if self.transactions.contains_key(hash) {
            self.transactions.remove(hash);
            info!(self.logger, "\nTransaction removed from mempool: {}", hash);
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
    use vec_proto::messages::{Contract, Transaction, TransactionInput, TransactionOutput};

    #[test]
    fn test_mempool_new() {
        let mempool = Mempool::new();
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_add() {
        let mempool = Mempool::new();
        let transaction = create_test_transaction();
        let result = mempool.add(transaction.clone());
        assert_eq!(result, true);
        assert_eq!(mempool.has(&transaction), true);
    }

    #[test]
    fn test_mempool_remove() {
        let mempool = Mempool::new();
        let transaction = create_test_transaction();
        let _ = mempool.add(transaction.clone());
        assert_eq!(mempool.has(&transaction), true);
        let result = mempool.remove(&transaction);
        assert_eq!(result, true);
        assert_eq!(mempool.has(&transaction), false);
    }

    fn create_test_transaction() -> Transaction {
        let contract = Contract::default();
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
            msg_contract: Some(contract),
        }
    }
}
