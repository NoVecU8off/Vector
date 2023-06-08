use prost::Message;
use sha3::{Digest, Sha3_256};
use vec_proto::messages::Transaction;

pub async fn hash_transaction(transaction: &Transaction) -> Vec<u8> {
    let mut transaction_bytes = Vec::new();
    transaction.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}

pub fn hash_transaction_sync(transaction: &Transaction) -> Vec<u8> {
    let mut transaction_bytes = Vec::new();
    transaction.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use vec_proto::messages::{Transaction, TransactionInput, TransactionOutput};

    #[test]
    fn test_hash_transaction() {
        let transaction1 = create_test_transaction(0);
        let transaction2 = create_test_transaction(1);

        let hash1_async = block_on(hash_transaction(&transaction1));
        let hash1_sync = hash_transaction_sync(&transaction1);

        let hash2_async = block_on(hash_transaction(&transaction2));
        let hash2_sync = hash_transaction_sync(&transaction2);

        assert_eq!(hash1_async, hash1_sync);
        assert_eq!(hash2_async, hash2_sync);

        assert_ne!(hash1_async, hash2_async);
        assert_ne!(hash1_sync, hash2_sync);
    }

    fn create_test_transaction(msg_index: u64) -> Transaction {
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
                msg_index,
            }],
        }
    }
}
