use vec_cryptography::cryptography::{Wallet, Signature};
use vec_proto::messages::{Transaction};
use ed25519_dalek::PublicKey;
use sha3::{Digest, Sha3_256};
use prost::Message;

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

pub fn hash_transaction_without_signature(transaction: &Transaction) -> Vec<u8> {
    let mut transaction_clone = transaction.clone();
    for input in &mut transaction_clone.msg_inputs {
        input.msg_sig.clear();
    }
    let mut transaction_bytes = Vec::new();
    transaction_clone.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}