use vec_cryptography::cryptography::{NodeKeypair, Signature};
use vec_proto::messages::{Transaction};
use ed25519_dalek::PublicKey;
use sha3::{Digest, Sha3_256};
use prost::Message;

pub async fn sign_transaction(keypair: &NodeKeypair, tx: &Transaction) -> Signature {
    let hash = hash_transaction(tx).await;
    keypair.sign(&hash)
}

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
        input.msg_signature.clear();
    }
    let mut transaction_bytes = Vec::new();
    transaction_clone.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}

pub fn verify_transaction(transaction: &Transaction, public_keys: &[PublicKey]) -> bool {
    for (i, input) in transaction.msg_inputs.iter().enumerate() {
        let public_key = &public_keys[i];
        let vec_signature = Signature::signature_from_vec(&input.msg_signature);
        let signature_bytes = vec_signature.to_bytes();
        let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
            .expect("Failed to convert signature to ed25519_dalek::Signature");
        let transaction_hash = hash_transaction_without_signature(transaction);
        if public_key.verify_strict(&transaction_hash, &dalek_signature).is_err() {
            return false;
        }
    }
    true
}