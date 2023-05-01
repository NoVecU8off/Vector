use sn_cryptography::cryptography::{Keypair, Signature};
use sn_proto::messages::{Transaction};
use ed25519_dalek::PublicKey;
use sha3::{Digest, Sha3_512};
use prost::Message;

pub async fn sign_transaction(keypair: &Keypair, tx: &Transaction) -> Signature {
    let hash = hash_transaction(tx).await;
    keypair.sign(&hash)
}

pub async fn hash_transaction(transaction: &Transaction) -> Vec<u8> {
    let mut transaction_bytes = Vec::new();
    transaction.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Sha3_512::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}

pub async fn hash_transaction_without_signature(transaction: &Transaction) -> Vec<u8> {
    let mut transaction_clone = transaction.clone();
    for input in &mut transaction_clone.msg_inputs {
        input.msg_signature.clear();
    }
    let mut transaction_bytes = Vec::new();
    transaction_clone.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Sha3_512::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}

pub async fn verify_transaction(transaction: &Transaction, public_keys: &[PublicKey]) -> bool {
    for (i, input) in transaction.msg_inputs.iter().enumerate() {
        let public_key = &public_keys[i];
        let sn_signature = Signature::signature_from_vec(&input.msg_signature);
        let signature_bytes = sn_signature.to_bytes(); // assuming this method exists
        let dalek_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes)
            .expect("Failed to convert signature to ed25519_dalek::Signature");
        let transaction_hash = hash_transaction_without_signature(transaction).await;
        if public_key.verify_strict(&transaction_hash, &dalek_signature).is_err() {
            return false;
        }
    }
    true
}

pub async fn verify_transaction_one(transaction: &Transaction, keypairs: &[Keypair]) -> bool {
    for input in &transaction.msg_inputs {
        if input.msg_signature.is_empty() {
            panic!("The transaction has no signature");
        }
        let signature = Signature::signature_from_vec(&input.msg_signature);
        let public_key = PublicKey::from_bytes(&input.msg_public_key).unwrap();
        let message_without_signature = hash_transaction_without_signature(transaction).await;
        let mut verified = false;
        for keypair in keypairs {
            if keypair.public == public_key && keypair.verify(&message_without_signature, &signature) {
                verified = true;
                break;
            }
        }
        if !verified {
            return false;
        }
    }
    true
}