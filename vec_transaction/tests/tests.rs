use vec_transaction::transaction::*;
use vec_cryptography::cryptography::*;
use vec_proto::messages::{Transaction, TransactionInput, TransactionOutput};

#[test]
fn test_generate_seed_thread() {
    let seed = generate_seed_thread();
    assert_eq!(seed.len(), 32);
}

#[test]
fn test_generate_seed_os() {
    let seed = generate_seed_os();
    assert_eq!(seed.len(), 32);
}

#[test]
fn test_inherit_seed() {
    let seed = inherit_seed();
    assert_eq!(seed.len(), 32);
}

#[test]
fn test_generate_keypair() {
    let keypair = NodeKeypair::generate_keypair();
    assert_eq!(keypair.sk.to_bytes().len(), 32);
    assert_eq!(keypair.pk.to_bytes().len(), 32);
}

#[test]
fn test_sign_and_verify() {
    let message = b"Hello, world!";
    let keypair = NodeKeypair::generate_keypair();
    let signature = keypair.sign(message);
    assert!(keypair.verify(message, &signature));
}

#[test]
fn test_sign_and_verify_different_way() {
    let keypair = NodeKeypair::generate_keypair();
    let message = "Hello, world!".as_bytes();

    let signature = keypair.sign(&message);

    println!("message: {:?}", message);
    println!("pk key: {:?}", keypair.pk.as_bytes());
    println!("signature: {:?}", signature.signature.to_bytes());

    assert!(keypair.verify(&message, &signature));
}

fn create_random_transaction() -> Transaction {
    let input = TransactionInput {
        msg_previous_tx_hash: "fdbb;osiajpoascpkknb wlkm;ld".to_string(),
        msg_previous_out_index: rand::random::<u32>(),
        msg_pk: (0..32).map(|_| rand::random::<u8>()).collect(),
        msg_sig: vec![],
    };
    let output = TransactionOutput {
        msg_amount: rand::random::<u64>(),
        msg_to: (0..32).map(|_| rand::random::<u8>()).collect(),
    };
    Transaction {
        msg_inputs: vec![input],
        msg_outputs: vec![output],
        msg_timestamp: 21356,
    }
}

#[tokio::test]
async fn test_hash_transaction() {
    let transaction1 = create_random_transaction();
    let transaction2 = create_random_transaction();

    let hash1 = hash_transaction(&transaction1).await;
    let hash2 = hash_transaction(&transaction2).await;

    assert_ne!(hash1, hash2);
}

#[tokio::test]
async fn test_hash_transaction_without_signature() {
    let mut transaction = create_random_transaction();
    let hash_before_signing = hash_transaction_without_signature(&transaction);

    // Add a random signature
    transaction.msg_inputs[0].msg_sig = (0..64).map(|_| rand::random::<u8>()).collect();

    let hash_after_signing = hash_transaction_without_signature(&transaction);

    assert_eq!(hash_before_signing, hash_after_signing);
}

#[tokio::test]
async fn test_sign_transaction() {
    let keypair = NodeKeypair::generate_keypair();
    let transaction = create_random_transaction();

    let signature = sign_transaction(&keypair, &transaction).await;

    let transaction_hash = hash_transaction(&transaction).await;
    assert!(keypair.verify(&transaction_hash, &signature));
}

#[tokio::test]
async fn test_verify_transaction_two() {
    let keypair = NodeKeypair::generate_keypair();
    let mut transaction = create_random_transaction();

    let signature = sign_transaction(&keypair, &transaction).await;
    transaction.msg_inputs[0].msg_sig = signature.signature.to_bytes().to_vec();

    assert!(verify_transaction(&transaction, &[keypair.pk]));
}