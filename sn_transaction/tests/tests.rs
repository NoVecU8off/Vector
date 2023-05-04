use sn_transaction::transaction::*;
use sn_cryptography::cryptography::*;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};

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
    let keypair = Keypair::generate_keypair();
    assert_eq!(keypair.private.to_bytes().len(), 32);
    assert_eq!(keypair.public.to_bytes().len(), 32);
}

#[test]
fn test_sign_and_verify() {
    let message = b"Hello, world!";
    let keypair = Keypair::generate_keypair();
    let signature = keypair.sign(message);
    assert!(keypair.verify(message, &signature));
}

#[test]
fn test_sign_and_verify_different_way() {
    let keypair = Keypair::generate_keypair();
    let message = "Hello, world!".as_bytes();

    let signature = keypair.sign(&message);

    println!("message: {:?}", message);
    println!("public key: {:?}", keypair.public.as_bytes());
    println!("signature: {:?}", signature.signature.to_bytes());

    assert!(keypair.verify(&message, &signature));
}

#[test]
fn test_derive_address() {
    let keypair = Keypair::generate_keypair();
    let address = keypair.derive_address();
    assert_eq!(address.address.len(), 20);
}

#[test]
fn test_address_to_string() {
    let address = Address::from_bytes([
        119, 2, 129, 224, 245, 161, 44, 24, 46, 93, 89, 87, 144, 63, 53, 63, 33, 64, 92, 127,
    ]);
    println!("{}", address.to_string());
    assert_eq!(
        address.to_string(),
        "770281e0f5a12c182e5d5957903f353f21405c7f"
    );
}

#[test]
fn test_address_from_bytes() {
    let bytes = [
        119, 2, 129, 224, 245, 161, 44, 24, 46, 93, 89, 87, 144, 63, 53, 63, 33, 64, 92, 127,
    ];
    let address = Address::from_bytes(bytes);
    assert_eq!(address.address, bytes);
}

fn create_random_transaction() -> Transaction {
    let input = TransactionInput {
        msg_previous_tx_hash: (0..64).map(|_| rand::random::<u8>()).collect(),
        msg_previous_out_index: rand::random::<u32>(),
        msg_public_key: (0..32).map(|_| rand::random::<u8>()).collect(),
        msg_signature: vec![],
    };
    let output = TransactionOutput {
        msg_amount: rand::random::<i64>(),
        msg_address: (0..32).map(|_| rand::random::<u8>()).collect(),
    };
    Transaction {
        msg_version: rand::random::<i32>(),
        msg_inputs: vec![input],
        msg_outputs: vec![output],
        msg_relative_timestamp: 21356,
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
    transaction.msg_inputs[0].msg_signature = (0..64).map(|_| rand::random::<u8>()).collect();

    let hash_after_signing = hash_transaction_without_signature(&transaction);

    assert_eq!(hash_before_signing, hash_after_signing);
}

#[tokio::test]
async fn test_sign_transaction() {
    let keypair = Keypair::generate_keypair();
    let transaction = create_random_transaction();

    let signature = sign_transaction(&keypair, &transaction).await;

    let transaction_hash = hash_transaction(&transaction).await;
    assert!(keypair.verify(&transaction_hash, &signature));
}

#[tokio::test]
async fn test_verify_transaction_two() {
    let keypair = Keypair::generate_keypair();
    let mut transaction = create_random_transaction();

    let signature = sign_transaction(&keypair, &transaction).await;
    transaction.msg_inputs[0].msg_signature = signature.signature.to_bytes().to_vec();

    assert!(verify_transaction(&transaction, &[keypair.public]));
}