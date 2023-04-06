use sn_store::store::*;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput, Block, Header};
use sn_transaction::transaction::*;
use sn_block::block::*;
use sn_cryptography::cryptography::*;
use std::thread;
use std::sync::mpsc;

fn create_sample_utxo() -> UTXO {
    UTXO {
        hash: "sample_hash".to_string(),
        out_index: 0,
        amount: 100,
        spent: false,
    }
}
fn create_sample_transaction() -> Transaction {
    Transaction {
        msg_version: 1,
        msg_inputs: vec![TransactionInput {
            msg_previous_tx_hash: vec![0; 32], // Updated field
            msg_previous_out_index: 0, // Updated field
            msg_public_key: vec![0; 32],
            msg_signature: vec![0; 64],
        }],
        msg_outputs: vec![TransactionOutput {
            msg_amount: 100,
            msg_address: vec![0; 32], // Updated field
        }],
    }
}

fn create_sample_block() -> Block {
    Block {
        msg_header: Some(Header {
            msg_version: 1,
            msg_height: 0, // Added missing field
            msg_previous_hash: vec![0; 32], // Updated field
            msg_root_hash: vec![0; 32], // Updated field
            msg_timestamp: 0,
        }),
        msg_transactions: vec![create_sample_transaction()], // Updated field
        msg_public_key: vec![0; 32], // Added missing field
        msg_signature: vec![0; 64], // Added missing field
    }
}

#[test]
fn test_memory_utxo_store() {
    let mut utxo_store = MemoryUTXOStore::new();
    let utxo = create_sample_utxo();
    let key = format!("{}_{}", utxo.hash, utxo.out_index);

    // Test put
    assert!(utxo_store.put(utxo.clone()).is_ok());

    // Test get
    let retrieved_utxo_result = utxo_store.get(&utxo.hash, utxo.out_index).unwrap();
    println!("Debug: test key: {}", key); // Add debug print
    println!("Debug: retrieved_utxo_result: {:?}", retrieved_utxo_result); // Add debug print
    let retrieved_utxo = retrieved_utxo_result.unwrap();
    assert_eq!(utxo, retrieved_utxo);
}

#[test]
fn test_memory_tx_store() {
    let mut tx_store = MemoryTXStore::new();
    let tx = create_sample_transaction();
    let tx_hash = hex::encode(hash_transaction(&tx));

    // Test put
    assert!(tx_store.put(tx.clone()).is_ok());

    // Test get
    let retrieved_tx = tx_store.get(&tx_hash).unwrap().unwrap();
    assert_eq!(tx, retrieved_tx);
}

#[test]
fn test_memory_block_store() {
    let block_store = MemoryBlockStore::new();
    let block = create_sample_block();
    let block_hash = hex::encode(hash_header_by_block(&block).unwrap());

    // Test put
    assert!(block_store.put(&block).is_ok());

    // Test get
    let retrieved_block = block_store.get(&block_hash).unwrap().unwrap();
    assert_eq!(block, retrieved_block);
}

#[test]
fn memory_tx_store_put_get() {
    let mut tx_store = MemoryTXStore::new();

    let keypair = Keypair::generate_keypair();
    let tx = Transaction {
        msg_version: 1,
        msg_inputs: vec![TransactionInput {
            msg_previous_tx_hash: vec![0; 32],
            msg_previous_out_index: 0,
            msg_public_key: keypair.public.to_bytes().to_vec(),
            msg_signature: vec![0; 64],
        }],
        msg_outputs: vec![TransactionOutput {
            msg_amount: 1000,
            msg_address: vec![0; 32],
        }],
    };

    tx_store.put(tx.clone()).unwrap();

    let tx_hash = hex::encode(hash_transaction(&tx));
    let retrieved_tx = tx_store.get(&tx_hash).unwrap();

    assert_eq!(Some(tx), retrieved_tx);
}

#[test]
fn memory_block_store_put_get() {
    let block_store = MemoryBlockStore::new();

    let block = Block {
        msg_header: Some(Header {
            msg_version: 1,
            msg_height: 0,
            msg_previous_hash: vec![0; 32],
            msg_root_hash: vec![0; 32],
            msg_timestamp: 0,
        }),
        msg_transactions: vec![],
        msg_public_key: vec![0; 32],
        msg_signature: vec![0; 64],
    };

    block_store.put(&block).unwrap();

    let block_hash = hex::encode(hash_header_by_block(&block).unwrap());
    let retrieved_block = block_store.get(&block_hash).unwrap();

    assert_eq!(Some(block), retrieved_block);
}

#[test]
fn memory_utxo_store_concurrent_access() {
    let utxo_store = MemoryUTXOStore::new();
    let utxo = UTXO {
        hash: "hash_1".to_string(),
        out_index: 0,
        amount: 1000,
        spent: false,
    };

    let (tx, rx) = mpsc::channel();
    let mut utxo_store_clone = utxo_store.clone();
    let utxo_clone = utxo.clone();
    let writer = thread::spawn(move || {
        utxo_store_clone.put(utxo_clone).unwrap();
        tx.send(()).unwrap();
    });

    let utxo_store_clone = utxo_store.clone();
    let reader = thread::spawn(move || {
        rx.recv().unwrap(); // Wait for the writer to finish
        let retrieved_utxo = utxo_store_clone.get("hash_1", 0).unwrap(); // Pass out_index to the get method
        assert_eq!(Some(utxo.clone()), retrieved_utxo);
    });

    writer.join().unwrap();
    reader.join().unwrap();
}