use sn_store::store::*;
use hex::encode;
use sn_transaction::transaction::*;
use sn_block::block::*;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput, Block, Header};
use sn_cryptography::cryptography::Keypair;
use sn_merkle::merkle::MerkleTree;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn create_sample_transaction() -> Transaction {
    let keypair = Keypair::generate_keypair();
    let input = TransactionInput {
        msg_previous_tx_hash: (0..64).map(|_| rand::random::<u8>()).collect(),
        msg_previous_out_index: rand::random::<u32>(),
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };
    let output = TransactionOutput {
        msg_amount: rand::random::<i64>(),
        msg_to: (0..32).map(|_| rand::random::<u8>()).collect(),
    };
    Transaction {
        msg_version: rand::random::<i32>(),
        msg_inputs: vec![input],
        msg_outputs: vec![output],
        msg_relative_timestamp: 21,
    }
}

async fn create_sample_block() -> Block {
    let transactions = vec![
        Transaction {
            msg_inputs: vec![],
            msg_outputs: vec![],
            msg_version: 1,
            msg_relative_timestamp: 221,
        },
        Transaction {
            msg_inputs: vec![],
            msg_outputs: vec![],
            msg_version: 1,
            msg_relative_timestamp: 21,
        },
    ];

    let merkle_tree = MerkleTree::new(&transactions).unwrap();
    let merkle_root = merkle_tree.root.to_vec();

    let header = Header {
        msg_version: 1,
        msg_height: 0,
        msg_previous_hash: vec![0; 64],
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };

    let public_key = vec![0; 32];
    let signature = vec![0; 64];

    Block {
        msg_header: Some(header),
        msg_transactions: transactions,
        msg_public_key: public_key,
        msg_signature: signature,
    }
}

#[test]
fn memory_utxo_store() {
    let mut store = MemoryUTXOStore::new();
    let utxo = UTXO {
        hash: "test_hash".to_string(),
        out_index: 0,
        amount: 100,
        spent: false,
    };
    let put_result = store.put(utxo.clone());
    assert!(put_result.is_ok());

    let get_result = store.get(&utxo.hash, utxo.out_index);
    assert_eq!(get_result.unwrap(), Some(utxo));
}

#[tokio::test]
async fn memory_tx_store() {
    let mut store = MemoryTXStore::new();
    let tx = create_sample_transaction();

    let put_result = store.put(tx.clone()).await;
    assert!(put_result.is_ok());

    let hash = encode(hash_transaction(&tx).await);
    let get_result = store.get(&hash).await;
    assert_eq!(get_result.unwrap(), Some(tx));
}

#[tokio::test]
async fn memory_block_store() {
    let store = MemoryBlockStore::new();
    let block = create_sample_block().await;

    let put_result = store.put(&block).await;
    assert!(put_result.is_ok());

    let hash = encode(hash_header_by_block(&block).unwrap());
    let get_result = store.get(&hash).await;
    assert_eq!(get_result.unwrap(), Some(block));
}
