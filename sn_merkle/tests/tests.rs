use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};
use sn_merkle::merkle::*;

fn sample_transactions() -> Vec<Transaction> {
    vec![
        Transaction {
            msg_version: 1,
            msg_inputs: vec![
                TransactionInput {
                    msg_previous_tx_hash: vec![1, 2, 3],
                    msg_previous_out_index: 0,
                    msg_public_key: vec![4, 5, 6],
                    msg_signature: vec![7, 8, 9],
                },
            ],
            msg_outputs: vec![
                TransactionOutput {
                    msg_amount: 100,
                    msg_address: vec![10, 11, 12],
                },
            ],
            msg_relative_timestamp: 583,
        },
        Transaction {
            msg_version: 2,
            msg_inputs: vec![
                TransactionInput {
                    msg_previous_tx_hash: vec![11, 2, 3],
                    msg_previous_out_index: 0,
                    msg_public_key: vec![41, 5, 6],
                    msg_signature: vec![71, 8, 9],
                },
            ],
            msg_outputs: vec![
                TransactionOutput {
                    msg_amount: 1100,
                    msg_address: vec![101, 11, 12],
                },
            ],
            msg_relative_timestamp: 8646,
        },
    ]
}

#[tokio::test]
async fn test_new() {
    let transactions = sample_transactions();
    let tree = MerkleTree::new(&transactions).unwrap();

    assert_eq!(tree.get_leaves().len(), transactions.len());
    assert!(!tree.get_root().is_empty());
}

#[tokio::test]
async fn test_verify() {
    let transactions = sample_transactions();
    let tree = MerkleTree::new(&transactions).unwrap();
    for (_index, transaction) in transactions.iter().enumerate() {
        if let Some((leaf_index, proof)) = tree.get_proof(transaction).await.unwrap() {
            assert!(tree.verify(transaction, leaf_index, &proof).await.unwrap());
        } else {
            panic!("Proof not found for transaction");
        }
    }
}



#[tokio::test]
async fn test_add_leaf() {
    let transactions = sample_transactions();
    let mut tree = if transactions.len() > 1 {
        MerkleTree::new(&transactions[0..1]).unwrap()
    } else {
        MerkleTree::new(&[]).unwrap()
    };

    let original_root = tree.get_root().to_vec();
    let original_leaves_len = tree.get_leaves().len();

    // Create a new transaction to add to the Merkle tree
    let new_transaction = Transaction {
        msg_version: 2,
        msg_inputs: vec![
            TransactionInput {
                msg_previous_tx_hash: vec![11, 2, 3],
                msg_previous_out_index: 0,
                msg_public_key: vec![41, 5, 6],
                msg_signature: vec![71, 8, 9],
            },
        ],
        msg_outputs: vec![
            TransactionOutput {
                msg_amount: 1100,
                msg_address: vec![101, 11, 12],
            },
        ],
        msg_relative_timestamp: 327,
    };

    tree.add_leaf(new_transaction.clone());

    assert_ne!(tree.get_root(), &original_root[..]);
    assert_eq!(tree.get_leaves().len(), original_leaves_len + 1);
}

#[tokio::test]
async fn test_remove_leaf() {
    let transactions = sample_transactions();
    let mut tree = MerkleTree::new(&transactions).unwrap();

    let original_root = tree.get_root().to_vec();

    assert!(tree.remove_leaf(&transactions[0]).await.unwrap());

    assert_ne!(tree.get_root(), &original_root[..]);
    assert_eq!(tree.get_leaves().len(), transactions.len() - 1);
}