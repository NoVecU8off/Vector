
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
        },
    ]
}

#[test]
fn test_new() {
    let transactions = sample_transactions();
    let tree = MerkleTree::new(&transactions);

    assert_eq!(tree.get_leaves().len(), transactions.len());
    assert!(!tree.get_root().is_empty());
}

#[test]
fn test_verify() {
    let transactions = sample_transactions();
    let tree = MerkleTree::new(&transactions);

    for (_index, transaction) in transactions.iter().enumerate() {
        let (leaf_index, proof) = tree.get_proof(transaction).unwrap();
        assert!(tree.verify(transaction, leaf_index, &proof));
    }
}

#[test]
fn test_add_leaf() {
    let transactions = sample_transactions();
    let mut tree = if transactions.len() > 1 {
        MerkleTree::new(&transactions[0..1])
    } else {
        MerkleTree::new(&[])
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
    };

    tree.add_leaf(new_transaction.clone());

    assert_ne!(tree.get_root(), &original_root[..]);
    assert_eq!(tree.get_leaves().len(), original_leaves_len + 1);
}

#[test]
fn test_remove_leaf() {
    let transactions = sample_transactions();
    let mut tree = MerkleTree::new(&transactions);

    let original_root = tree.get_root().to_vec();

    assert!(tree.remove_leaf(&transactions[0]));

    assert_ne!(tree.get_root(), &original_root[..]);
    assert_eq!(tree.get_leaves().len(), transactions.len() - 1);
}