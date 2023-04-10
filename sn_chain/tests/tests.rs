use sn_chain::chain::*;
use sn_store::store::*;
use sn_block::block::*;
use sn_cryptography::cryptography::*;
use sn_transaction::transaction::*;
use sn_proto::messages::*;
use sn_merkle::merkle::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn create_test_chain() -> Chain {
    let block_store = Box::new(MemoryBlockStore::new());
    let tx_store = Box::new(MemoryTXStore::new());
    Chain::new_chain(block_store, tx_store).expect("Failed to create test chain")
}

#[test]
fn test_create_genesis_block() {
    let genesis_block = create_genesis_block();
    assert_eq!(genesis_block.msg_header.as_ref().unwrap().msg_height, 0);
    assert_eq!(genesis_block.msg_transactions.len(), 1);
}

#[test]
fn test_new_chain() {
    let chain = create_test_chain();
    assert_eq!(chain.chain_len(), 1);
    assert_eq!(chain.chain_height(), 0);
}

#[test]
fn test_add_block() {
    let mut chain = create_test_chain();
    let genesis_block = chain.get_block_by_height(0).unwrap();
    let input_tx = &genesis_block.msg_transactions[0];
    let input_tx_hash = hash_transaction(input_tx);
    let input_amount = input_tx.msg_outputs[0].msg_amount;

    let keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&keypair);

    let mut input = TransactionInput {
        msg_previous_tx_hash: input_tx_hash,
        msg_previous_out_index: 0,
        msg_public_key: vec![],
        msg_signature: vec![],
    };

    let output = TransactionOutput {
        msg_amount: input_amount,
        msg_address: address.to_bytes().to_vec(),
    };

    let mut new_transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![input.clone()],
        msg_outputs: vec![output],
    };

    let signature = sign_transaction(&keypair, &new_transaction);
    input.msg_signature = signature.to_vec();
    input.msg_public_key = keypair.public.to_bytes().to_vec();
    new_transaction.msg_inputs[0] = input;

    let merkle_tree = MerkleTree::new(&[new_transaction.clone()]);
    let merkle_root = merkle_tree.root.to_vec();

    let prev_header = genesis_block.msg_header.as_ref().unwrap();
    let header = Header {
        msg_version: 1,
        msg_height: prev_header.msg_height + 1,
        msg_previous_hash: hash_header(prev_header).unwrap().to_vec(),
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };

    let mut new_block = Block {
        msg_header: Some(header),
        msg_transactions: vec![new_transaction],
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };

    let signature = sign_block(&new_block, &keypair).unwrap();
    new_block.msg_signature = signature.to_vec();

    assert!(chain.add_block(new_block).is_ok());
}

#[test]
fn test_get_block_by_height() {
    let chain = create_test_chain();
    let result = chain.get_block_by_height(0);
    assert!(result.is_ok());
    let block = result.unwrap();
    assert_eq!(block.msg_header.as_ref().unwrap().msg_height, 0);
}

#[test]
fn test_get_block_by_hash() {
    let chain = create_test_chain();
    let block = chain.get_block_by_height(0).unwrap();
    let hash = hash_header_by_block(&block).unwrap();
    let result = chain.get_block_by_hash(&hash);
    assert!(result.is_ok());
    let retrieved_block = result.unwrap();
    assert_eq!(retrieved_block.msg_header.as_ref().unwrap().msg_height, 0);
}

#[test]
fn test_validate_block() {
    let mut chain = create_test_chain();
    let genesis_block = chain.get_block_by_height(0).unwrap();
    let input_tx = &genesis_block.msg_transactions[0];
    let input_tx_hash = hash_transaction(input_tx);
    let input_amount = input_tx.msg_outputs[0].msg_amount;

    let keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&keypair);

    let mut input = TransactionInput {
        msg_previous_tx_hash: input_tx_hash,
        msg_previous_out_index: 0,
        msg_public_key: vec![],
        msg_signature: vec![],
    };

    let output = TransactionOutput {
        msg_amount: input_amount,
        msg_address: address.to_bytes().to_vec(),
    };

    let mut new_transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![input.clone()],
        msg_outputs: vec![output],
    };

    let signature = sign_transaction(&keypair, &new_transaction);
    input.msg_signature = signature.to_vec();
    input.msg_public_key = keypair.public.to_bytes().to_vec();
    new_transaction.msg_inputs[0] = input;

    let merkle_tree = MerkleTree::new(&[new_transaction.clone()]);
    let merkle_root = merkle_tree.root.to_vec();

    let prev_header = genesis_block.msg_header.as_ref().unwrap();
    let header = Header {
        msg_version: 1,
        msg_height: prev_header.msg_height + 1,
        msg_previous_hash: hash_header(prev_header).unwrap().to_vec(),
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };

    let mut new_block = Block {
        msg_header: Some(header),
        msg_transactions: vec![new_transaction],
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };

    let signature = sign_block(&new_block, &keypair).unwrap();
    new_block.msg_signature = signature.to_vec();
    chain.add_block(new_block.clone()).expect("ERROR DURING ADD BLOCK");
    let result = chain.validate_block(&new_block);
    assert!(result.is_ok());
}

#[test]
fn test_validate_transaction() {
    let chain = create_test_chain();
    let genesis_block = chain.get_block_by_height(0).unwrap();
    let transaction = &genesis_block.msg_transactions[0];
    let keypair = Keypair::generate_keypair();
    let result = chain.validate_transaction(transaction, &[keypair]);
    assert!(result.is_ok());
}








// #[test]
// fn test_add_block() -> Result<(), Box<dyn std::error::Error>> {
//     let mut chain = create_test_chain().expect("Failed to create test chain");
//     let genesis_block = chain.get_block_by_height(0).unwrap();
//     let input_tx = &genesis_block.msg_transactions[0];
//     let input_tx_hash = hash_transaction(input_tx);
//     let input_amount = input_tx.msg_outputs[0].msg_amount;

//     let keypair = Keypair::generate_keypair();
//     let address = Keypair::derive_address(&keypair);

//     let mut input = TransactionInput {
//         msg_previous_tx_hash: input_tx_hash,
//         msg_previous_out_index: 0,
//         msg_public_key: vec![],
//         msg_signature: vec![],
//     };

//     let output = TransactionOutput {
//         msg_amount: input_amount,
//         msg_address: address.to_bytes().to_vec(),
//     };

//     let mut new_transaction = Transaction {
//         msg_version: 1,
//         msg_inputs: vec![input.clone()],
//         msg_outputs: vec![output],
//     };

//     let signature = sign_transaction(&keypair, &new_transaction);
//     input.msg_signature = signature.to_vec();
//     input.msg_public_key = keypair.public.to_bytes().to_vec();
//     new_transaction.msg_inputs[0] = input;

//     let merkle_tree = MerkleTree::new(&[new_transaction.clone()]);
//     let merkle_root = merkle_tree.root.to_vec();

//     let prev_header = genesis_block.msg_header.as_ref().unwrap();
//     let header = Header {
//         msg_version: 1,
//         msg_height: prev_header.msg_height + 1,
//         msg_previous_hash: hash_header(prev_header).unwrap().to_vec(),
//         msg_root_hash: merkle_root,
//         msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
//     };

//     let mut new_block = Block {
//         msg_header: Some(header),
//         msg_transactions: vec![new_transaction],
//         msg_public_key: keypair.public.to_bytes().to_vec(),
//         msg_signature: vec![],
//     };

//     let signature = sign_block(&new_block, &keypair).unwrap();
//     new_block.msg_signature = signature.to_vec();

//     assert!(chain.add_block(new_block).is_ok());
//     Ok(())
// }