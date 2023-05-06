use sn_chain::chain::*;
use sn_store::store::*;
use sn_block::block::*;
use sn_cryptography::cryptography::*;
use sn_transaction::transaction::*;
use sn_proto::messages::*;
use sn_merkle::merkle::*;
use std::time::{SystemTime, UNIX_EPOCH};
use hex::encode;
use anyhow::Result;
use tokio::runtime::Runtime;

async fn create_test_chain() -> Result<Chain> {
    let block_store = Box::new(MemoryBlockStore::new());
    let tx_store = Box::new(MemoryTXStore::new());
    let chain = Chain::new_chain(block_store, tx_store).await.unwrap();
    Ok(chain)
}

#[tokio::test]
async fn test_create_genesis_block() {
    let genesis_block = create_genesis_block().await.unwrap();
    assert_eq!(genesis_block.msg_header.as_ref().unwrap().msg_height, 0);
    assert_eq!(genesis_block.msg_transactions.len(), 1);
}

#[tokio::test]
async fn test_new_chain() {
    let chain = create_test_chain().await.unwrap();
    assert_eq!(chain.chain_len(), 1);
    assert_eq!(chain.chain_height(), 0);
}

#[tokio::test]
async fn test_add_block() {
    let mut chain = create_test_chain().await.unwrap();
    let genesis_block = chain.get_block_by_height(0).await.unwrap();
    let input_tx = &genesis_block.msg_transactions[0];
    let input_tx_hash = hash_transaction(input_tx).await;
    let input_amount = input_tx.msg_outputs[0].msg_amount;
    let keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&keypair);
    let mut input = TransactionInput {
        msg_previous_tx_hash: input_tx_hash,
        msg_previous_out_index: 0,
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };
    let unsigned_input = TransactionInput {
        msg_previous_tx_hash: input.msg_previous_tx_hash.clone(),
        msg_previous_out_index: input.msg_previous_out_index,
        msg_public_key: input.msg_public_key.clone(),
        msg_signature: vec![],
    };
    let output = TransactionOutput {
        msg_amount: input_amount,
        msg_address: address.to_bytes().to_vec(),
    };
    let mut new_transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![unsigned_input],
        msg_outputs: vec![output],
        msg_relative_timestamp: 123,
    };
    let signature = sign_transaction(&keypair, &new_transaction).await;
    input.msg_signature = signature.to_vec();
    new_transaction.msg_inputs[0] = input;
    let merkle_tree = MerkleTree::new(&vec![new_transaction.clone()]).unwrap();
    let merkle_root = merkle_tree.root.to_vec();
    let prev_header = genesis_block.msg_header.as_ref().unwrap();
    let header = Header {
        msg_version: 1,
        msg_height: prev_header.msg_height + 1,
        msg_previous_hash: hash_header(prev_header).await.unwrap().to_vec(),
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };
    let mut new_block = Block {
        msg_header: Some(header),
        msg_transactions: vec![new_transaction],
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };
    let signature = sign_block(&new_block, &keypair).await.unwrap();
    new_block.msg_signature = signature.to_vec();
    assert!(chain.add_block(new_block).await.is_ok());
}

#[tokio::test]
async fn test_get_block_by_height() {
    let chain = create_test_chain().await.unwrap();
    assert!(chain.get_block_by_height(0).await.is_ok());
    let block = chain.get_block_by_height(0).await.unwrap();
    assert_eq!(block.msg_header.as_ref().unwrap().msg_height, 0);
}

#[tokio::test]
async fn test_get_block_by_hash() {
    let chain = create_test_chain().await.unwrap();
    let block = chain.get_block_by_height(0).await.unwrap();
    let hash = hash_header_by_block(&block).unwrap();
    assert!(chain.get_block_by_hash(&hash).await.is_ok());
    let retrieved_block = chain.get_block_by_hash(&hash).await.unwrap();
    assert_eq!(retrieved_block.msg_header.as_ref().unwrap().msg_height, 0);
}

#[tokio::test]
async fn test_validate_block_another() {
    let block_store = Box::new(MemoryBlockStore::new());
    let tx_store = Box::new(MemoryTXStore::new());
    let chain = Chain::new_chain(block_store, tx_store).await.unwrap();
    let genesis_block = chain.get_block_by_height(0).await.unwrap();
    let genesis_block_hash = hash_header_by_block(&genesis_block).unwrap().to_vec();
    let keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&keypair);
    let output = TransactionOutput {
        msg_amount: 0,
        msg_address: address.to_bytes().to_vec(),
    };
    let transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![],
        msg_outputs: vec![output],
        msg_relative_timestamp: 125,
    };
    let merkle_tree = MerkleTree::new(&vec![transaction.clone()]).unwrap();
    let merkle_root = merkle_tree.root.to_vec();
    let last_block = chain.get_block_by_height(chain.chain_height()).await.unwrap();
    let prev_header = last_block.msg_header.as_ref().unwrap();
    let prev_block_hash = hash_header(prev_header).await.unwrap();
    let prev_block_hash_vec = prev_block_hash.to_vec();
    let header = Header {
        msg_version: 1,
        msg_height: 1,
        msg_previous_hash: prev_block_hash_vec,
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };
    let mut block = Block {
        msg_header: Some(header),
        msg_transactions: vec![transaction],
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };
    let signature = sign_block(&block, &keypair).await.unwrap();
    block.msg_signature = signature.to_vec();
    assert_eq!(genesis_block_hash, genesis_block_hash);
    let added_block_hash = hash_header_by_block(&block).unwrap().to_vec();
    assert_eq!(encode(added_block_hash.clone()), encode(added_block_hash.clone()));
    assert!(chain.validate_block(&block).await.is_ok());
}

#[tokio::test]
async fn test_validate_transaction() {
    let chain = create_test_chain().await.unwrap();
    let genesis_block = chain.get_block_by_height(0).await.unwrap();
    let transaction = &genesis_block.msg_transactions[0];
    let keypair = Keypair::generate_keypair();
    assert!(chain.validate_transaction(transaction, &[keypair]).is_ok());
}

#[test]
fn test_rt_validate_transaction() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let chain = create_test_chain().await.unwrap();
        let genesis_block = chain.get_block_by_height(0).await.unwrap();
        let transaction = &genesis_block.msg_transactions[0];
        let keypair = Keypair::generate_keypair();
        assert!(chain.validate_transaction(transaction, &[keypair]).is_ok());
    });
}

#[tokio::test]
async fn test_add_block_two() {
    let mut chain = create_test_chain().await.unwrap();
    let genesis_block = chain.get_block_by_height(0).await.unwrap();
    let genesis_hash = hash_header_by_block(&genesis_block).unwrap().to_vec();
    let input_tx = &genesis_block.msg_transactions[0];
    let input_tx_hash = hash_transaction(input_tx).await;
    let input_amount = input_tx.msg_outputs[0].msg_amount;
    let keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&keypair);

    let mut input = TransactionInput {
        msg_previous_tx_hash: input_tx_hash,
        msg_previous_out_index: 0,
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };

    let unsigned_input = TransactionInput {
        msg_previous_tx_hash: input.msg_previous_tx_hash.clone(),
        msg_previous_out_index: input.msg_previous_out_index,
        msg_public_key: input.msg_public_key.clone(),
        msg_signature: vec![],
    };

    let output = TransactionOutput {
        msg_amount: input_amount,
        msg_address: address.to_bytes().to_vec(),
    };

    let mut new_transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![unsigned_input],
        msg_outputs: vec![output],
        msg_relative_timestamp: 12,
    };

    let signature = sign_transaction(&keypair, &new_transaction).await;
    input.msg_signature = signature.to_vec();
    new_transaction.msg_inputs[0] = input;
    let merkle_tree = MerkleTree::new(&vec![new_transaction.clone()]).unwrap();
    let merkle_root = merkle_tree.root.to_vec();
    let prev_header = genesis_block.msg_header.as_ref().unwrap();

    let header = Header {
        msg_version: 1,
        msg_height: prev_header.msg_height + 1,
        msg_previous_hash: hash_header(prev_header).await.unwrap().to_vec(),
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };
    
    let mut new_block = Block {
        msg_header: Some(header),
        msg_transactions: vec![new_transaction],
        msg_public_key: keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };

    let signature = sign_block(&new_block, &keypair).await.unwrap();
    new_block.msg_signature = signature.to_vec();

    // Test adding the new block to the chain
    assert!(chain.add_block(new_block).await.is_ok());

    // Test getting the block by height and checking its height
    let retrieved_block = chain.get_block_by_height(1).await.unwrap();
    assert_eq!(retrieved_block.msg_header.as_ref().unwrap().msg_height, 1);

    // Test getting the block by hash and checking its height
    let retrieved_block = chain.get_block_by_hash(&genesis_hash).await.unwrap();
    assert_eq!(retrieved_block.msg_header.as_ref().unwrap().msg_height, 0);

    // Test getting the block by hash and checking its previous hash
    let retrieved_block = chain.get_block_by_height(1).await.unwrap();
    assert_eq!(retrieved_block.msg_header.as_ref().unwrap().msg_previous_hash, genesis_hash);
}