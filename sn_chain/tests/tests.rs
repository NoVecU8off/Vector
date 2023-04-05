use sn_block::block::*;
use sn_chain::chain::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Block, Transaction, Header};
use sn_store::store::{MemoryBlockStore, MemoryTXStore, MemoryUTXOStore, BlockStorer, TXStorer};
// use sn_merkle::merkle::*;
// use std::error::Error;
// use std::time::SystemTime;
// use std::time::UNIX_EPOCH;

fn setup_chain() -> Chain {
    let block_storer: Box<dyn BlockStorer> = Box::new(MemoryBlockStore::new());
    let tx_storer: Box<dyn TXStorer> = Box::new(MemoryTXStore::new());
    Chain::new(block_storer, tx_storer)
}

#[test]
fn test_create_genesis_block() {
    let genesis_block = create_genesis_block();
    assert_eq!(genesis_block.msg_header.as_ref().unwrap().msg_height, 0);
    assert_eq!(genesis_block.msg_transactions.len(), 1);
}

#[test]
fn test_add_block() {
    let mut chain = setup_chain();
    let genesis_block = create_genesis_block();

    assert_eq!(chain.height(), 0);
    assert_eq!(chain.headers_len(), 1);

    let block_result = chain.add_block(genesis_block.clone());
    assert!(block_result.is_err(), "Adding a duplicate genesis block should fail");
}

#[test]
fn test_get_block_by_hash_and_height() {
    let chain = setup_chain();
    let genesis_block = create_genesis_block();
    let genesis_block_hash = hash_block(&genesis_block).unwrap();

    let retrieved_block_by_hash = chain.get_block_by_hash(&genesis_block_hash).unwrap();
    let retrieved_block_by_height = chain.get_block_by_height(0).unwrap();

    assert_eq!(genesis_block, retrieved_block_by_hash);
    assert_eq!(genesis_block, retrieved_block_by_height);
}

#[test]
fn test_validate_block() {
    let chain = setup_chain();
    let genesis_block = create_genesis_block();

    let block_result = chain.validate_block(&genesis_block);
    assert!(block_result.is_err(), "Genesis block should not be valid in the current chain");
}