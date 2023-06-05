use vec_proto::messages::{Block, Header};
use vec_merkle::merkle::{MerkleTree};
use sha3::{Keccak256, Digest};
use vec_errors::errors::*;
use prost::Message;

pub async fn verify_root_hash(block: &Block) -> Result<bool, BlockOpsError> {
    let transaction_data: Vec<Vec<u8>> = block.msg_transactions
        .iter()
        .map(|transaction| {
            let mut bytes = Vec::new();
            transaction.encode(&mut bytes).unwrap();
            bytes
        })
        .collect();
    let merkle_tree = MerkleTree::from_list(&transaction_data);
    if let Some(header) = block.msg_header.as_ref() {
        let merkle_root = merkle_tree.get_hash();
        Ok(header.msg_root_hash == merkle_root)
    } else {
        Err(BlockOpsError::MissingHeader)
    }
}

pub fn hash_header_by_block(block: &Block) -> Result<Vec<u8>, BlockOpsError> {
    let mut hasher = Keccak256::new();
    if let Some(header) = block.msg_header.as_ref() {
        hasher.update(header.msg_version.to_be_bytes());
        hasher.update(header.msg_height.to_be_bytes());
        hasher.update(&header.msg_previous_hash);
        hasher.update(&header.msg_root_hash);
        hasher.update(header.msg_timestamp.to_be_bytes());
        // hasher.update(&header.msg_nonce.to_be_bytes());
    } else {
        return Err(BlockOpsError::MissingHeader);
    }
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub async fn hash_header(header: &Header) -> Result<Vec<u8>, BlockOpsError> {
    let mut hasher = Keccak256::new();
    hasher.update(header.msg_version.to_be_bytes());
    hasher.update(header.msg_height.to_be_bytes());
    hasher.update(&header.msg_previous_hash);
    hasher.update(&header.msg_root_hash);
    hasher.update(header.msg_timestamp.to_be_bytes());
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub async fn hash_block(block: &Block) -> Result<Vec<u8>, BlockOpsError> {
    let mut hasher = Keccak256::new();
    if let Some(header) = block.msg_header.as_ref() {
        hasher.update(header.msg_version.to_be_bytes());
        hasher.update(header.msg_height.to_be_bytes());
        hasher.update(&header.msg_previous_hash);
        hasher.update(&header.msg_root_hash);
        hasher.update(header.msg_timestamp.to_be_bytes());
        hasher.update(&header.msg_nonce.to_le_bytes());
    }
    for transaction in &block.msg_transactions {
        let mut bytes = Vec::new();
        transaction.encode(&mut bytes).unwrap();
        hasher.update(bytes);
    }
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}