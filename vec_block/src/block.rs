use vec_proto::messages::{Block, Header};
use vec_merkle::merkle::{MerkleTree};
use vec_cryptography::cryptography::{Keypair, Signature};
use sha3::{Digest, Sha3_256};
use vec_errors::errors::*;
use prost::Message;

pub async fn sign_block(block: &Block, keypair: &Keypair) -> Result<Signature, BlockOpsError> {
    let hash = hash_header_by_block(block)?;
    let signature = keypair.sign(&hash);
    Ok(signature)
}

pub async fn verify_block(block: &Block, signature: &Signature, keypair: &Keypair) -> Result<bool, BlockOpsError> {
    let hash = hash_header_by_block(block)?;
    Ok(keypair.verify(&hash, signature))
}

pub fn verify_block_sync(block: &Block, signature: &Signature, keypair: &Keypair) -> Result<bool, BlockOpsError> {
    let hash = hash_header_by_block(block)?;
    Ok(keypair.verify(&hash, signature))
}

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

pub fn hash_header_by_block(block: &Block) -> Result<[u8; 32], BlockOpsError> {
    let mut hasher = Sha3_256::new();
    if let Some(header) = block.msg_header.as_ref() {
        hasher.update(header.msg_version.to_be_bytes());
        hasher.update(header.msg_height.to_be_bytes());
        hasher.update(&header.msg_previous_hash);
        hasher.update(&header.msg_root_hash);
        hasher.update(header.msg_timestamp.to_be_bytes());
    } else {
        return Err(BlockOpsError::MissingHeader);
    }
    let hash = hasher.finalize();
    let hash_bytes: [u8; 32] = hash.into();
    Ok(hash_bytes)
}

pub async fn hash_header(header: &Header) -> Result<[u8; 32], BlockOpsError> {
    let mut hasher = Sha3_256::new();
    hasher.update(header.msg_version.to_be_bytes());
    hasher.update(header.msg_height.to_be_bytes());
    hasher.update(&header.msg_previous_hash);
    hasher.update(&header.msg_root_hash);
    hasher.update(header.msg_timestamp.to_be_bytes());
    let hash = hasher.finalize();
    let hash_bytes: [u8; 32] = hash.into();
    Ok(hash_bytes)
}