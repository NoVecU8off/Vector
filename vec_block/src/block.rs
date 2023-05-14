use vec_proto::messages::{Block, Header};
use vec_merkle::merkle::MerkleTree;
use vec_cryptography::cryptography::{Keypair, Signature};
use std::error::Error;
use sha3::{Digest, Sha3_256};
use anyhow::Result;

pub async fn sign_block(block: &Block, keypair: &Keypair) -> Result<Signature> {
    let hash = hash_header_by_block(block).unwrap();
    let signature = keypair.sign(&hash);
    Ok(signature)
}

pub async fn verify_block(block: &Block, signature: &Signature, keypair: &Keypair) -> Result<bool> {
    let hash = hash_header_by_block(block).unwrap();
    Ok(keypair.verify(&hash, signature))
}

pub fn verify_block_sync(block: &Block, signature: &Signature, keypair: &Keypair) -> Result<bool> {
    let hash = hash_header_by_block(block).unwrap();
    Ok(keypair.verify(&hash, signature))
}

pub async fn verify_root_hash(block: &Block) -> Result<bool> {
    let merkle_tree = MerkleTree::new(&block.msg_transactions).unwrap();
    let merkle_root = merkle_tree.root.to_vec();
    if let Some(header) = block.msg_header.as_ref() {
        Ok(header.msg_root_hash == merkle_root)
    } else {
        Err(anyhow::anyhow!("Block header is missing"))
    }
}

pub fn hash_header_by_block(block: &Block) -> Result<[u8; 32]> {
    let mut hasher = Sha3_256::new();
    if let Some(header) = block.msg_header.as_ref() {
        hasher.update(header.msg_version.to_be_bytes());
        hasher.update(header.msg_height.to_be_bytes());
        hasher.update(&header.msg_previous_hash);
        hasher.update(&header.msg_root_hash);
        hasher.update(header.msg_timestamp.to_be_bytes());
    } else {
        return Err(anyhow::anyhow!("Block header is missing"));
    }
    let hash = hasher.finalize();
    let hash_bytes: [u8; 32] = hash.into();
    Ok(hash_bytes)
}

pub async fn hash_header(header: &Header) -> Result<[u8; 32], Box<dyn Error>> {
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