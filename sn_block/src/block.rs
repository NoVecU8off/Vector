use sn_proto::messages::{Block, Header};
use sn_merkle::merkle::MerkleTree;
use sn_cryptography::cryptography::{Keypair, Signature};
use std::error::Error;
use sha3::{Digest, Sha3_512};
use prost::Message;

pub fn sign_block(block: &Block, keypair: &Keypair) -> Result<Signature, Box<dyn Error>> {

    let merkle_tree = MerkleTree::new(&block.msg_transactions);
    let merkle_root: Vec<u8> = merkle_tree.root.to_vec();

    let hash = hash_header_by_block(block)?;

    let signature = keypair.sign(&hash);

    println!("Merkle root: {:?}", merkle_root);

    Ok(signature)
}

pub fn verify_block(block: &Block, signature: &Signature, keypair: &Keypair) -> Result<bool, Box<dyn Error>> {

    let mut block_bytes = Vec::new();
    
    block.encode(&mut block_bytes)?;

    let merkle_tree = MerkleTree::new(&block.msg_transactions);
    let merkle_root: Vec<u8> = merkle_tree.root.to_vec();

    let hash = hash_header_by_block(block)?;

    println!("Merkle root: {:?}", merkle_root);

    Ok(keypair.verify(&hash, &signature))

}

pub fn verify_root_hash(block: &Block) -> bool {
    let merkle_tree = MerkleTree::new(&block.msg_transactions);
    let merkle_root: Vec<u8> = merkle_tree.root.to_vec();

    println!("Merkle root: {:?}", merkle_root);

    if let Some(header) = block.msg_header.as_ref() {
        header.msg_root_hash == merkle_root
    } else {
        false
    }
}

pub fn hash_header_by_block(block: &Block) -> Result<[u8; 64], Box<dyn Error>> {

    let mut hasher = Sha3_512::new();

    if let Some(header) = block.msg_header.as_ref() {

        hasher.update(&header.msg_version.to_be_bytes());

        hasher.update(&header.msg_height.to_be_bytes());

        hasher.update(&header.msg_previous_hash);

        hasher.update(&header.msg_root_hash);

        hasher.update(&header.msg_timestamp.to_be_bytes());

    } else {

        return Err("Block header is missing".into());

    }

    let hash = hasher.finalize();
    let hash_bytes: [u8; 64] = hash.into();

    Ok(hash_bytes)

}

pub fn hash_header(header: &Header) -> Result<[u8; 64], Box<dyn Error>> {
    
    let mut hasher = Sha3_512::new();

    hasher.update(&header.msg_version.to_be_bytes());

    hasher.update(&header.msg_height.to_be_bytes());

    hasher.update(&header.msg_previous_hash);

    hasher.update(&header.msg_root_hash);
    
    hasher.update(&header.msg_timestamp.to_be_bytes());

    let hash = hasher.finalize();
    let hash_bytes: [u8; 64] = hash.into();

    Ok(hash_bytes)

}

