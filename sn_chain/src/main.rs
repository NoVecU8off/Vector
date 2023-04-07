use std::error::Error;
use sn_chain::chain::*;
use sn_cryptography::cryptography::{Keypair};
use sn_block::block::*;

fn main() -> Result<(), Box<dyn Error>> {
    // 1. Create a block and a keypair.
    let block = create_genesis_block();
    let keypair = Keypair::generate_keypair();

    // 2. Sign the block.
    let signature = sign_block(&block, &keypair)?;

    // 3. Verify the block's signature.
    let is_signature_valid = verify_block(&block, &signature, &keypair)?;

    // 4. Verify the block's Merkle root hash.
    let is_root_hash_valid = verify_root_hash(&block);

    // 5. Hash the block and its header.
    let block_hash = hash_header_by_block(&block)?;
    let header_hash = hash_header_by_block(&block)?;

    // 6. Compare the hashes.
    let are_hashes_equal = block_hash == header_hash;

    // 7. Print the results.
    println!("Is signature valid: {}, Signature: {}", is_signature_valid, signature);
    println!("Is root hash valid: {}", is_root_hash_valid);
    println!("Are block and header hashes equal: {}", are_hashes_equal);

    Ok(())
}
