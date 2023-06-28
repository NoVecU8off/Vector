use bs58;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use merlin::Transcript;
use prost::Message;
use vec_crypto::crypto::{verify_blsag, BLSAGSignature, Wallet};
use vec_errors::errors::*;
use vec_merkle::merkle::MerkleTree;
use vec_proto::messages::{Block, Transaction};
use vec_storage::lazy_traits::{BLOCK_STORER, IMAGE_STORER, OUTPUT_STORER};
use vec_utils::utils::*;

// Return the "highest" block index in the local chain instance
pub async fn max_index() -> Result<u32, BlockStorageError> {
    match BLOCK_STORER.get_highest_index().await {
        Ok(Some(index)) => Ok(index),
        Ok(None) => Ok(0),
        Err(e) => Err(e),
    }
}

// Add the block to the chain
pub async fn add_block(wallet: &Wallet, block: Block) -> Result<(), ChainOpsError> {
    let header = block
        .msg_header
        .as_ref()
        .ok_or(ChainOpsError::MissingBlockHeader)?;
    validate_block(&block).await?;
    for transaction in block.msg_transactions.iter() {
        wallet.process_transaction(transaction).await?;
    }
    let hash = hash_block(&block)?;
    let index = header.msg_index;
    BLOCK_STORER.put_block(index, hash, &block).await?;
    Ok(())
}

// Validate the candidate block
pub async fn validate_block(incoming_block: &Block) -> Result<(), ChainOpsError> {
    check_previous_block_hash(incoming_block).await?;
    check_transactions_in_block(incoming_block).await?;
    Ok(())
}

// Function used during the genesis to add the block without actual verifying the transactions
pub async fn add_genesis_block(wallet: &Wallet, block: Block) -> Result<(), ChainOpsError> {
    let header = block
        .msg_header
        .as_ref()
        .ok_or(ChainOpsError::MissingBlockHeader)?;
    for transaction in block.msg_transactions.iter() {
        wallet.process_transaction(transaction).await?;
    }
    let hash = hash_block(&block)?.to_vec();
    let index = header.msg_index;
    BLOCK_STORER.put_block(index, hash, &block).await?;
    Ok(())
}

// Returns the block from the BlockDB by its hash
pub async fn get_block_by_hash(hash: Vec<u8>) -> Result<Block, ChainOpsError> {
    match BLOCK_STORER.get(hash.clone()).await {
        Ok(Some(block)) => Ok(block),
        Ok(None) => Err(ChainOpsError::BlockNotFound(
            bs58::encode(hash).into_string(),
        )),
        Err(err) => Err(err.into()),
    }
}

// Check if the hash of the previous block in DB maches the msg_previous_hash of the candidate block
pub async fn check_previous_block_hash(incoming_block: &Block) -> Result<bool, ChainOpsError> {
    let previous_hash = get_previous_hash_in_chain().await?;
    if let Some(header) = incoming_block.msg_header.as_ref() {
        if previous_hash != header.msg_previous_hash {
            return Err(ChainOpsError::InvalidPreviousBlockHash {
                expected: bs58::encode(previous_hash).into_string(),
                got: bs58::encode(header.msg_previous_hash.clone()).into_string(),
            });
        }
    } else {
        return Err(ChainOpsError::MissingBlockHeader);
    }
    Ok(true)
}

pub async fn get_previous_hash_in_chain() -> Result<Vec<u8>, ChainOpsError> {
    let previous_index = max_index().await?;
    let previous_hash = match BLOCK_STORER.get_hash_by_index(previous_index).await? {
        Some(hash) => hash,
        None => return Err(ChainOpsError::MissingBlockHash),
    };
    Ok(previous_hash)
}

pub async fn check_transactions_in_block(incoming_block: &Block) -> Result<(), ChainOpsError> {
    for tx in &incoming_block.msg_transactions {
        validate_transaction(tx).await?;
    }
    Ok(())
}

pub async fn validate_transaction(transaction: &Transaction) -> Result<bool, ChainOpsError> {
    let inputs_valid = validate_inputs(transaction).await?;
    let outputs_valid = validate_outputs(transaction)?;

    Ok(inputs_valid && outputs_valid)
}

// Returns the sum of decrypted outputs stored in the OutputDB
pub async fn get_balance() -> u64 {
    let output_set = OUTPUT_STORER.get().await.unwrap();
    let mut total_balance = 0;
    for owned_output in &output_set {
        let decrypted_amount = owned_output.decrypted_amount;
        total_balance += decrypted_amount;
    }
    total_balance
}

// Deserialize the input and validate bLSAG and image
pub async fn validate_inputs(transaction: &Transaction) -> Result<bool, ChainOpsError> {
    for input in transaction.msg_inputs.iter() {
        let signature = BLSAGSignature::from_vec(&input.msg_blsag).unwrap();
        let vec_ring: &Vec<Vec<u8>> = &input.msg_ring;
        let compressed_ring: Vec<CompressedRistretto> = vec_ring
            .iter()
            .map(|inner_vec| CompressedRistretto::from_slice(inner_vec))
            .collect::<Vec<_>>();
        let ring: &[CompressedRistretto] = &compressed_ring;
        let message = &input.msg_message;
        let image = input.msg_key_image.clone();

        if IMAGE_STORER.contains(image).await? || !verify_blsag(&signature, ring, message) {
            return Ok(false);
        }
    }
    Ok(true)
}

// Verify Pedersen commitment and range proof
pub fn validate_outputs(transaction: &Transaction) -> Result<bool, ChainOpsError> {
    for output in transaction.msg_outputs.iter() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let mut verifier_transcript = Transcript::new(b"Transaction");
        let proof = RangeProof::from_bytes(&output.msg_proof)
            .map_err(|_| ChainOpsError::DeserializationError)?;
        let committed_value = CompressedRistretto::from_slice(&output.msg_commitment);

        if proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut verifier_transcript,
                &committed_value,
                32,
            )
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn verify_root_hash(block: &Block) -> Result<bool, BlockOpsError> {
    let transaction_data: Vec<Vec<u8>> = block
        .msg_transactions
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
