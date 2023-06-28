use prost::Message;
use sha3::{Digest, Keccak256};
use vec_errors::errors::*;
use vec_proto::messages::*;
use vec_proto::messages::{Block, Header};

pub fn hash_header_by_block(block: &Block) -> Result<Vec<u8>, BlockOpsError> {
    let mut hasher = Keccak256::new();
    if let Some(header) = block.msg_header.as_ref() {
        hasher.update(header.msg_version.to_be_bytes());
        hasher.update(header.msg_index.to_be_bytes());
        hasher.update(&header.msg_previous_hash);
        hasher.update(&header.msg_root_hash);
        hasher.update(header.msg_timestamp.to_be_bytes());
        hasher.update(header.msg_nonce.to_be_bytes());
    } else {
        return Err(BlockOpsError::MissingHeader);
    }
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub fn hash_header(header: &Header) -> Result<Vec<u8>, BlockOpsError> {
    let mut hasher = Keccak256::new();
    hasher.update(header.msg_version.to_be_bytes());
    hasher.update(header.msg_index.to_be_bytes());
    hasher.update(&header.msg_previous_hash);
    hasher.update(&header.msg_root_hash);
    hasher.update(header.msg_timestamp.to_be_bytes());
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub fn hash_block(block: &Block) -> Result<Vec<u8>, BlockOpsError> {
    let mut bytes = Vec::new();
    block.encode(&mut bytes).unwrap();
    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub fn mine(mut block: Block) -> Result<u32, NodeServiceError> {
    let difficulty = 4;
    for nonce in 0..(u32::max_value()) {
        block.msg_header.as_mut().unwrap().msg_nonce = nonce;
        let hash = hash_block(&block)?;
        if check_difficulty(&hash, difficulty) {
            return Ok(nonce);
        }
    }
    Err(NodeServiceError::MineError)
}

fn check_difficulty(hash: &[u8], difficulty: usize) -> bool {
    let hex_hash = hex::encode(hash);
    let leading_zeros = hex_hash.chars().take_while(|c| *c == 'd').count();

    leading_zeros >= difficulty
}

pub fn hash_transaction(transaction: &Transaction) -> Vec<u8> {
    let mut transaction_bytes = Vec::new();
    transaction.encode(&mut transaction_bytes).unwrap();
    let mut hasher = Keccak256::new();
    hasher.update(&transaction_bytes);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vec_proto::messages::{Transaction, TransactionInput, TransactionOutput};

    #[test]
    fn test_hash_transaction() {
        let transaction1 = create_test_transaction(0);
        let transaction2 = create_test_transaction(1);

        let hash1_async = hash_transaction(&transaction1);
        let hash1_sync = hash_transaction(&transaction1);

        let hash2_async = hash_transaction(&transaction2);
        let hash2_sync = hash_transaction(&transaction2);

        assert_eq!(hash1_async, hash1_sync);
        assert_eq!(hash2_async, hash2_sync);

        assert_ne!(hash1_async, hash2_async);
        assert_ne!(hash1_sync, hash2_sync);
    }

    fn create_test_transaction(msg_index: u32) -> Transaction {
        let contract = Contract::default();
        Transaction {
            msg_inputs: vec![TransactionInput {
                msg_ring: vec![vec![]],
                msg_blsag: vec![],
                msg_message: vec![],
                msg_key_image: vec![],
            }],
            msg_outputs: vec![TransactionOutput {
                msg_stealth_address: vec![],
                msg_output_key: vec![],
                msg_proof: vec![],
                msg_commitment: vec![],
                msg_amount: vec![],
                msg_index,
            }],
            msg_contract: Some(contract),
        }
    }

    fn make_block() -> Block {
        let block = Block::default();

        block
    }

    #[test]
    fn test_mining() {
        let block = make_block();
        let _ = mine(block).expect("Mine function failed");
    }

    #[test]
    fn test_hash_header_by_block() {
        let block = make_block();
        assert!(hash_header_by_block(&block).is_ok());
    }

    #[test]
    fn test_hash_header() {
        let block = make_block();
        if let Some(header) = block.msg_header.as_ref() {
            assert!(hash_header(header).is_ok());
        } else {
            panic!("Block header missing");
        }
    }

    #[test]
    fn test_hash_block() {
        let block = make_block();
        assert!(hash_block(&block).is_ok());
    }
}
