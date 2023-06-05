use vec_proto::messages::{Block, Header, Transaction, TransactionInput, TransactionOutput};
use vec_merkle::merkle::{MerkleTree};
use sha3::{Keccak256, Digest};
use vec_errors::errors::*;
use prost::Message;
use rand::Rng;

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
        hasher.update(header.msg_index.to_be_bytes());
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
    hasher.update(header.msg_index.to_be_bytes());
    hasher.update(&header.msg_previous_hash);
    hasher.update(&header.msg_root_hash);
    hasher.update(header.msg_timestamp.to_be_bytes());
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub async fn hash_block(block: &Block) -> Result<Vec<u8>, BlockOpsError> {
    let mut bytes = Vec::new();
    block.encode(&mut bytes).unwrap();
    let mut hasher = Keccak256::new();
        hasher.update(&bytes);
    let hash = hasher.finalize().to_vec();
    Ok(hash)
}

pub async fn mine(mut block: Block) -> Result<u64, NodeServiceError> {
    let difficulty = 4;
    for nonce in 0..(u64::max_value()) {
        block.msg_header.as_mut().unwrap().msg_nonce = nonce;
        let hash = hash_block(&block).await?;
        println!("nonce: {}, hash: {}", nonce, hex::encode(hash.clone()));
        if check_difficulty(&hash, difficulty) {
            return Ok(nonce);
        }
    }
    Err(NodeServiceError::MineError)
}

fn check_difficulty(hash: &[u8], difficulty: usize) -> bool {
    let hex_representation = hex::encode(hash);
    let leading_zeros = hex_representation.chars().take_while(|c| *c == '0').count();

    leading_zeros >= difficulty
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn make_block() -> Block {
        let data = b"fkjbao;ufv;skodnvvfkmvnbkfnuvdfj";
        let mut hasher = Keccak256::new();
            hasher.update(data);
        let hash = hasher.finalize().to_vec();
        let mut hasher = Keccak256::new();
            hasher.update(hash.clone());
        let hash2 = hasher.finalize().to_vec();
        let header = Header {
            msg_version: 1,
            msg_index: 17382,
            msg_previous_hash: hash,
            msg_root_hash: hash2,
            msg_timestamp: 7456046298,
            msg_nonce: 0,
        };
        let block = Block {
            msg_header: Some(header),
            msg_transactions: vec![]
        };
        block
    }

    fn make_transaction() -> Transaction {
        let transaction = Transaction {
            msg_inputs: vec![],
            msg_outputs: vec![],
        };
        transaction
    }

    #[tokio::test]
    async fn test_mining() {
        let block = make_block();
        let _ = mine(block).await.expect("Mine function failed");
    }

    #[tokio::test]
    async fn test_verify_root_hash() {
        let mut block = make_block();
        let transaction = make_transaction();
        block.msg_transactions.push(transaction);
        assert!(verify_root_hash(&block).await.is_ok());
    }

    #[tokio::test]
    async fn test_hash_header_by_block() {
        let block = make_block();
        assert!(hash_header_by_block(&block).is_ok());
    }

    #[tokio::test]
    async fn test_hash_header() {
        let block = make_block();
        if let Some(header) = block.msg_header.as_ref() {
            assert!(hash_header(header).await.is_ok());
        } else {
            panic!("Block header missing");
        }
    }

    #[tokio::test]
    async fn test_hash_block() {
        let block = make_block();
        assert!(hash_block(&block).await.is_ok());
    }

    #[tokio::test]
    async fn test_check_difficulty() {
        let difficulty = 4;
        let mut rng = rand::thread_rng();
        let random_data: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
        let mut hasher = Keccak256::new();
        hasher.update(&random_data);
        let hash = hasher.finalize();
        assert!(check_difficulty(&hash, difficulty));
    }

}