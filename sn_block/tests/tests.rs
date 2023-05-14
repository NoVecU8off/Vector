#[cfg(test)]
mod tests {
    use sn_block::block::*;
    use sn_proto::messages::{Block, Header, Transaction};
    use sn_cryptography::cryptography::{Keypair};
    use std::time::{SystemTime, UNIX_EPOCH};
    use sn_merkle::merkle::*;

    async fn create_sample_block() -> Block {
        let transactions = vec![
            Transaction {
                msg_inputs: vec![],
                msg_outputs: vec![],
                msg_version: 1,
                msg_relative_timestamp: 1,
            },
            Transaction {
                msg_inputs: vec![],
                msg_outputs: vec![],
                msg_version: 1,
                msg_relative_timestamp: 2,
            },
        ];
    
        let merkle_tree = MerkleTree::new(&transactions).unwrap();
        let merkle_root = merkle_tree.root.to_vec();
    
        let header = Header {
            msg_version: 1,
            msg_height: 0,
            msg_previous_hash: vec![0; 32],
            msg_root_hash: merkle_root,
            msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
        };
    
        let public_key = vec![0; 32];
        let signature = vec![0; 32];
    
        Block {
            msg_header: Some(header),
            msg_transactions: transactions,
            msg_public_key: public_key,
            msg_signature: signature,
        }
    }

    #[tokio::test]
    async fn test_sign_and_verify_block() {
        let block = create_sample_block().await;
        let keypair = Keypair::generate_keypair();
        let signature = sign_block(&block, &keypair).await.unwrap();

        let result = verify_block(&block, &signature, &keypair).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_verify_root_hash() {
        let block = create_sample_block().await;
        assert!(verify_root_hash(&block).await.unwrap());
    }

    #[tokio::test]
    async fn test_hash_block() {
        let block = create_sample_block().await;
        let hash = hash_header_by_block(&block).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[tokio::test]
    async fn test_hash_header_by_block() {
        let block = create_sample_block().await;
        let hash = hash_header_by_block(&block).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[tokio::test]
    async fn test_hash_header() {
        let block = create_sample_block().await;
        let header = block.msg_header.unwrap();
        let hash = hash_header(&header).await.unwrap();
        assert_eq!(hash.len(), 32);
    }
}