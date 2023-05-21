use vec_store::block_store::{BlockStorer};
use vec_cryptography::cryptography::{Keypair, Signature};
use vec_transaction::transaction::*;
use vec_proto::messages::{Header, Block, Transaction, TransactionOutput};
use vec_block::block::*;
use vec_merkle::merkle::MerkleTree;
use hex::encode;
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{PublicKey, Verifier};
use rayon::prelude::*;
use vec_errors::errors::*;
use prost::Message;

#[derive(Clone)]
pub struct HeaderList {
    headers: Vec<Header>,
}

impl HeaderList {
    pub fn new() -> Self {
        HeaderList { headers: Vec::new() }
    }

    pub fn add_header(&mut self, h: Header) {
        self.headers.push(h);
    }

    pub fn get_header_by_index(&self, index: usize) -> Result<&Header, ChainOpsError> {
        if index >= self.headers_list_height() {
            return Err(ChainOpsError::IndexTooHigh);
        }
        Ok(&self.headers[index])
    }

    pub fn headers_list_height(&self) -> usize {
        if self.headers_list_len() == 0 {
            0
        } else {
            self.headers_list_len() - 1
        }
    }

    pub fn headers_list_len(&self) -> usize {
        self.headers.len()
    }
}

impl Default for HeaderList {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Chain {
    pub block_store: Box<dyn BlockStorer>,
    pub headers: HeaderList,
}

impl Chain {
    pub async fn new_chain(block_store: Box<dyn BlockStorer>) -> Result<Chain, ChainOpsError> {
        let mut chain = Chain {
            block_store,
            headers: HeaderList::new(),
        };
        chain.add_leader_block(create_genesis_block().await?).await?;
        Ok(chain)
    }

    pub fn chain_height(&self) -> usize {
        self.headers.headers_list_height()
    }

    pub fn chain_len(&self) -> usize {
        self.headers.headers_list_len()
    }

    pub async fn validate_block(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        self.check_block_signature(incoming_block).await?;
        self.check_previous_block_hash(incoming_block).await?;
        self.check_transactions_in_block(incoming_block)?;
        Ok(())
    }

    pub async fn add_block(&mut self, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.validate_block(&block).await?;
        self.headers.add_header(header.clone());
        self.block_store.put(&block).await?;
        Ok(())
    }

    pub async fn add_leader_block(&mut self, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.headers.add_header(header.clone());
        self.block_store.put(&block).await?;
        Ok(())
    }
    
    pub async fn get_block_by_hash(&self, hash: &[u8]) -> Result<Block, ChainOpsError> {
        let hash_hex = encode(hash);
        match self.block_store.get(&hash_hex).await {
            Ok(Some(block)) => Ok(block),
            Ok(None) => Err(ChainOpsError::BlockNotFound(hash_hex)),
            Err(err) => Err(err.into()),
        }
    }
    
    pub async fn get_block_by_height(&self, height: usize) -> Result<Block, ChainOpsError> {
        if self.chain_len() == 0 {
            return Err(ChainOpsError::ChainIsEmpty);
        }
        if self.chain_height() < height {
            return Err(ChainOpsError::HeightTooHigh { height, max_height: self.chain_height() });
        }
        let header = self.headers.get_header_by_index(height)?;
        let hash = hash_header(header).await?;
        let block = self.get_block_by_hash(&hash).await?;
        Ok(block)
    }

    async fn check_block_signature(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        let signature_vec = incoming_block.msg_signature.clone();
        let signature = Signature::signature_from_vec(&signature_vec);
        let public_key = PublicKey::from_bytes(&incoming_block.msg_public_key)
            .map_err(|_| ChainOpsError::InvalidPublicKey)?;
    
        let message = hash_header_by_block(incoming_block)?;
        public_key.verify(&message, &signature.signature)?;
        Ok(())
    }    

    async fn check_previous_block_hash(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        if self.chain_len() > 0 {
            let last_block = self.get_block_by_height(self.chain_height()).await?;
            let last_block_hash = hash_header_by_block(&last_block)?.to_vec();
            if let Some(header) = incoming_block.msg_header.as_ref() {
                if last_block_hash != header.msg_previous_hash {
                    return Err(ChainOpsError::InvalidPreviousBlockHash {
                        expected: encode(last_block_hash),
                        got: encode(header.msg_previous_hash.clone()),
                    });
                }
            } else {
                return Err(ChainOpsError::MissingBlockHeader);
            }
        }
        Ok(())
    }

    pub async fn get_previous_hash_in_chain(&self) -> Result<Vec<u8>, ChainOpsError> {
        let last_block = self.get_block_by_height(self.chain_height()).await?;
        let last_block_hash = hash_header_by_block(&last_block)?.to_vec();
        Ok(last_block_hash)
    }

    fn check_transactions_in_block(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        incoming_block
            .msg_transactions
            .par_iter()
            .try_for_each(|tx| {
                self.validate_transaction(tx)
            })
    }
    
    fn validate_transaction(&self, transaction: &Transaction) -> Result<(), ChainOpsError> {
        let public_keys = self.extract_public_keys_from_transaction(transaction)?;
        self.check_transaction_signature(transaction, &public_keys)?;
        Ok(())
    }
    
    fn extract_public_keys_from_transaction(&self, transaction: &Transaction) -> Result<Vec<PublicKey>, ChainOpsError> {
        let mut public_keys = Vec::new();
        for input in &transaction.msg_inputs {
            let public_key = PublicKey::from_bytes(&input.msg_public_key)
                .map_err(|_| ChainOpsError::InvalidPublicKeyInTransactionInput)?;
            public_keys.push(public_key);
        }
        Ok(public_keys)
    }

    fn check_transaction_signature(&self, transaction: &Transaction, public_keys: &[PublicKey]) -> Result<(), ChainOpsError> {
        if !verify_transaction(transaction, public_keys) {
            Err(ChainOpsError::InvalidTransactionSignature)
        } else {
            Ok(())
        }
    }
}

pub async fn create_genesis_block() -> Result<Block, ChainOpsError> {
    let genesis_keypair = Keypair::generate_keypair();
    let address = genesis_keypair.public;
    let output = TransactionOutput {
        msg_amount: 1000,
        msg_to: address.to_bytes().to_vec(),
    };
    let transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![],
        msg_outputs: vec![output],
        msg_relative_timestamp: 0,
    };
    let mut bytes = Vec::new();
    transaction.encode(&mut bytes).unwrap();
    let merkle_tree = MerkleTree::from_list(&vec![bytes]);
    let merkle_root = merkle_tree.get_hash();
    let header = Header {
        msg_version: 1,
        msg_height: 0,
        msg_previous_hash: vec![],
        msg_root_hash: merkle_root,
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
    };
    let mut block = Block {
        msg_header: Some(header),
        msg_transactions: vec![transaction],
        msg_public_key: genesis_keypair.public.to_bytes().to_vec(),
        msg_signature: vec![],
    };
    let signature = sign_block(&block, &genesis_keypair).await?;
    block.msg_signature = signature.to_vec();
    Ok(block)
}