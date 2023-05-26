use vec_storage::{block_db::*, utxo_db::*, pool_db::*};
use vec_cryptography::cryptography::{NodeKeypair, Signature};
use vec_proto::messages::{Header, Block, Transaction, TransactionOutput, TransactionInput};
use vec_block::block::*;
use vec_merkle::merkle::MerkleTree;
use vec_transaction::transaction::hash_transaction;
use hex::encode;
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{PublicKey, Verifier, Signature as EdSignature};
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
    pub headers: HeaderList,
    pub blocks: Box<dyn BlockStorer>,
    pub utxos: Box<dyn UTXOStorer>,
    pub stake_pools: Box<dyn StakePoolStorer>,
}

impl Chain {
    pub async fn new(blocks: Box<dyn BlockStorer>, utxos: Box<dyn UTXOStorer>, stake_pools: Box<dyn StakePoolStorer>) -> Result<Chain, ChainOpsError> {
        let chain = Chain {
            headers: HeaderList::new(),
            blocks,
            utxos,
            stake_pools,
        };
        Ok(chain)
    }

    pub async fn genesis(blocks: Box<dyn BlockStorer>, utxos: Box<dyn UTXOStorer>, stake_pools: Box<dyn StakePoolStorer>) -> Result<Chain, ChainOpsError> {
        let mut chain = Chain {
            headers: HeaderList::new(),
            blocks,
            utxos,
            stake_pools,
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

    pub async fn add_block(&mut self, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.validate_block(&block).await?;
        self.headers.add_header(header.clone());
        self.blocks.put(&block).await?;
        Ok(())
    }

    pub async fn validate_block(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        self.check_block_signature(incoming_block).await?;
        self.check_previous_block_hash(incoming_block).await?;
        self.check_transactions_in_block(incoming_block).await?;
        Ok(())
    }

    pub async fn add_leader_block(&mut self, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.headers.add_header(header.clone());
        self.blocks.put(&block).await?;
        Ok(())
    }

    pub async fn get_block_by_hash(&self, hash: &[u8]) -> Result<Block, ChainOpsError> {
        let hash_hex = encode(hash);
        match self.blocks.get(&hash_hex).await {
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
        let signature_vec = incoming_block.msg_sig.clone();
        let signature = Signature::signature_from_vec(&signature_vec);
        let pk = PublicKey::from_bytes(&incoming_block.msg_pk)
            .map_err(|_| ChainOpsError::InvalidPublicKey)?;
        let message = hash_header_by_block(incoming_block)?;
        pk.verify(&message, &signature.signature)?;
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

    pub async fn check_transactions_in_block(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        for tx in &incoming_block.msg_transactions {
            self.process_transaction(tx).await?;
        }
        Ok(())
    }
    
    pub async fn validate_transaction(&self, tx: &Transaction) -> Result<(), ChainOpsError> {
        let mut input_sum: u64 = 0;
        let mut inputs: Vec<UTXO> = Vec::new();
        for input in &tx.msg_inputs {
            let utxo = self.utxos.get(&encode(&input.msg_previous_tx_hash), input.msg_previous_out_index).await?;
            match utxo {
                Some(u) => {
                    input_sum += u.amount;
                    inputs.push(u);
                },
                None => return Err(ValidationError::MissingInput)?,
            };
        }
        for (input, utxo) in tx.msg_inputs.iter().zip(inputs.iter()) {
            if !Chain::verify_signature(&utxo, &input)? {
                return Err(ValidationError::InvalidSignature)?;
            }
        }
        let output_sum: u64 = tx.msg_outputs.iter().map(|o| o.msg_amount).sum();
        if input_sum < output_sum {
            return Err(ValidationError::InsufficientInput)?;
        }
        Ok(())
    }
    
    pub fn verify_signature(utxo: &UTXO, input: &TransactionInput) -> Result<bool, ChainOpsError> {
        let pub_key = PublicKey::from_bytes(&input.msg_pk).map_err(|_| ChainOpsError::InvalidPublicKey)?;
        let signature = EdSignature::from_bytes(&input.msg_sig).map_err(|_| ChainOpsError::InvalidInputSignature)?;
        let message = format!("{}{}", utxo.transaction_hash, utxo.output_index);
        if utxo.pk != input.msg_pk {
            return Err(ValidationError::PublicKeyMismatch)?;
        }
        match pub_key.verify(message.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub async fn process_transaction(&self, transaction: &Transaction) -> Result<(), ChainOpsError> {
        for input in &transaction.msg_inputs {
            let tx_hash = hex::encode(input.msg_previous_tx_hash.clone());
            self.utxos.remove(&(tx_hash, input.msg_previous_out_index)).await?;
        }
        let transaction_hash = hex::encode(hash_transaction(transaction).await);
        for (output_index, output) in transaction.msg_outputs.iter().enumerate() {
            let utxo = UTXO {
                transaction_hash: transaction_hash.clone(),
                output_index: output_index as u32,
                amount: output.msg_amount,
                pk: output.msg_to.clone(),
            };
            self.utxos.put(&utxo).await?;
        }
        Ok(())
    }
    
}

pub async fn create_genesis_block() -> Result<Block, ChainOpsError> {
    let genesis_keypair = NodeKeypair::generate_keypair();
    let address = genesis_keypair.pk;
    let output = TransactionOutput {
        msg_amount: 1000,
        msg_to: address.to_bytes().to_vec(),
    };
    let transaction = Transaction {
        msg_inputs: vec![],
        msg_outputs: vec![output],
        msg_timestamp: 0,
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
        msg_timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    };
    let mut block = Block {
        msg_header: Some(header),
        msg_transactions: vec![transaction],
        msg_pk: genesis_keypair.pk.to_bytes().to_vec(),
        msg_sig: vec![],
    };
    let signature = sign_block(&block, &genesis_keypair).await?;
    block.msg_sig = signature.to_vec();
    Ok(block)
}