use vec_storage::{block_db::*, utxo_db::*, pool_db::*};
use vec_cryptography::cryptography::{Wallet, Signature, verify};
use vec_proto::messages::{Header, Block, Transaction, TransactionOutput};
use vec_block::block::*;
use vec_merkle::merkle::MerkleTree;
use vec_transaction::transaction::hash_transaction;
use curve25519_dalek_ng::{traits::Identity, constants, scalar::Scalar, ristretto::RistrettoPoint, ristretto::CompressedRistretto};
use hex::encode;
use std::time::{SystemTime, UNIX_EPOCH};
use vec_errors::errors::*;
use prost::Message;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use merlin::Transcript;
use rand::thread_rng;

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
        let signature = Signature::from_vec(&signature_vec).unwrap();
        let pub_sp_key = Wallet::public_spend_key_from_vec(&incoming_block.msg_public).unwrap();
        let message = hash_header_by_block(incoming_block)?;
        verify(&pub_sp_key, &message, &signature);
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
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        for input in &tx.msg_inputs {
            // Verify existence of the referenced UTXO and the provided signature
            let utxo = self.utxos.get(&input.msg_previous_tx_hash, input.msg_previous_out_index).await?;
            match utxo {
                Some(u) => {
                    let msg_to_verify = format!("{}{}", u.utxo_transaction_hash, u.utxo_output_index);
                    let pub_sp_key = Wallet::public_spend_key_from_vec(&u.utxo_public_key).unwrap();
                    let signature = Signature::from_vec(&input.msg_sig).unwrap();
                    if !verify(&pub_sp_key, &msg_to_verify.as_bytes(), &signature) {
                        return Err(ValidationError::InvalidSignature)?;
                    }
                    let mut verifier_transcript = Transcript::new(b"TransactionProof");
                    let proof = RangeProof::from_bytes(&input.msg_proof).unwrap();
                    let compressed_ristretto = CompressedRistretto::from_slice(&input.msg_commited_value);
                    if proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &compressed_ristretto, 64).is_err() {
                        return Err(ValidationError::IncorrectRangeProofs)?;
                    }
                },
                None => return Err(ValidationError::MissingInput)?,
            }
        }
        Ok(())
    }

    pub async fn process_transaction(&self, transaction: &Transaction) -> Result<(), ChainOpsError> {
        // Remove spent UTXOs
        for input in &transaction.msg_inputs {
            let tx_hash = input.msg_previous_tx_hash.clone();
            self.utxos.remove(&(tx_hash, input.msg_previous_out_index)).await?;
        }
        // Create new UTXOs for the transaction outputs
        let transaction_hash = hex::encode(hash_transaction(transaction).await);
        for (output_index, output) in transaction.msg_outputs.iter().enumerate() {
            let utxo = UTXO {
                utxo_transaction_hash: transaction_hash.clone(),
                utxo_output_index: output_index as u32,
                utxo_public_key: output.msg_public.clone(),
                utxo_commited_value: output.msg_commited_value.clone(),
                utxo_proof: output.msg_proof.clone(),
            };
            self.utxos.put(&utxo).await?;
        }
        Ok(())
    }
}

pub async fn create_genesis_block() -> Result<Block, ChainOpsError> {
    let genesis_wallet = Wallet::generate();
    let address = genesis_wallet.public_spend_key;
    let genesis_amount: u64 = 50; 
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let blinding = Scalar::random(&mut thread_rng());
    let mut transcript = Transcript::new(b"TransactionRangeProof");
    let (proof, commited_value) = RangeProof::prove_single(
        &bp_gens, 
        &pc_gens, 
        &mut transcript, 
        genesis_amount, 
        &blinding, 
        64
    )
    .unwrap();
    let output = TransactionOutput {
        msg_commited_value: commited_value.as_bytes().to_vec(),
        msg_proof: proof.to_bytes().to_vec(),
        msg_to: address.to_bytes().to_vec(),
        msg_public: genesis_wallet.public_spend_key_to_vec(),
    };
    let transaction = Transaction {
        msg_inputs: vec![],
        msg_outputs: vec![output],
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
        msg_public: genesis_wallet.public_spend_key_to_vec(),
        msg_sig: vec![],
    };
    let signature = sign_block(&block, &genesis_wallet).await?;
    block.msg_sig = signature.to_vec();
    Ok(block)
}
