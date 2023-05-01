use sn_store::store::{BlockStorer, TXStorer, UTXOStorer, MemoryUTXOStore, UTXO};
use sn_cryptography::cryptography::{Keypair, Signature};
use sn_transaction::transaction::*;
use sn_proto::messages::{Header, Block, Transaction, TransactionOutput};
use sn_block::block::*;
use sn_merkle::merkle::MerkleTree;
use hex::encode;
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{PublicKey, SecretKey, ExpandedSecretKey};
use anyhow::{Error, Result};
use std::sync::{Arc};
use futures::stream::StreamExt;

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

    pub fn get_header_by_index(&self, index: usize) -> Result<&Header> {
        if index > self.headers_list_height() {
            return Err(anyhow::anyhow!("Index too high!"));
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
    pub tx_store: Box<dyn TXStorer>,
    pub utxo_store: Box<dyn UTXOStorer>,
    pub headers: HeaderList,
}

impl Chain {
    pub async fn new_chain(block_store: Box<dyn BlockStorer>, tx_store: Box<dyn TXStorer>) -> Result<Chain> {
        let mut chain = Chain {
            block_store,
            tx_store,
            utxo_store: Box::new(MemoryUTXOStore::new()),
            headers: HeaderList::new(),
        };
        chain.add_block(create_genesis_block().await.map_err(|e| anyhow::anyhow!("Failed to create genesis block: {}", e))?).await?;
        Ok(chain)
    }

    pub fn chain_height(&self) -> usize {
        self.headers.headers_list_height()
    }

    pub fn chain_len(&self) -> usize {
        self.headers.headers_list_len()
    }

    pub async fn add_block(&mut self, block: Block) -> Result<()> {
        self.validate_block(&block).await.unwrap();
        let header = block
            .msg_header
            .as_ref()
            .ok_or("missing block header")
            .unwrap()
            .clone();
        self.headers.add_header(header);
        self.add_transactions(&block).await?;
        self.block_store.put(&block).await?;
        Ok(())
    }
    
    async fn add_transactions(&mut self, block: &Block) -> Result<()> {
        for tx in &block.msg_transactions {
            let cloned_tx = tx.clone();
            self.tx_store.put(cloned_tx).await?;
            let hash = encode(hash_transaction(tx).await);
            self.add_outputs(tx, &hash).await?;
            self.update_inputs(tx, &hash).await?;
        }
        Ok(())
    }
    
    async fn add_outputs(&mut self, tx: &Transaction, hash: &str) -> Result<()> {
        for (i, output) in tx.msg_outputs.iter().enumerate() {
            let utxo = UTXO {
                hash: hash.clone().to_string(),
                amount: output.msg_amount,
                out_index: i as u32,
                spent: false,
            };
            self.utxo_store.put(utxo).await?;
        }
        Ok(())
    }
    
    async fn update_inputs(&mut self, tx: &Transaction, hash: &str) -> Result<()> {
        for input in &tx.msg_inputs {
            let prev_hash = encode(&input.msg_previous_tx_hash);
            if let Some(mut utxo) = self
                .utxo_store
                .get(&prev_hash, input.msg_previous_out_index)
                .await
                .unwrap()
            {
                utxo.spent = true;
                self.utxo_store.put(utxo).await?;
            } else {
                return Err(Error::msg(format!(
                    "UTXO not found for input {} of tx {}",
                    input.msg_previous_out_index, hash
                )));
            }
        }
        Ok(())
    }
    
    pub async fn get_block_by_hash(&self, hash: &[u8]) -> Result<Block> {
        let hash_hex = encode(hash);
        match self.block_store.get(&hash_hex).await {
            Ok(Some(block)) => Ok(block),
            Ok(None) => Err(anyhow::anyhow!("block with hash {} not found", hash_hex)),
            Err(err) => Err(err.into()),
        }
    }
    
    pub async fn get_block_by_height(&self, height: usize) -> Result<Block> {
        if self.chain_len() == 0 {
            return Err(anyhow::anyhow!("chain is empty"));
        }
        if self.chain_height() < height {
            return Err(anyhow::anyhow!(
                "given height ({}) too high - height ({})",
                height,
                self.chain_height()
            )
            .into());
        }
        let header = self.headers.get_header_by_index(height).unwrap();
        let hash = hash_header(header).await.unwrap();
        let block = self.get_block_by_hash(&hash).await.unwrap();
        Ok(block)
    }

    async fn check_transaction_signature(&self, transaction: &Transaction, keypair: &[Keypair]) -> Result<()> {
        let public_keys: Vec<PublicKey> = keypair.iter().map(|keypair| keypair.public).collect(); 
        if !verify_transaction(transaction, &public_keys).await {
            Err(anyhow::anyhow!("invalid transaction signature"))
        } else {
            Ok(())
        }
    }

    async fn check_transaction_inputs(&self, transaction: &Transaction) -> Result<i32> {
        let mut sum_inputs = 0;
        let hash = hex::encode(hash_transaction(transaction).await);
        for (i, input) in transaction.msg_inputs.iter().enumerate() {
            let prev_hash = hex::encode(&input.msg_previous_tx_hash);
            if let Some(utxo) = self.utxo_store.get(&prev_hash, input.msg_previous_out_index).await.unwrap() {
                sum_inputs += utxo.amount as i32;
                if utxo.spent {
                    return Err(anyhow::anyhow!("input {} of tx {} is already spent", i, hash).into());
                }
            } else {
                return Err(anyhow::anyhow!("UTXO not found for input {} of tx {}", i, hash).into());
            }
        }
        Ok(sum_inputs)
    }

    async fn check_block_signature(&self, incoming_block: &Block) -> Result<()> {
        let signature_vec = incoming_block.msg_signature.clone();
        let signature = Signature::signature_from_vec(&signature_vec);
        let public_key = PublicKey::from_bytes(&incoming_block.msg_public_key)
            .map_err(|_| "Invalid public key in block").unwrap();
        let keypair = Keypair {
            private: SecretKey::from_bytes(&[0u8; 32]).unwrap(),
            optional_private: None,
            expanded_private_key: ExpandedSecretKey::from(&SecretKey::from_bytes(&[0u8; 32]).unwrap()),
            public: public_key,
        };
        if !verify_block(incoming_block, &signature, &keypair).await.unwrap() {
            Err(anyhow::anyhow!("invalid block signature"))
        } else {
            Ok(())
        }
    }

    async fn check_transactions_in_block(&self, incoming_block: &Block, keypair: &[Keypair]) -> Result<()> {
        let keypair_arc = Arc::new(keypair.to_vec());
        let tx_futures = incoming_block
            .msg_transactions
            .iter()
            .map(|tx| {
                let chain = self.clone();
                let keypair = keypair_arc.clone();
                async move { chain.validate_transaction(tx, &keypair).await }
            });
        futures::stream::iter(tx_futures)
            .buffer_unordered(16)
            .for_each_concurrent(None, |result| async move {
                result.unwrap();
            })
            .await;
        Ok(())
    }

    async fn check_previous_block_hash(&self, incoming_block: &Block) -> Result<()> {
        if self.chain_len() > 0 {
            let last_block = self.get_block_by_height(self.chain_height()).await.unwrap();
            let last_block_hash = hash_header_by_block(&last_block).unwrap().to_vec();
            if let Some(header) = incoming_block.msg_header.as_ref() {
                if last_block_hash != header.msg_previous_hash {
                    return Err(anyhow::anyhow!("invalid previous block hash: expected ({}), got ({})", encode(last_block_hash), encode(header.msg_previous_hash.clone())));
                }
            } else {
                return Err(anyhow::anyhow!("Block header is missing"));
            }
        }
        Ok(())
    }
    
    // Add a new function to get the keypair for block validation
    async fn get_keypair_for_block(&self, incoming_block: &Block) -> Result<Vec<Keypair>> {
        // Replace this with the appropriate logic for getting the correct keypair(s) for the block
        let public_key = PublicKey::from_bytes(&incoming_block.msg_public_key)
            .map_err(|_| "Invalid public key in block").unwrap();
        let keypair = Keypair {
            private: SecretKey::from_bytes(&[0u8; 32]).unwrap(),
            optional_private: None,
            expanded_private_key: ExpandedSecretKey::from(&SecretKey::from_bytes(&[0u8; 32]).unwrap()),
            public: public_key,
        };
        Ok(vec![keypair])
    }

    pub async fn validate_block(&self, incoming_block: &Block) -> Result<()> {
        self.check_block_signature(incoming_block).await?;
        self.check_previous_block_hash(incoming_block).await?;
        let keypair = self.get_keypair_for_block(incoming_block).await?;
        self.check_transactions_in_block(incoming_block, &keypair).await?;
        Ok(())
    }

    pub async fn validate_transaction(&self, transaction: &Transaction, keypair: &[Keypair]) -> Result<()> {
        self.check_transaction_signature(transaction, keypair).await?;
        let sum_inputs = self.check_transaction_inputs(transaction).await?;
        let sum_outputs: i32 = transaction.msg_outputs.iter().map(|o| o.msg_amount as i32).sum();
        if sum_inputs < sum_outputs {
            Err(anyhow::anyhow!("insufficient balance got ({}) spending ({})", sum_inputs, sum_outputs).into())
        } else {
            Ok(())
        }
    }
}

pub async fn create_genesis_block() -> Result<Block> {
    let genesis_keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&genesis_keypair);
    let output = TransactionOutput {
        msg_amount: 0,
        msg_address: address.to_bytes().to_vec(),
    };
    let transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![],
        msg_outputs: vec![output],
    };
    let merkle_tree = MerkleTree::new(&[transaction.clone()]).await.unwrap();
    let merkle_root = merkle_tree.root.to_vec();
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
    let signature = sign_block(&block, &genesis_keypair).await.unwrap();
    block.msg_signature = signature.to_vec();
    Ok(block)
}
