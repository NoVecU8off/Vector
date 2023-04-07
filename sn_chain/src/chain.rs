use sn_store::store::{BlockStorer, TXStorer, UTXOStorer, MemoryUTXOStore, UTXO};
use sn_cryptography::cryptography::{Keypair, Signature};
use sn_transaction::transaction::*;
use sn_proto::messages::{Header, Block, Transaction, TransactionOutput};
use sn_block::block::*;
use sn_merkle::merkle::MerkleTree;
use hex::encode;
use std::time::{SystemTime, UNIX_EPOCH};
use ed25519_dalek::{PublicKey, SecretKey, ExpandedSecretKey};

pub struct HeaderList {
    headers: Vec<Header>,
}

impl HeaderList {
    pub fn new() -> Self {
        HeaderList { headers: Vec::new() }
    }
    pub fn add(&mut self, h: Header) {
        self.headers.push(h);
    }
    pub fn get(&self, index: usize) -> &Header {
        if index > self.height() {
            panic!("index too high!");
        }
        &self.headers[index]
    }
    pub fn height(&self) -> usize {
        self.len() - 1
    }
    pub fn len(&self) -> usize {
        self.headers.len()
    }
}
pub struct Chain {
    pub block_store: Box<dyn BlockStorer>,
    pub tx_store: Box<dyn TXStorer>,
    pub utxo_store: Box<dyn UTXOStorer>,
    pub headers: HeaderList,
}
impl Chain {
    pub fn new(block_store: Box<dyn BlockStorer>, tx_store: Box<dyn TXStorer>) -> Self {
        let mut chain = Chain {
            block_store,
            tx_store,
            utxo_store: Box::new(MemoryUTXOStore::new()),
            headers: HeaderList::new(),
        };
        chain.add_block(create_genesis_block()).unwrap();
        chain
    }
    pub fn height(&self) -> usize {
        self.headers.height()
    }
    pub fn headers_len(&self) -> usize {
        self.headers.len()
    }
    pub fn add_block(&mut self, block: Block) -> Result<(), Box<dyn std::error::Error>> {
        self.validate_block(&block)?;
        let header = block.msg_header.as_ref().ok_or("missing block header")?.clone();
        self.headers.add(header);  
        for tx in &block.msg_transactions {
            let cloned_tx = tx.clone();
            println!("Storing transaction: {:?}", cloned_tx);
            self.tx_store.put(cloned_tx)?;
            let hash = encode(hash_transaction(&tx)); 
            for (i, output) in tx.msg_outputs.iter().enumerate() {
                let utxo = UTXO {
                    hash: hash.clone(),
                    amount: output.msg_amount,
                    out_index: i as u32, // Use the index from the loop
                    spent: false,
                };
    
                self.utxo_store.put(utxo)?;
            }
        }
        self.block_store.put(&block)?;
        Ok(())

    }

    pub fn get_block_by_hash(&self, hash: &[u8]) -> Result<Block, Box<dyn std::error::Error>> {
        let hash_hex = encode(hash);
        match self.block_store.get(&hash_hex) {
            Ok(Some(block)) => Ok(block),
            Ok(None) => Err(format!("block with hash {} not found", hash_hex).into()),
            Err(err) => Err(err.into()),
        }
    }
    
    pub fn get_block_by_height(&self, height: usize) -> Result<Block, Box<dyn std::error::Error>> {
        if self.height() < height {
            return Err(format!(
                "given height ({}) too high - height ({})",
                height,
                self.height()
            )
            .into());
        }
        let header = self.headers.get(height);
        let hash = hash_header(header)?;
        self.get_block_by_hash(&hash)
    }

    pub fn validate_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let signature_vec = block.msg_signature.clone();
        let signature = Signature::signature_from_vec(&signature_vec);   
        let public_key = PublicKey::from_bytes(&block.msg_public_key)
            .map_err(|_| "Invalid public key in block")?;
        let dummy_secret_key = SecretKey::from_bytes(&[0u8; 32]).unwrap();
        let dummy_expanded_secret_key = ExpandedSecretKey::from(&dummy_secret_key);      
        let keypair = Keypair {
            private: dummy_secret_key,
            optional_private: None,
            expanded_private_key: dummy_expanded_secret_key,
            public: public_key,
        }; 
        if !verify_block(block, &signature, &keypair)? {
            return Err("invalid block signature".into());
        } 
        let current_block = self.get_block_by_height(self.height())?;
        let hash = hash_header_by_block(&current_block).unwrap().to_vec();
        if let Some(header) = block.msg_header.as_ref() {
            if hash != header.msg_previous_hash {
                return Err("invalid previous block hash".into());
            }
        } else {
            return Err("Block header is missing".into());
        }
        for tx in &block.msg_transactions {
            self.validate_transaction(tx, &[keypair.clone()])?;
        }
        Ok(())
    }
    
    pub fn validate_transaction(&self, tx: &Transaction, keypair: &[Keypair]) -> Result<(), Box<dyn std::error::Error>> {
        let public_keys: Vec<PublicKey> = keypair.iter().map(|keypair| keypair.public.clone()).collect();    
        if !verify_transaction(tx, &public_keys) {
            return Err("invalid tx signature".into());
        }    
        let n_inputs = tx.msg_inputs.len();
        let hash = hex::encode(hash_transaction(tx));
        let mut sum_inputs = 0;   
        for i in 0..n_inputs {   
            let prev_hash = hex::encode(&tx.msg_inputs[i].msg_previous_tx_hash);
            if let Some(utxo) = self.utxo_store.get(&prev_hash, tx.msg_inputs[i].msg_previous_out_index)? {
                sum_inputs += utxo.amount as i32;   
                if utxo.spent {
                    return Err(format!("input {} of tx {} is already spent", i, hash).into());
                }
            } else {
                return Err(format!("UTXO not found for input {} of tx {}", i, hash).into());
            }   
        }    
        let sum_outputs: i32 = tx.msg_outputs.iter().map(|o| o.msg_amount as i32).sum();   
        if sum_inputs < sum_outputs {
            return Err(format!("insufficient balance got ({}) spending ({})", sum_inputs, sum_outputs).into());
        }   
        Ok(())   
    }   
}

pub fn create_genesis_block() -> Block {
    let genesis_keypair = Keypair::generate_keypair();
    let address = Keypair::derive_address(&genesis_keypair);
    let output = TransactionOutput {
        msg_amount: 1000,
        msg_address: address.to_bytes().to_vec(),
    };
    let transaction = Transaction {
        msg_version: 1,
        msg_inputs: vec![],
        msg_outputs: vec![output],
    };
    let merkle_tree = MerkleTree::new(&[transaction.clone()]);
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
    let signature = sign_block(&block, &genesis_keypair).unwrap();
    block.msg_signature = signature.to_vec();
    block
}

