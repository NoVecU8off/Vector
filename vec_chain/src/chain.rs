use vec_storage::{block_db::*, output_db::*, image_db::*};
use vec_cryptography::cryptography::{Wallet, BLSAGSignature, hash_to_point};
use vec_proto::messages::{Header, Block, Transaction};
use curve25519_dalek_ng::{traits::Identity, constants, scalar::Scalar, ristretto::RistrettoPoint, ristretto::CompressedRistretto};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use vec_block::block::*;
use hex::encode;
use vec_errors::errors::*;
use merlin::Transcript;
use sha3::{Keccak256, Digest};

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
    pub images: Box<dyn ImageStorer>,
    pub outputs: Box<dyn OutputStorer>,
}

impl Chain {
    pub async fn new(blocks: Box<dyn BlockStorer>, images: Box<dyn ImageStorer>, outputs: Box<dyn OutputStorer>) -> Result<Chain, ChainOpsError> {
        let chain = Chain {
            headers: HeaderList::new(),
            blocks,
            images,
            outputs
        };
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
        let hash = hash_header_by_block(&block).unwrap().to_vec();
        self.blocks.put(hash, &block).await?;
        Ok(())
    }

    pub async fn validate_block(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        self.check_previous_block_hash(incoming_block).await?;
        self.check_transactions_in_block(incoming_block).await?;
        Ok(())
    }

    pub async fn add_genesis_block(&mut self, wallet: &Wallet, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.headers.add_header(header.clone());
        for transaction in block.msg_transactions.iter() {
            self.process_transaction(wallet, transaction).await?;
        };
        let hash = hash_header_by_block(&block).unwrap().to_vec();
        self.blocks.put(hash, &block).await?;
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
            self.validate_transaction(tx).await?;
        }
        Ok(())
    }

    pub async fn validate_transaction(&self, transaction: &Transaction) -> Result<bool, ChainOpsError> {
        let inputs_valid = self.validate_inputs(transaction).await?;
        let outputs_valid = self.validate_outputs(transaction)?;
    
        Ok(inputs_valid && outputs_valid)
    }

    pub async fn get_balance(&self) -> u64 {
        let output_set = self.outputs.get().await.unwrap();
        let mut total_balance = 0;
        for owned_output in &output_set {
            let decrypted_amount = owned_output.decrypted_amount as u64;
            total_balance += decrypted_amount;
        }
        total_balance
    }
    
    pub async fn validate_inputs(&self, transaction: &Transaction) -> Result<bool, ChainOpsError> {
        for input in transaction.msg_inputs.iter() {
            let signature = BLSAGSignature::from_vec(&input.msg_blsag).unwrap();
            let vec_of_u8: &Vec<Vec<u8>> = &input.msg_ring;
            let vec_of_compressed: Vec<CompressedRistretto> = vec_of_u8.iter()
                .map(|inner_vec| {
                    CompressedRistretto::from_slice(inner_vec)
                })
                .collect::<Vec<_>>();
            let ring: &[CompressedRistretto] = &vec_of_compressed;
            let message = &input.msg_message;
            let image = input.msg_key_image.clone();
            
            if self.images.contains(image).await? || !self.verify_blsag(&signature, ring, message) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    pub fn validate_outputs(&self, transaction: &Transaction) -> Result<bool, ChainOpsError> {
        for output in transaction.msg_outputs.iter() {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(64, 1);
            let mut verifier_transcript = Transcript::new(b"Transaction");
            let proof = RangeProof::from_bytes(&output.msg_proof).map_err(|_| ChainOpsError::DeserializationError)?;
            let committed_value = CompressedRistretto::from_slice(&output.msg_commitment);
    
            if proof.verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 32).is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn verify_blsag(&self, sig: &BLSAGSignature, p: &[CompressedRistretto], m: &[u8]) -> bool {
        let n = p.len();
        let c1 = sig.c;
        let s = sig.s.clone();
        let image = sig.i;
        let mut l: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
        let mut r: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
        let mut c: Vec<Scalar> = vec![Scalar::zero(); n];
        c[0] = c1;
        for j in 0..n {
            let i = j % n;
            let ip1 = (j + 1) % n;
            l[i] = s[i] * &constants::RISTRETTO_BASEPOINT_POINT + c[i] * p[i].decompress().unwrap();
            r[i] = s[i] * hash_to_point(&p[i]) + c[i] * image.decompress().unwrap();
            let mut hasher = Keccak256::new();
                hasher.update(m);
                hasher.update(l[i].compress().to_bytes());
                hasher.update(r[i].compress().to_bytes());
            let hash = hasher.finalize();
            c[ip1] = Scalar::from_bytes_mod_order(hash.into());
        }
    
        if c1 == c[0] {
            return true;
        }
        false
    }

    pub async fn process_transaction(&self, wallet: &Wallet, transaction: &Transaction) -> Result<(), ChainOpsError> {
        for output in &transaction.msg_outputs {
            let index = output.msg_index;
            let key = CompressedRistretto::from_slice(&output.msg_output_key);
            let stealth = CompressedRistretto::from_slice(&output.msg_stealth_address);

            if wallet.check_property(key, index, stealth) {
                let decrypted_amount = wallet.decrypt_amount(key, index, &output.msg_amount);
                let owned_output = OwnedOutput {
                    output: Output {
                        stealth: output.msg_stealth_address.clone(),
                        output_key: output.msg_output_key.clone(),
                        amount: output.msg_amount.clone(),
                        commitment: output.msg_commitment.clone(),
                        range_proof: output.msg_proof.clone(),
                    },
                    decrypted_amount,
                };
                self.outputs.put(&owned_output).await?;
            }
        }
        Ok(())
    }
}
