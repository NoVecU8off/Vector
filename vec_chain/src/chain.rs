use vec_storage::{block_db::*, output_db::*, image_db::*};
use vec_cryptography::cryptography::{Wallet, BLSAGSignature, hash_to_point};
use vec_proto::messages::{Block, Transaction};
use curve25519_dalek_ng::{traits::Identity, constants, scalar::Scalar, ristretto::RistrettoPoint, ristretto::CompressedRistretto};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use vec_block::block::*;
use hex::encode;
use vec_errors::errors::*;
use merlin::Transcript;
use sha3::{Keccak256, Digest};

pub struct Chain {
    pub blocks: Box<dyn BlockStorer>,
    pub images: Box<dyn ImageStorer>,
    pub outputs: Box<dyn OutputStorer>,
}

impl Chain {
    pub async fn new(blocks: Box<dyn BlockStorer>, images: Box<dyn ImageStorer>, outputs: Box<dyn OutputStorer>) -> Result<Chain, ChainOpsError> {
        let chain = Chain {
            blocks,
            images,
            outputs
        };
        Ok(chain)
    }

    pub async fn max_index(&self) -> Result<u64, BlockStorageError> {
        match self.blocks.get_highest_index().await {
            Ok(Some(index)) => Ok(index),
            Ok(None) => Ok(0), // or return a default value
            Err(e) => Err(e),
        }
    }

    pub async fn add_block(&mut self, wallet: &Wallet, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.validate_block(&block).await?;
        for transaction in block.msg_transactions.iter() {
            self.process_transaction(wallet, transaction).await?;
        };
        let hash = hash_block(&block).await?;
        let index = header.msg_index;
        self.blocks.put_block(index, hash, &block).await?;
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
        for transaction in block.msg_transactions.iter() {
            self.process_transaction(wallet, transaction).await?;
        };
        let hash = hash_block(&block).await?.to_vec();
        let index = header.msg_index;
        self.blocks.put_block(index, hash, &block).await?;
        Ok(())
    }

    pub async fn get_block_by_hash(&self, hash: Vec<u8>) -> Result<Block, ChainOpsError> {
        match self.blocks.get(hash.clone()).await {
            Ok(Some(block)) => Ok(block),
            Ok(None) => Err(ChainOpsError::BlockNotFound(hex::encode(hash))),
            Err(err) => Err(err.into()),
        }
    }
    
    // pub async fn get_block_by_index(&self, index: u64) -> Result<Block, ChainOpsError> {
    //     if self.max_index().await? == 0 {
    //         return Err(ChainOpsError::ChainIsEmpty);
    //     }
    //     let hash = self.blocks.get_hash_by_index(index).await?;
    //     let block = self.get_block_by_hash(hash).await?;
    //     Ok(block)
    // }

    pub async fn check_previous_block_hash(&self, incoming_block: &Block) -> Result<bool, ChainOpsError> {
        let previous_index = self.max_index().await?;
        if previous_index > 0 {
            let previous_hash = match self.blocks.get_hash_by_index(previous_index).await? {
                Some(hash) => hash,
                None => return Err(ChainOpsError::MissingBlockHash),
            };
            if let Some(header) = incoming_block.msg_header.as_ref() {
                if previous_hash != header.msg_previous_hash {
                    return Err(ChainOpsError::InvalidPreviousBlockHash {
                        expected: encode(previous_hash),
                        got: encode(header.msg_previous_hash.clone()),
                    });
                }
            } else {
                return Err(ChainOpsError::MissingBlockHeader);
            }
        }
        Ok(true)
    }

    pub async fn get_previous_hash_in_chain(&self) -> Result<Vec<u8>, ChainOpsError> {
        let previous_index = self.max_index().await?;
        let previous_hash = match self.blocks.get_hash_by_index(previous_index).await? {
            Some(hash) => hash,
            None => return Err(ChainOpsError::MissingBlockHash),
        };
        Ok(previous_hash)
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_chain() -> Result<Chain, ChainOpsError> {
        let block_db = sled::open("C:/Vector/blocks").unwrap();
        let index_db = sled::open("C:/Vector/indexes").unwrap();
        let output_db = sled::open("C:/Vector/outputs").unwrap();
        let image_db = sled::open("C:/Vector/images").unwrap();
        let blocks: Box<dyn BlockStorer> = Box::new(BlockDB::new(block_db, index_db));
        let outputs: Box<dyn OutputStorer> = Box::new(OutputDB::new(output_db));
        let images: Box<dyn ImageStorer> = Box::new(ImageDB::new(image_db));
        let chain = Chain::new(blocks, images, outputs).await.unwrap();
        Ok(chain)
    }

    #[tokio::test]
    async fn test_chain_new() {
        let result = create_test_chain().await;
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.max_index().await.unwrap(), 0);
    }
}