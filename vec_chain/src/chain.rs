use bs58;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    constants, ristretto::CompressedRistretto, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use prost::Message;
use rand::seq::SliceRandom;
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tokio::sync::RwLock;
use vec_crypto::cryptography::{derive_keys_from_address, hash_to_point, BLSAGSignature, Wallet};
use vec_errors::errors::*;
use vec_merkle::merkle::MerkleTree;
use vec_proto::messages::{Block, Transaction, TransactionInput, TransactionOutput};
use vec_storage::{block_db::*, image_db::*, output_db::*};
use vec_utils::utils::*;

pub struct Chain {
    pub blocks: Arc<RwLock<dyn BlockStorer>>,
    pub images: Arc<RwLock<dyn ImageStorer>>,
    pub outputs: Arc<RwLock<dyn OutputStorer>>,
}

impl Chain {
    pub async fn new(
        blocks: Arc<RwLock<dyn BlockStorer>>,
        images: Arc<RwLock<dyn ImageStorer>>,
        outputs: Arc<RwLock<dyn OutputStorer>>,
    ) -> Result<Chain, ChainOpsError> {
        let chain = Chain {
            blocks,
            images,
            outputs,
        };
        Ok(chain)
    }

    // Return the "highest" block index in the local chain instance
    pub async fn max_index(&self) -> Result<u64, BlockStorageError> {
        // let blocks: Box<dyn BlockStorer>;
        let rlock = self.blocks.read().await;
        match rlock.get_highest_index().await {
            Ok(Some(index)) => Ok(index),
            Ok(None) => Ok(0),
            Err(e) => Err(e),
        }
    }

    // Add the block to the chain
    pub async fn add_block(&self, wallet: &Wallet, block: Block) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        self.validate_block(&block).await?;
        for transaction in block.msg_transactions.iter() {
            self.process_transaction(wallet, transaction).await?;
        }
        let hash = hash_block(&block)?;
        let index = header.msg_index;
        let wlock = self.blocks.write().await;
        wlock.put_block(index, hash, &block).await?;
        drop(wlock);
        Ok(())
    }

    // Validate the candidate block
    pub async fn validate_block(&self, incoming_block: &Block) -> Result<(), ChainOpsError> {
        self.check_previous_block_hash(incoming_block).await?;
        self.check_transactions_in_block(incoming_block).await?;
        Ok(())
    }

    // Function used during the genesis to add the block without actual verifying the transactions
    pub async fn add_genesis_block(
        &self,
        wallet: &Wallet,
        block: Block,
    ) -> Result<(), ChainOpsError> {
        let header = block
            .msg_header
            .as_ref()
            .ok_or(ChainOpsError::MissingBlockHeader)?;
        for transaction in block.msg_transactions.iter() {
            self.process_transaction(wallet, transaction).await?;
        }
        let hash = hash_block(&block)?.to_vec();
        let index = header.msg_index;
        let wlock = self.blocks.write().await;
        wlock.put_block(index, hash, &block).await?;
        drop(wlock);
        Ok(())
    }

    // Returns the block from the BlockDB by its hash
    pub async fn get_block_by_hash(&self, hash: Vec<u8>) -> Result<Block, ChainOpsError> {
        match self.blocks.read().await.get(hash.clone()).await {
            Ok(Some(block)) => Ok(block),
            Ok(None) => Err(ChainOpsError::BlockNotFound(
                bs58::encode(hash).into_string(),
            )),
            Err(err) => Err(err.into()),
        }
    }

    // Check if the hash of the previous block in DB maches the msg_previous_hash of the candidate block
    pub async fn check_previous_block_hash(
        &self,
        incoming_block: &Block,
    ) -> Result<bool, ChainOpsError> {
        let previous_hash = self.get_previous_hash_in_chain().await?;
        if let Some(header) = incoming_block.msg_header.as_ref() {
            if previous_hash != header.msg_previous_hash {
                return Err(ChainOpsError::InvalidPreviousBlockHash {
                    expected: bs58::encode(previous_hash).into_string(),
                    got: bs58::encode(header.msg_previous_hash.clone()).into_string(),
                });
            }
        } else {
            return Err(ChainOpsError::MissingBlockHeader);
        }
        Ok(true)
    }

    pub async fn get_previous_hash_in_chain(&self) -> Result<Vec<u8>, ChainOpsError> {
        let previous_index = self.max_index().await?;
        let previous_hash = match self
            .blocks
            .read()
            .await
            .get_hash_by_index(previous_index)
            .await?
        {
            Some(hash) => hash,
            None => return Err(ChainOpsError::MissingBlockHash),
        };
        Ok(previous_hash)
    }

    pub async fn check_transactions_in_block(
        &self,
        incoming_block: &Block,
    ) -> Result<(), ChainOpsError> {
        for tx in &incoming_block.msg_transactions {
            self.validate_transaction(tx).await?;
        }
        Ok(())
    }

    pub async fn validate_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<bool, ChainOpsError> {
        let inputs_valid = self.validate_inputs(transaction).await?;
        let outputs_valid = self.validate_outputs(transaction)?;

        Ok(inputs_valid && outputs_valid)
    }

    // Returns the sum of decrypted outputs stored in the OutputDB
    pub async fn get_balance(&self) -> u64 {
        let output_set = self.outputs.read().await.get().await.unwrap();
        let mut total_balance = 0;
        for owned_output in &output_set {
            let decrypted_amount = owned_output.decrypted_amount;
            total_balance += decrypted_amount;
        }
        total_balance
    }

    // Deserialize the input and validate bLSAG and image
    pub async fn validate_inputs(&self, transaction: &Transaction) -> Result<bool, ChainOpsError> {
        for input in transaction.msg_inputs.iter() {
            let signature = BLSAGSignature::from_vec(&input.msg_blsag).unwrap();
            let vec_ring: &Vec<Vec<u8>> = &input.msg_ring;
            let compressed_ring: Vec<CompressedRistretto> = vec_ring
                .iter()
                .map(|inner_vec| CompressedRistretto::from_slice(inner_vec))
                .collect::<Vec<_>>();
            let ring: &[CompressedRistretto] = &compressed_ring;
            let message = &input.msg_message;
            let image = input.msg_key_image.clone();

            if self.images.read().await.contains(image).await?
                || !self.verify_blsag(&signature, ring, message)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // Verify Pedersen commitment and range proof
    pub fn validate_outputs(&self, transaction: &Transaction) -> Result<bool, ChainOpsError> {
        for output in transaction.msg_outputs.iter() {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(64, 1);
            let mut verifier_transcript = Transcript::new(b"Transaction");
            let proof = RangeProof::from_bytes(&output.msg_proof)
                .map_err(|_| ChainOpsError::DeserializationError)?;
            let committed_value = CompressedRistretto::from_slice(&output.msg_commitment);

            if proof
                .verify_single(
                    &bp_gens,
                    &pc_gens,
                    &mut verifier_transcript,
                    &committed_value,
                    32,
                )
                .is_err()
            {
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
            l[i] = s[i] * constants::RISTRETTO_BASEPOINT_POINT + c[i] * p[i].decompress().unwrap();
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

    // Check if the output belongs to us, if so - store it in OutputDB
    pub async fn process_transaction(
        &self,
        wallet: &Wallet,
        transaction: &Transaction,
    ) -> Result<(), ChainOpsError> {
        for output in &transaction.msg_outputs {
            let index = output.msg_index;
            let key = CompressedRistretto::from_slice(&output.msg_output_key);
            let stealth = CompressedRistretto::from_slice(&output.msg_stealth_address);

            if wallet.check_property(key, index, stealth)? {
                let decrypted_amount = wallet.decrypt_amount(key, index, &output.msg_amount)?;
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
                {
                    self.outputs.write().await.put(&owned_output).await?;
                }
            }
        }
        Ok(())
    }

    // Collects outputs from OutputDB and constructs Inputs for transaction
    pub async fn prepare_inputs(
        &self,
        wallet: &Wallet,
    ) -> Result<(Vec<TransactionInput>, u64), ChainOpsError> {
        let output_set = self.outputs.read().await.get().await.unwrap();
        let mut total_input_amount = 0;
        let mut inputs = Vec::new();
        for owned_output in &output_set {
            let decrypted_amount = owned_output.decrypted_amount;
            total_input_amount += decrypted_amount;
            let owned_stealth_addr = &owned_output.output.stealth;
            let compressed_stealth = CompressedRistretto::from_slice(&owned_stealth_addr);
            let wallets_res: Result<Vec<Wallet>, _> = (0..9).map(|_| Wallet::generate()).collect();
            let wallets = wallets_res?;
            let mut s_addrs: Vec<CompressedRistretto> =
                wallets.iter().map(|w| w.public_spend_key).collect();
            s_addrs.push(compressed_stealth);
            s_addrs.shuffle(&mut rand::thread_rng());
            let s_addrs_vec: Vec<Vec<u8>> =
                s_addrs.iter().map(|key| key.to_bytes().to_vec()).collect();
            let m = b"Message example";
            let blsag = wallet.gen_blsag(&s_addrs, m, &compressed_stealth)?;
            let image = blsag.i;
            let input = TransactionInput {
                msg_ring: s_addrs_vec,
                msg_blsag: blsag.to_vec(),
                msg_message: m.to_vec(),
                msg_key_image: image.to_bytes().to_vec(),
            };
            inputs.push(input);
        }

        Ok((inputs, total_input_amount))
    }

    // Constructs Outputs for the transaction by given Recipient address, output index and amount
    pub fn prepare_output(
        &self,
        wallet: &Wallet,
        recipient_address: &str,
        output_index: u64,
        amount: u64,
    ) -> Result<TransactionOutput, ChainOpsError> {
        let (recipient_spend_key, recipient_view_key) =
            derive_keys_from_address(recipient_address).unwrap();
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let recipient_view_key_point = recipient_view_key.decompress().unwrap();
        let q = r * recipient_view_key_point;
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let recipient_spend_key_point = recipient_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + recipient_spend_key_point).compress();
        let encrypted_amount = wallet.encrypt_amount(&q_bytes, output_index, amount)?;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let blinding = Scalar::random(&mut rand::thread_rng());
        let mut prover_transcript = Transcript::new(b"Transaction");
        let secret = amount;
        let (proof, commitment) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            secret,
            &blinding,
            32,
        )
        .unwrap();

        Ok(TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: proof.to_bytes().to_vec(),
            msg_commitment: commitment.to_bytes().to_vec(),
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        })
    }

    // Constructs change output in case the sum of inputs exceeds the amount we want to spend
    pub fn prepare_change_output(
        &self,
        wallet: &Wallet,
        change: u64,
        output_index: u64,
    ) -> Result<TransactionOutput, ChainOpsError> {
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let view_key_point = &wallet.public_view_key.decompress().unwrap();
        let q = r * view_key_point;
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let spend_key_point = &wallet.public_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + spend_key_point).compress();
        let encrypted_amount = wallet.encrypt_amount(&q_bytes, output_index, change)?;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(64, 1);
        let blinding = Scalar::random(&mut rand::thread_rng());
        let mut prover_transcript = Transcript::new(b"Transaction");
        let secret = change;
        let (proof, commitment) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            secret,
            &blinding,
            32,
        )
        .unwrap();

        Ok(TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: proof.to_bytes().to_vec(),
            msg_commitment: commitment.to_bytes().to_vec(),
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        })
    }
}

pub fn verify_root_hash(block: &Block) -> Result<bool, BlockOpsError> {
    let transaction_data: Vec<Vec<u8>> = block
        .msg_transactions
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_chain() -> Result<Chain, ChainOpsError> {
        let block_db = sled::open("C:/Vector/blocks").unwrap();
        let index_db = sled::open("C:/Vector/indexes").unwrap();
        let output_db = sled::open("C:/Vector/outputs").unwrap();
        let image_db = sled::open("C:/Vector/images").unwrap();
        let blocks: Arc<RwLock<dyn BlockStorer>> =
            Arc::new(RwLock::new(BlockDB::new(block_db, index_db)));
        let outputs: Arc<RwLock<dyn OutputStorer>> =
            Arc::new(RwLock::new(OutputDB::new(output_db)));
        let images: Arc<RwLock<dyn ImageStorer>> = Arc::new(RwLock::new(ImageDB::new(image_db)));
        let chain = Chain::new(blocks, images, outputs).await.unwrap();
        Ok(chain)
    }

    async fn create_test_block() -> Block {
        Block::default()
    }

    async fn create_test_wallet() -> Wallet {
        Wallet::generate().unwrap()
    }

    #[tokio::test]
    async fn test_chain_new() {
        let result = create_test_chain().await;
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.max_index().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_max_index() {
        let chain = create_test_chain().await.unwrap();
        assert_eq!(chain.max_index().await.unwrap(), 0);

        let block = create_test_block().await;
        let wallet = create_test_wallet().await;
        chain.add_block(&wallet, block).await.unwrap();
        assert_eq!(chain.max_index().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_add_block() {
        let chain = create_test_chain().await.unwrap();
        let block = create_test_block().await;
        let wallet = create_test_wallet().await;
        assert!(chain.add_block(&wallet, block).await.is_ok());
        assert_eq!(chain.max_index().await.unwrap(), 1);
    }
}
