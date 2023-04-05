// pub fn validate_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
    //     let signature_vec = block.msg_signature.clone();
    //     let signature = Signature::signature_from_vec(&signature_vec);
    
    //     let public_key = PublicKey::from_bytes(&block.msg_public_key)
    //         .map_err(|_| "Invalid public key in block")?;
    
    //     let dummy_secret_key = SecretKey::from_bytes(&[0u8; 32]).unwrap();
    //     let dummy_expanded_secret_key = ExpandedSecretKey::from(&dummy_secret_key);
    
    //     let keypair = Keypair {
    //         private: dummy_secret_key, // This will not be used
    //         optional_private: None, // This will not be used
    //         expanded_private_key: dummy_expanded_secret_key, // This will not be used
    //         public: public_key,
    //     };
    
    //     if let Ok(false) = block::verify_block(block, &signature, &keypair) {
    //         return Err("invalid block signature".into());
    //     }
    
    //     let current_block = self.get_block_by_height(self.height())?;
    //     let hash = block::hash_block(&current_block).unwrap().to_vec();
    
    //     if let Some(header) = block.msg_header.as_ref() {
    //         if hash != header.msg_previous_hash {
    //             return Err("invalid previous block hash".into());
    //         }
    //     } else {
    //         return Err("Block header is missing".into());
    //     }
    
    //     for tx in &block.msg_transactions {
    //         self.validate_transaction(tx, &[keypair.public.clone()])?;
    //     }
    
    //     Ok(())
    // }

    // pub fn validate_transaction(&self, tx: &Transaction, public_keys: &[PublicKey]) -> Result<(), Box<dyn std::error::Error>> {
    
    //     if !transaction::verify_transaction(tx, public_keys) {
    //         return Err("invalid tx signature".into());
    //     }
    
    //     let n_inputs = tx.msg_inputs.len();
    //     let hash = hex::encode(transaction::hash_transaction(tx));
    //     let mut sum_inputs = 0;
    
    //     for i in 0..n_inputs {
    
    //         let prev_hash = hex::encode(&tx.msg_inputs[i].msg_previous_tx_hash);
    //         if let Some(utxo) = self.utxo_store.get(&prev_hash, tx.msg_inputs[i].msg_previous_out_index)? {
    //             sum_inputs += utxo.amount as i32;
    
    //             if utxo.spent {
    //                 return Err(format!("input {} of tx {} is already spent", i, hash).into());
    //             }
    //         } else {
    //             return Err(format!("UTXO not found for input {} of tx {}", i, hash).into());
    //         }
    
    //     }
    
    //     let sum_outputs: i32 = tx.msg_outputs.iter().map(|o| o.msg_amount as i32).sum();
    
    //     if sum_inputs < sum_outputs {
    //         return Err(format!("insufficient balance got ({}) spending ({})", sum_inputs, sum_outputs).into());
    //     }
    
    //     Ok(())
    // }
    
// }