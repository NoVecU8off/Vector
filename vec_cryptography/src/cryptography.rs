use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
use curve25519_dalek_ng::edwards::EdwardsPoint;
use curve25519_dalek_ng::constants;
use sha3::{Keccak256, Digest};
use bs58;

struct Wallet {
    secret_spend_key: Scalar,
    secret_view_key: Scalar,
    public_spend_key: CompressedEdwardsY,
    public_view_key: CompressedEdwardsY,
    address: String,
}

#[derive(Clone, Copy)]
pub struct Signature {
    r: CompressedEdwardsY,
    s: Scalar,
}

impl Wallet {
    fn generate() -> Wallet {
        let mut rng = rand::thread_rng();

        // Generate a random secret spend key
        let secret_spend_key: Scalar = Scalar::random(&mut rng);

        // Derive the secret view key by hashing the secret spend key and reducing modulo l
        let mut hasher = Keccak256::new();
        hasher.update(secret_spend_key.as_bytes());
        let hashed_key = hasher.finalize();
        let secret_view_key = Scalar::from_bytes_mod_order(hashed_key.into());

        // Calculate the public keys by multiplying the secret keys by the basepoint of the elliptic curve
        let public_spend_key = &constants::ED25519_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::ED25519_BASEPOINT_TABLE * &secret_view_key;

        // Prepare the address data (public spend key + public view key)
        let mut data = vec![];
        data.extend(public_spend_key.compress().as_bytes());
        data.extend(public_view_key.compress().as_bytes());

        // Add the checksum (the first four bytes of the Keccak-256 hash of the address data)
        let mut hasher = Keccak256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        data.extend(&hash[0..4]);

        // Encode the address data as a Base58 string
        let address = bs58::encode(&data).into_string();

        Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key: public_spend_key.compress(),
            public_view_key: public_view_key.compress(),
            address,
        }
    }

    fn reconstruct(secret_spend_key: Scalar) -> Wallet {
        // Derive the secret view key by hashing the secret spend key and reducing modulo l
        let mut hasher = Keccak256::new();
        hasher.update(secret_spend_key.as_bytes());
        let hashed_key = hasher.finalize();
        let secret_view_key = Scalar::from_bytes_mod_order(hashed_key.into());

        // Calculate the public keys by multiplying the secret keys by the basepoint of the elliptic curve
        let public_spend_key = &constants::ED25519_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::ED25519_BASEPOINT_TABLE * &secret_view_key;

        // Prepare the address data (public spend key + public view key)
        let mut data = vec![];
        data.extend(public_spend_key.compress().as_bytes());
        data.extend(public_view_key.compress().as_bytes());

        // Add the checksum (the first four bytes of the Keccak-256 hash of the address data)
        let mut hasher = Keccak256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        data.extend(&hash[0..4]);

        // Encode the address data as a Base58 string
        let address = bs58::encode(&data).into_string();

        Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key: public_spend_key.compress(),
            public_view_key: public_view_key.compress(),
            address,
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let mut rng = rand::thread_rng();
    
        // Step 1: Generate a random nonce
        let nonce = Scalar::random(&mut rng);
    
        // Step 2: Calculate the point R = nonce * basepoint
        let r_ep = &constants::ED25519_BASEPOINT_TABLE * &nonce;
        let r = r_ep.compress();
    
        // Step 3: Hash the concatenation of R, the public key, and the message
        let mut hasher = Keccak256::new();
        hasher.update(r_ep.compress().as_bytes());
        hasher.update(self.public_spend_key.as_bytes());
        hasher.update(message);
        let h = hasher.finalize();
    
        // Step 4: Convert the hash to a scalar
        let h_scalar = Scalar::from_bits(h.into());
    
        // Step 5: Calculate s = nonce - hash * secret_key
        let s = nonce - h_scalar * self.secret_spend_key;
    
        Signature { r, s }
    }
    
    fn verify(public_spend_key: CompressedEdwardsY, message: &[u8], signature: Signature) -> bool {
        // Step 1: Decompress the R value and public key
        let r = signature.r.decompress().unwrap();
        let public_spend_key_point = public_spend_key.decompress().unwrap();
    
        // Step 2: Hash the concatenation of R, the public key, and the message
        let mut hasher = Keccak256::new();
        hasher.update(signature.r.as_bytes());
        hasher.update(public_spend_key.as_bytes());
        hasher.update(message);
        let h = hasher.finalize();
    
        // Step 3: Convert the hash to a scalar
        let h_scalar = Scalar::from_bits(h.into());
    
        // Step 4: Calculate the expected R value: R' = s * basepoint + h * public_key
        let r_prime = &constants::ED25519_BASEPOINT_TABLE * &signature.s + public_spend_key_point * &h_scalar;
    
        // Step 5: Verify the signature by checking if R equals R'
        r == r_prime
    }

    fn generate_one_time_address(&self, recipient_view_key: CompressedEdwardsY, recipient_spend_key: CompressedEdwardsY, output_index: u64) -> Result<(CompressedEdwardsY, CompressedEdwardsY), &'static str> {
        // Step 0: Generate a random transaction private key
        let mut rng = rand::thread_rng();
        let tx_private_key = Scalar::random(&mut rng);
        let dec_public_tx_key = &constants::ED25519_BASEPOINT_TABLE * &tx_private_key;
        let public_tx_key = dec_public_tx_key.compress();

        // Step 1: Compute r * PV, where r is the transaction private key and PV is the recipient's public view key
        let recipient_view_key_point = recipient_view_key.decompress().ok_or("Failed to decompress recipient's public view key")?;
        let r_times_pv = tx_private_key * recipient_view_key_point;

        // Step 2: Append the output index i to r * PV
        let mut r_times_pv_bytes = r_times_pv.compress().as_bytes().to_vec();
        r_times_pv_bytes.extend(&output_index.to_le_bytes());

        // Step 3: Hash (r * PV | i) using Keccak-256 and reduce modulo l
        let mut hasher = Keccak256::new();
        hasher.update(&r_times_pv_bytes);
        let hashed_key = hasher.finalize();
        let hs = Scalar::from_bytes_mod_order(hashed_key.into());

        // Step 4: Compute Hs(r * PV | i) * G, where G is the base point of the elliptic curve
        let hs_times_g = &constants::ED25519_BASEPOINT_TABLE * &hs;

        // Step 5: Add the recipient's public spend key PS to Hs(r * PV | i) * G to compute the final one-time address X
        let recipient_spend_key_point = recipient_spend_key.decompress().ok_or("Failed to decompress recipient's public spend key")?;
        let one_time_address = hs_times_g + recipient_spend_key_point;

        Ok((one_time_address.compress(), public_tx_key))
    }

    fn check_property(&self, tx_public_key: CompressedEdwardsY, output_index: u64, output: CompressedEdwardsY) -> Result<bool, &'static str> {
        // Step 1: Compute pV * R, where pV is the private view key and R is the transaction public key
        let tx_public_key_point = tx_public_key.decompress().ok_or("Failed to decompress transaction public key")?;
        let pv_times_r = self.secret_view_key * tx_public_key_point;

        // Step 2: Append the output index i to pV * R
        let mut pv_times_r_bytes = pv_times_r.compress().as_bytes().to_vec();
        pv_times_r_bytes.extend(&output_index.to_le_bytes());

        // Step 3: Hash (pV * R | i) using Keccak-256 and reduce modulo l
        let mut hasher = Keccak256::new();
        hasher.update(&pv_times_r_bytes);
        let hashed_key = hasher.finalize();
        let hs = Scalar::from_bytes_mod_order(hashed_key.into());

        // Step 4: Compute Hs(pV * R | i) * G, where G is the base point of the elliptic curve
        let hs_times_g = &constants::ED25519_BASEPOINT_TABLE * &hs;

        // Step 5: Add the own public spend key PS to Hs(pV * R | i) * G to compute the expected output X
        let expected_output = hs_times_g + self.public_spend_key.decompress().ok_or("Failed to decompress own public spend key")?;

        Ok(expected_output.compress() == output)
    }

    pub fn generate_ring_signature(&self, message: &[u8], keys: Vec<CompressedEdwardsY>, secret_index: usize) -> Result<(Vec<Scalar>, Scalar, Scalar), &'static str> {
        if secret_index >= keys.len() {
            return Err("Invalid secret index");
        }

        let n = keys.len();
        let hp_r = Self::hash_points_to_point(&keys);

        // Step 1: Calculate the key image
        let key_image = self.secret_spend_key * hp_r;

        // Step 2: Generate random values
        let mut rng = rand::thread_rng();
        let alpha = Scalar::random(&mut rng);
        let mut r_values: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();

        // Step 3: Calculate c_values[secret_index + 1]
        let mut c_values: Vec<Scalar> = vec![Scalar::zero(); n];
        c_values[(secret_index + 1) % n] = Self::hash_numbers(
            &keys,
            &key_image,
            message,
            &(&constants::ED25519_BASEPOINT_TABLE * &alpha).compress(),
            &(hp_r * alpha),
        );

        // Step 4: Calculate the remaining c_values
        for i in (secret_index + 1)..(secret_index + n) {
            let i = i % n;
            let ci = c_values[i];
            let ri = r_values[i];
            let ki = keys[i].decompress().ok_or("Failed to decompress public key")?;

            let term1 = &constants::ED25519_BASEPOINT_TABLE * &ri + ki * &ci;
            let term2 = hp_r * ri + key_image * ci;

            c_values[(i + 1) % n] = Self::hash_numbers(
                &keys,
                &key_image,
                message,
                &term1.compress(),
                &term2,
            );
        }

        // Step 5: Calculate r_values[secret_index]
        r_values[secret_index] = alpha - c_values[secret_index] * self.secret_spend_key;

        Ok((c_values, r_values[secret_index], key_image))
    }

    pub fn verify_ring_signature(&self, message: &[u8], keys: Vec<CompressedEdwardsY>, c_values: Vec<Scalar>, r_value: Scalar, key_image: Scalar) -> Result<bool, &'static str> {
        let n = keys.len();

        let hp_r = Self::hash_points_to_point(&keys);
        
        let mut calculated_c_values: Vec<Scalar> = vec![Scalar::zero(); n];
        calculated_c_values[0] = c_values[0];

        for i in 0..n {
            let ri = if i == 0 { r_value } else { c_values[i-1] };
            let ci = calculated_c_values[i];
            let ki = keys[i].decompress().ok_or("Failed to decompress public key")?;
            
            let term1 = &constants::ED25519_BASEPOINT_TABLE * &ri + ki * &ci;
            let term2 = hp_r * ri + key_image * ci;
            
            calculated_c_values[(i + 1) % n] = Self::hash_numbers(
                &keys,
                &key_image,
                message,
                &term1.compress(),
                &term2,
            );
        }

        Ok(c_values[0] == calculated_c_values[0])
    }

    // Hash function Hn
    fn hash_numbers_ver(keys: &[CompressedEdwardsY], key_image: &CompressedEdwardsY, message: &[u8], z_prime: &CompressedEdwardsY, z_double_prime: &CompressedEdwardsY) -> Scalar {
        let mut hasher = Keccak256::new();
        for key in keys {
            hasher.update(key.as_bytes());
        }
        hasher.update(key_image.as_bytes());
        hasher.update(message);
        hasher.update(z_prime.as_bytes());
        hasher.update(z_double_prime.as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }

    // Hash function Hn
    fn hash_numbers(keys: &[CompressedEdwardsY], key_image: &Scalar, message: &[u8], term1: &CompressedEdwardsY, term2: &Scalar) -> Scalar {
        let mut hasher = Keccak256::new();
        for key in keys {
            hasher.update(key.as_bytes());
        }
        hasher.update(key_image.as_bytes());
        hasher.update(message);
        hasher.update(term1.as_bytes());
        hasher.update(term2.as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }

    // Hash function Hp
    fn hash_points_to_point(keys: &[CompressedEdwardsY]) -> Scalar {
        let mut hasher = Keccak256::new();
        for key in keys {
            hasher.update(key.as_bytes());
        }
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order(hash.into())
    }

    // pub fn verify_ring_signature(
    //     message: &[u8], 
    //     ring_signature: (Vec<Scalar>, Scalar, Scalar), 
    //     keys: Vec<CompressedEdwardsY>,
    // ) -> Result<bool, &'static str> {
    //     let n = keys.len();
    //     let (c_values, secret_r, key_image) = ring_signature;
        
    //     let hp_r = Self::hash_points_to_point(&keys);

    //     let mut computed_c_values: Vec<Scalar> = vec![Scalar::zero(); n];
    //     for i in 0..n {
    //         let ki = keys[i].decompress().ok_or("Failed to decompress public key")?;
            
    //         let term1 = &constants::ED25519_BASEPOINT_TABLE * &c_values[i] + ki * &computed_c_values[i];
    //         let term2 = hp_r * c_values[i] + key_image * computed_c_values[i];
            
    //         computed_c_values[(i + 1) % n] = Self::hash_numbers(
    //             &keys,
    //             &key_image,
    //             message,
    //             &term1.compress(),
    //             &term2,
    //         );
    //     }

    //     // Check if the computed c_values match the original c_values
    //     if c_values == computed_c_values {
    //         Ok(true)
    //     } else {
    //         Ok(false)
    //     }
    // }

    // pub fn verify_ring_signature(
    //     keys: Vec<CompressedEdwardsY>,
    //     message: &[u8],
    //     c_values: Vec<Scalar>,
    //     r_value: Scalar,
    //     key_image: EdwardsPoint
    // ) -> Result<bool, &'static str> {
    //     let n = keys.len();
    //     let hp_r = Self::hash_points_to_point(&keys);
        
    //     // Initialize vectors to hold z_prime and z_double_prime values
    //     let mut z_prime: Vec<EdwardsPoint> = vec![EdwardsPoint::default(); n];
    //     let mut z_double_prime: Vec<EdwardsPoint> = vec![EdwardsPoint::default(); n];
    
    //     // Step 1: Compute z_prime and z_double_prime for all i in {1, 2, ..., n}
    //     for i in 0..n {
    //         let ci = c_values[i];
    //         let ri = r_value;
    //         let ki = keys[i].decompress().ok_or("Failed to decompress public key")?;
            
    //         z_prime[i] = &constants::ED25519_BASEPOINT_TABLE * &ri + ki * &ci;
    //         z_double_prime[i] = (hp_r * ri) + (key_image * ci);
    //     }
    
    //     // Compute c_prime_values
    //     let mut c_prime_values: Vec<Scalar> = vec![Scalar::zero(); n];
    //     for i in 0..n {
    //         c_prime_values[(i + 1) % n] = Self::hash_numbers_ver(
    //             &keys,
    //             &key_image.compress(),
    //             message,
    //             &z_prime[i].compress(),
    //             &z_double_prime[i].compress()
    //         );
    //     }
    
    //     // Step 2: Check if c1_prime equals to c1
    //     if c_prime_values[0] == c_values[0] {
    //         Ok(true)
    //     } else {
    //         Err("Signature is not valid.")
    //     }
    // }
}

//********************************************************************************************************************************************************/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate();

        // Check if the secret and public keys were generated properly
        assert_ne!(wallet.secret_spend_key, Scalar::zero());
        assert_ne!(wallet.secret_view_key, Scalar::zero());
        assert_ne!(*wallet.public_spend_key.as_bytes(), [0; 32]);
        assert_ne!(*wallet.public_view_key.as_bytes(), [0; 32]);

        // Check if the public keys are correct multiples of the secret keys
        assert_eq!(wallet.public_spend_key, (&constants::ED25519_BASEPOINT_TABLE * &wallet.secret_spend_key).compress());
        assert_eq!(wallet.public_view_key, (&constants::ED25519_BASEPOINT_TABLE * &wallet.secret_view_key).compress());

        // Check if the address is properly encoded
        let decoded_address = bs58::decode(&wallet.address).into_vec().unwrap();
        assert_eq!(decoded_address[0..32], wallet.public_spend_key.as_bytes()[..]);
        assert_eq!(decoded_address[32..64], wallet.public_view_key.as_bytes()[..]);
    }

    #[test]
    fn test_wallet_signature() {
        let wallet = Wallet::generate();
        let message = b"Hello, World!";

        // Sign the message
        let signature = wallet.sign(message);

        // Check if the signature is valid
        assert!(Wallet::verify(wallet.public_spend_key, message, signature));

        // Check if the signature is invalid for a different message
        let different_message = b"Goodbye, World!";
        assert!(!Wallet::verify(wallet.public_spend_key, different_message, signature));

        // Check if the signature is invalid for a different key
        let different_wallet = Wallet::generate();
        assert!(!Wallet::verify(different_wallet.public_spend_key, message, signature));
    }

    #[test]
    fn test_wallet_reconstruction() {
        // Generate a new wallet
        let wallet = Wallet::generate();
        
        // Reconstruct the wallet using only the secret spend key
        let reconstructed_wallet = Wallet::reconstruct(wallet.secret_spend_key);

        // Check if the reconstructed wallet matches the original
        assert_eq!(wallet.secret_spend_key, reconstructed_wallet.secret_spend_key);
        assert_eq!(wallet.secret_view_key, reconstructed_wallet.secret_view_key);
        assert_eq!(*wallet.public_spend_key.as_bytes(), *reconstructed_wallet.public_spend_key.as_bytes());
        assert_eq!(*wallet.public_view_key.as_bytes(), *reconstructed_wallet.public_view_key.as_bytes());
        assert_eq!(wallet.address, reconstructed_wallet.address);
    }

    #[test]
    fn test_address_generation_and_checking() {
        let sender_wallet = Wallet::generate();
        let recipient_wallet = Wallet::generate();
        let malicious_wallet = Wallet::generate();

        assert_ne!(sender_wallet.secret_spend_key, recipient_wallet.secret_spend_key, "Sender and recipient spend keys should not be equal");
        assert_ne!(sender_wallet.secret_view_key, recipient_wallet.secret_view_key, "Sender and recipient view keys should not be equal");
        assert_ne!(sender_wallet.public_spend_key, recipient_wallet.public_spend_key, "Sender and recipient public spend keys should not be equal");
        assert_ne!(sender_wallet.public_view_key, recipient_wallet.public_view_key, "Sender and recipient public view keys should not be equal");

        let output_index = 0;
        let (one_time_address, public_tx_key) = sender_wallet
            .generate_one_time_address(
                recipient_wallet.public_view_key, 
                recipient_wallet.public_spend_key, 
                output_index
            ).unwrap();

        assert_ne!(one_time_address, sender_wallet.public_spend_key, "One-time address should not be equal to the sender's public spend key");
        assert_ne!(one_time_address, recipient_wallet.public_spend_key, "One-time address should not be equal to the recipient's public spend key");

        // Check if the recipient can recognize the output as belonging to him
        let is_recipient = recipient_wallet.check_property(public_tx_key, output_index, one_time_address).unwrap();

        assert!(is_recipient, "The recipient could not recognize the output as belonging to him");

        // Now check if a malicious wallet can falsely claim the output
        let is_malicious = malicious_wallet.check_property(public_tx_key, output_index, one_time_address).unwrap();

        assert!(!is_malicious, "The malicious wallet should not be able to claim the output");
    }

    #[test]
    fn test_ring_signature() {
        // Generate a wallet with random secret keys
        let wallet = Wallet::generate();

        // Generate a list of keys
        let mut rng = rand::thread_rng();
        let mut keys: Vec<CompressedEdwardsY> = (0..9) // Generate 9 random keys
            .map(|_| (&constants::ED25519_BASEPOINT_TABLE * &Scalar::random(&mut rng)).compress())
            .collect();

        // Add the public key of the wallet to the list of keys
        keys.push(wallet.public_spend_key);

        // Generate a ring signature
        let message = b"test message";
        let secret_index = keys.len() - 1; // The index of the wallet's public key in the keys vector
        let (c_values, r_value, key_image) = wallet.generate_ring_signature(message, keys.clone(), secret_index)
            .expect("Failed to generate ring signature");

        // Verify the ring signature
        let verified = wallet.verify_ring_signature(message, keys, c_values, r_value, key_image)
            .expect("Failed to verify ring signature");
        assert!(verified);
    }

}
