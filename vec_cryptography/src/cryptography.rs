use curve25519_dalek_ng::{scalar::Scalar, ristretto::RistrettoPoint};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::constants;
use sha3::{Keccak256, Keccak512, Digest};
use bs58;
use curve25519_dalek_ng::traits::Identity;

#[derive(Clone, Copy)]
pub struct Signature {
    r: CompressedRistretto,
    s: Scalar,
}

struct Wallet {
    secret_spend_key: Scalar,
    secret_view_key: Scalar,
    public_spend_key: RistrettoPoint,
    public_view_key: RistrettoPoint,
    address: String,
}

#[derive(Clone)]
pub struct BLSAGSignature {
    c_1: Scalar,
    r_n: Vec<Scalar>,
    k_i: RistrettoPoint,
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
        let public_spend_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_view_key;

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
            public_spend_key: public_spend_key,
            public_view_key: public_view_key,
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
        let public_spend_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_view_key;

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
            public_spend_key: public_spend_key,
            public_view_key: public_view_key,
            address,
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let mut rng = rand::thread_rng();
    
        // Step 1: Generate a random nonce
        let nonce = Scalar::random(&mut rng);
    
        // Step 2: Calculate the point R = nonce * basepoint
        let r_ep = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let r = r_ep.compress();
    
        // Step 3: Hash the concatenation of R, the public key, and the message
        let mut hasher = Keccak256::new();
        hasher.update(r_ep.compress().as_bytes());
        hasher.update(self.public_spend_key.compress().as_bytes());
        hasher.update(message);
        let h = hasher.finalize();
    
        // Step 4: Convert the hash to a scalar
        let h_scalar = Scalar::from_bits(h.into());
    
        // Step 5: Calculate s = nonce - hash * secret_key
        let s = nonce - h_scalar * self.secret_spend_key;
    
        Signature { r, s }
    }
    
    fn verify(public_spend_key: RistrettoPoint, message: &[u8], signature: Signature) -> bool {
        // Step 1: Decompress the R value and public key
        let r = signature.r.decompress().unwrap();
        let public_spend_key_point = public_spend_key;
    
        // Step 2: Hash the concatenation of R, the public key, and the message
        let mut hasher = Keccak256::new();
        hasher.update(signature.r.as_bytes());
        hasher.update(public_spend_key.compress().as_bytes());
        hasher.update(message);
        let h = hasher.finalize();
    
        // Step 3: Convert the hash to a scalar
        let h_scalar = Scalar::from_bits(h.into());
    
        // Step 4: Calculate the expected R value: R' = s * basepoint + h * public_key
        let r_prime = &constants::RISTRETTO_BASEPOINT_TABLE * &signature.s + public_spend_key_point * &h_scalar;
    
        // Step 5: Verify the signature by checking if R equals R'
        r == r_prime
    }

    fn generate_one_time_address(&self, recipient_view_key: RistrettoPoint, recipient_spend_key: RistrettoPoint, output_index: u64) -> Result<(CompressedRistretto, CompressedRistretto), &'static str> {
        // Step 0: Generate a random transaction private key
        let mut rng = rand::thread_rng();
        let tx_private_key = Scalar::random(&mut rng);
        let dec_public_tx_key = &constants::RISTRETTO_BASEPOINT_TABLE * &tx_private_key;
        let public_tx_key = dec_public_tx_key.compress();
    
        // Step 1: Compute r * PV, where r is the transaction private key and PV is the recipient's public view key
        let recipient_view_key_point = recipient_view_key;
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
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hs;
    
        // Step 5: Add the recipient's public spend key PS to Hs(r * PV | i) * G to compute the final one-time address X
        let recipient_spend_key_point = recipient_spend_key;
        let one_time_address = hs_times_g + recipient_spend_key_point;
    
        Ok((one_time_address.compress(), public_tx_key))
    }
    

    fn check_property(&self, tx_public_key: CompressedRistretto, output_index: u64, output: CompressedRistretto) -> Result<bool, &'static str> {
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
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hs;
    
        // Step 5: Add the own public spend key PS to Hs(pV * R | i) * G to compute the expected output X
        let expected_output = hs_times_g + self.public_spend_key;
    
        Ok(expected_output.compress() == output)
    }

    fn blsag(&self, message: &[u8], secret_index: usize, keys: Vec<RistrettoPoint>) -> BLSAGSignature {
        let key_image = self.secret_spend_key * hash_to_point(&keys[secret_index]);
    
        let mut random_numbers: Vec<Scalar> = vec![Scalar::zero(); keys.len()];
        for i in 0..keys.len() {
            if i != secret_index {
                random_numbers[i] = Scalar::random(&mut rand::thread_rng());
            }
        }
        let alpha = Scalar::random(&mut rand::thread_rng());
        let alpha_point = &constants::RISTRETTO_BASEPOINT_TABLE * &alpha;
        let alpha_mul_image = alpha * key_image;
    
        let mut hasher = Keccak512::new();
        hasher.update(message);
        hasher.update(alpha_point.compress().as_bytes());
        hasher.update(alpha_mul_image.compress().as_bytes());
        let c_pi = hasher.finalize();
        let mut bytes = [0u8;64];
        bytes.copy_from_slice(c_pi.as_slice());
        let c_pi_scalar = Scalar::from_bytes_mod_order_wide(&bytes);
    
        let mut c_values: Vec<Scalar> = vec![Scalar::zero(); keys.len()];
        c_values[secret_index] = c_pi_scalar;

        for i in 0..keys.len() {
            let real_i = (i + secret_index + 1) % keys.len();
            let rngck = &constants::RISTRETTO_BASEPOINT_TABLE * &random_numbers[real_i] + c_values[real_i] * keys[real_i];
            let rnhpck = random_numbers[real_i] * hash_to_point(&keys[real_i]) + c_values[real_i] * key_image;
            let mut hasher = Keccak512::new();
            hasher.update(message);
            hasher.update(rngck.compress().as_bytes());
            hasher.update(rnhpck.compress().as_bytes());
            let c_i_plus_1 = hasher.finalize();
            let mut output_bytes = [0u8;64];
            output_bytes.copy_from_slice(c_i_plus_1.as_slice());
            c_values[real_i] = Scalar::from_bytes_mod_order_wide(&output_bytes);
        }

        let r_pi = alpha - c_values[secret_index] * self.secret_spend_key; // (mod l)
        random_numbers[secret_index] = r_pi;
    
        let signature = BLSAGSignature {
            c_1: c_values[0],
            r_n: random_numbers,
            k_i: key_image,
        };
    
        return signature;
    }
}

fn verify_blsag(message: &[u8], signature: &BLSAGSignature, keys: Vec<RistrettoPoint>) -> bool {
    let mut c_values: Vec<Scalar> = vec![Scalar::zero(); keys.len()];
    for i in 0..keys.len() {
        let rngck = &constants::RISTRETTO_BASEPOINT_TABLE * &signature.r_n[i] + c_values[i] * keys[i];
        let rnhpck = signature.r_n[i] * hash_to_point(&keys[i]) + c_values[i] * signature.k_i;
        let mut hasher = Keccak512::new();
        hasher.update(message);
        hasher.update(rngck.compress().as_bytes());
        hasher.update(rnhpck.compress().as_bytes());
        let c_i_plus_1 = hasher.finalize();
        let mut output_bytes = [0u8;64];
        output_bytes.copy_from_slice(c_i_plus_1.as_slice());
        c_values[i] = Scalar::from_bytes_mod_order_wide(&output_bytes);
    }

    return c_values[0] == signature.c_1;
}

fn to_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

fn hash_to_point(point: &RistrettoPoint) -> RistrettoPoint {
    let mut hasher = Keccak512::new();
    hasher.update(to_bytes(point));
    let hash = hasher.finalize();
    let mut output_bytes = [0u8; 64];
    output_bytes.copy_from_slice(&hash.as_slice());
    RistrettoPoint::from_uniform_bytes(&output_bytes)
}

//********************************************************************************************************************************************************/
//********************************************************************************************************************************************************/

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand::Rng;
    #[test]
    fn test_blsag_signature() {
        // Create a deterministic random number generator for testing
        let mut rng: StdRng = SeedableRng::from_entropy();

        // Generate a few wallets
        let wallets: Vec<Wallet> = (0..5).map(|_| Wallet::generate()).collect();

        // Extract public keys
        let public_keys: Vec<RistrettoPoint> = wallets.iter().map(|w| w.public_spend_key).collect();

        // Secret index
        let secret_index: usize = rng.gen_range(0..wallets.len());

        // Message to sign
        let message: Vec<u8> = b"This is a test message".to_vec();

        // Create the BLSAG signature
        let signature: BLSAGSignature = wallets[secret_index].blsag(&message, secret_index, public_keys.clone());

        // Verify the signature
        assert!(verify_blsag(&message, &signature, public_keys));
    }


    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate();

        // Check if the secret and public keys were generated properly
        assert_ne!(wallet.secret_spend_key, Scalar::zero());
        assert_ne!(wallet.secret_view_key, Scalar::zero());
        assert_ne!(*wallet.public_spend_key.compress().as_bytes(), [0; 32]);
        assert_ne!(*wallet.public_view_key.compress().as_bytes(), [0; 32]);

        // Check if the public keys are correct multiples of the secret keys
        assert_eq!(wallet.public_spend_key, (&constants::RISTRETTO_BASEPOINT_TABLE * &wallet.secret_spend_key));
        assert_eq!(wallet.public_view_key, (&constants::RISTRETTO_BASEPOINT_TABLE * &wallet.secret_view_key));

        // Check if the address is properly encoded
        let decoded_address = bs58::decode(&wallet.address).into_vec().unwrap();
        assert_eq!(decoded_address[0..32], wallet.public_spend_key.compress().as_bytes()[..]);
        assert_eq!(decoded_address[32..64], wallet.public_view_key.compress().as_bytes()[..]);
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
        assert_eq!(*wallet.public_spend_key.compress().as_bytes(), *reconstructed_wallet.public_spend_key.compress().as_bytes());
        assert_eq!(*wallet.public_view_key.compress().as_bytes(), *reconstructed_wallet.public_view_key.compress().as_bytes());
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

        assert_ne!(one_time_address, sender_wallet.public_spend_key.compress(), "One-time address should not be equal to the sender's public spend key");
        assert_ne!(one_time_address, recipient_wallet.public_spend_key.compress(), "One-time address should not be equal to the recipient's public spend key");

        // Check if the recipient can recognize the output as belonging to him
        let is_recipient = recipient_wallet.check_property(public_tx_key, output_index, one_time_address).unwrap();

        assert!(is_recipient, "The recipient could not recognize the output as belonging to him");

        // Now check if a malicious wallet can falsely claim the output
        let is_malicious = malicious_wallet.check_property(public_tx_key, output_index, one_time_address).unwrap();

        assert!(!is_malicious, "The malicious wallet should not be able to claim the output");
    }
}

//&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/
//&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/

// struct CLSAG {
//     I: RistrettoPoint,
//     D: RistrettoPoint,
//     c1: Scalar,
//     s: Vec<Scalar>,
// }

// pub struct LRSSignature {
//     pub c: Scalar,
//     pub s: Vec<Scalar>,
//     pub y_: RistrettoPoint,
// }

// pub fn generate_lrs(message: &[u8], keys: &[RistrettoPoint], skey: &Scalar, index: usize) -> LRSSignature {
//     let n = keys.len();
//     let mut s: Vec<Scalar> = vec![Scalar::zero(); n];
//     let mut c: Vec<Scalar> = vec![Scalar::zero(); n];
//     let mut rng = rand::thread_rng();

//     // Calculate key image
//     let mut hasher = Keccak256::new();
//     hasher.update(skey.as_bytes());
//     let hash = hasher.finalize();
//     let mut hash_bytes = [0u8;64];
//     hash_bytes.copy_from_slice(hash.as_slice());
//     let sk_p = RistrettoPoint::from_uniform_bytes(&hash_bytes);
//     let y_ = sk_p * skey;

//     // Set random s value for all members but the signer
//     for i in 0..n {
//         if i != index {
//             s[i] = Scalar::random(&mut rng);
//         }
//     }

//     // Calculate initial c value (c[0]) for the first member after the signer
//     let next_index = (index + 1) % n;
//     let mut hasher = Keccak256::new();
//     hasher.update(message);
//     let hash = hasher.finalize();
//     let mut hash_bytes = [0u8;64];
//     hash_bytes.copy_from_slice(hash.as_slice());
//     let h = RistrettoPoint::from_uniform_bytes(&hash_bytes);
//     let temp = keys[next_index] * s[next_index] + y_ * s[next_index] + h * s[next_index];

//     let mut hasher = Keccak256::new();
//     hasher.update(temp.compress().as_bytes());
//     let hash = hasher.finalize();
//     let mut hash_bytes = [0u8;64];
//     hash_bytes.copy_from_slice(hash.as_slice());
//     c[next_index] = Scalar::from_bytes_mod_order_wide(&hash_bytes);

//     // Calculate c value for other members
//     for i in 1..n {
//         let current_index = (index + i) % n;
//         let next_index = (index + i + 1) % n;
//         let temp = keys[next_index] * s[current_index] + y_ * s[current_index] + h * s[next_index];
//         let mut hasher = Keccak256::new();
//         hasher.update(temp.compress().as_bytes());
//         let hash = hasher.finalize();
//         let mut hash_bytes = [0u8;64];
//         hash_bytes.copy_from_slice(hash.as_slice());
//         c[next_index] = Scalar::from_bytes_mod_order_wide(&hash_bytes);
//     }

//     // Calculate s value for the signer
//     s[index] = Scalar::random(&mut rng) - c[index] * skey;

//     LRSSignature { c: c[0], s, y_ }
// }

// pub fn verify_lrs(message: &[u8], keys: &[RistrettoPoint], signature: &LRSSignature) -> bool {
//     let n = keys.len();
//     let mut c: Vec<Scalar> = vec![Scalar::zero(); n];

//     // Calculate the hash of the message
//     let mut hasher = Keccak256::new();
//     hasher.update(message);
//     let hash = hasher.finalize();
//     let mut hash_bytes = [0u8;64];
//     hash_bytes.copy_from_slice(hash.as_slice());
//     let h = RistrettoPoint::from_uniform_bytes(&hash_bytes);

//     // Set the first c value to the one from the signature
//     c[0] = signature.c;

//     // Calculate c values for all members
//     for i in 0..n {
//         let next_index = (i + 1) % n;
//         let temp = keys[i] * signature.s[i] + signature.y_ * c[i] + h * signature.s[next_index];

//         let mut hasher = Keccak256::new();
//         hasher.update(temp.compress().as_bytes());
//         let hash = hasher.finalize();
//         let mut hash_bytes = [0u8;64];
//         hash_bytes.copy_from_slice(hash.as_slice());
//         c[next_index] = Scalar::from_bytes_mod_order_wide(&hash_bytes);
//     }

//     // Check if the calculated c value is the same as the initial one
//     c[0] == signature.c
// }


fn load_3(input: &[u8]) -> i64 {
    let mut result = 0i64;
    result = result | ((input[0] as i64));
    result = result | ((input[1] as i64) << 8);
    result = result | ((input[2] as i64) << 16);
    result
}

fn load_4(input: &[u8]) -> i64 {
    let mut result = 0i64;
    result = result | ((input[0] as i64));
    result = result | ((input[1] as i64) << 8);
    result = result | ((input[2] as i64) << 16);
    result = result | ((input[3] as i64) << 24);
    result
}

fn sc_reduce32(s: &mut [u8]) {
    let mut s0 = 2097151 & load_3(&s[0..3]);
    let mut s1  = 2097151 & (load_4(&s[2..6]) >> 5);
    let mut s2  = 2097151 & (load_3(&s[5..8]) >> 2);
    let mut s3  = 2097151 & (load_4(&s[7..11]) >> 7);
    let mut s4  = 2097151 & (load_4(&s[10..14]) >> 4);
    let mut s5  = 2097151 & (load_3(&s[13..16]) >> 1);
    let mut s6  = 2097151 & (load_4(&s[15..19]) >> 6);
    let mut s7  = 2097151 & (load_3(&s[18..21]) >> 3);
    let mut s8  = 2097151 & load_3(&s[21..24]);
    let mut s9  = 2097151 & (load_4(&s[23..27]) >> 5);
    let mut s10 = 2097151 & (load_3(&s[26..29]) >> 2);
    let mut s11 = load_4(&s[28..32]) >> 7;
    let mut s12 = 0;

    let mut carry = vec![0i64; 12];

    let m = 1 << 20;
    let n = 21;
    for _ in 0..2 {
        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry[0]  = (s0 + m) >> n; s1 += carry[0]; s0 -= carry[0] << n;
        carry[1]  = (s1 + m) >> n; s2 += carry[1]; s1 -= carry[1] << n;
        carry[2]  = (s2 + m) >> n; s3 += carry[2]; s2 -= carry[2] << n;
        carry[3]  = (s3 + m) >> n; s4 += carry[3]; s3 -= carry[3] << n;
        carry[4]  = (s4 + m) >> n; s5 += carry[4]; s4 -= carry[4] << n;
        carry[5]  = (s5 + m) >> n; s6 += carry[5]; s5 -= carry[5] << n;
        carry[6]  = (s6 + m) >> n; s7 += carry[6]; s6 -= carry[6] << n;
        carry[7]  = (s7 + m) >> n; s8 += carry[7]; s7 -= carry[7] << n;
        carry[8]  = (s8 + m) >> n; s9 += carry[8]; s8 -= carry[8] << n;
        carry[9]  = (s9 + m) >> n; s10 += carry[9]; s9 -= carry[9] << n;
        carry[10] = (s10 + m) >> n; s11 += carry[10]; s10 -= carry[10] << n;
        carry[11] = (s11 + m) >> n; s12 += carry[11]; s11 -= carry[11] << n;
    }

    let mut s = vec![
        s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11
    ];

    for i in 0..12 {
        s[i] += s12 * [666643, 470296, 654183, -997805, 136657, -683901][i % 6];
        carry[i] = s[i] >> 21;
        if i < 11 {
            s[i + 1] += carry[i];
        }
        s[i] -= carry[i] << 21;
    }
}


// fn H_n(x: &[u8]) -> [u8; 32] {
//     let mut hasher = Keccak256::new();
//     hasher.update(x);
//     let mut data = hasher.finalize().to_vec();
//     sc_reduce32(&mut data);
//     data.try_into().expect("Wrong length after sc_reduce32")
// }