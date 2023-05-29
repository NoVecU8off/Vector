use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::edwards::CompressedEdwardsY;
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
}


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
}
