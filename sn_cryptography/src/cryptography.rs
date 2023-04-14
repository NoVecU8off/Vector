use ed25519_dalek::{SecretKey, ExpandedSecretKey, PublicKey, Signature as Ed25519Signature};
use ed25519_dalek::{Verifier};
use rand::{Rng, thread_rng};
use rand::{rngs::OsRng, RngCore};
use sha3::{Sha3_512, Digest};
use arrayref::{array_ref};
use std::fmt;

pub fn generate_seed_thread() -> [u8; 32] {
    let mut threaded_seed = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill(&mut threaded_seed);
    threaded_seed
}

pub fn generate_seed_os() -> [u8; 32] {
    let mut os_seed = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut os_seed);
    os_seed
}

pub fn inherit_seed() -> [u8; 32] {
    let t_seed = generate_seed_thread();
    let o_seed = generate_seed_os();
    let mut hasher = Sha3_512::new();
    hasher.update(array_ref![t_seed, 0, 32]);
    hasher.update(array_ref![o_seed, 0, 32]);
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    seed
}
pub struct Keypair {
    pub private: SecretKey,
    pub optional_private: Option<SecretKey>,
    pub expanded_private_key: ExpandedSecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate_keypair() -> Self {
        let seed = inherit_seed();
        let private_key = SecretKey::from_bytes(&seed).unwrap();
        let expanded_secret_key: ExpandedSecretKey = ExpandedSecretKey::from(&private_key);
        let public_key = PublicKey::from(&expanded_secret_key);
        Keypair {
            private: private_key,
            optional_private: None, // Initialize `optional_private` with None
            expanded_private_key: expanded_secret_key,
            public: public_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.expanded_private_key.sign(message, &self.public);
        Signature {
            signature: sig,
        }
    }

    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool { 
        self.public.verify(message, &sig.signature).is_ok()
    }

    pub fn derive_address(&self) -> Address {
        let bytes = self.public.as_bytes();
        let (_, public_tail) = bytes.split_at(bytes.len() - 20);
        Address {
            address: public_tail.try_into().unwrap(),
        }
    }

    pub fn public_to_vec(&self) -> Vec<u8> {
        let vec_public = self.public.as_bytes().to_vec();
        vec_public
    }

    pub fn public_key_from_vec(vec_public: &[u8]) -> PublicKey {
        PublicKey::from_bytes(vec_public).unwrap()
    }
}

impl Clone for Keypair {
    fn clone(&self) -> Self {
        let private = SecretKey::from_bytes(&self.private.to_bytes()).expect("Unable to clone SecretKey");
        let optional_private = self.optional_private.as_ref().map(|sk| SecretKey::from_bytes(&sk.to_bytes()).expect("Unable to clone optional SecretKey"));
        let expanded_private_key = ExpandedSecretKey::from_bytes(&self.expanded_private_key.to_bytes()).expect("Unable to clone ExpandedSecretKey");
        let public = PublicKey::from_bytes(&self.public.to_bytes()).expect("Unable to clone PublicKey");
        Self {
            private,
            optional_private,
            expanded_private_key,
            public,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub address: [u8; 20],
}

impl Address {
    pub fn to_bytes(&self) -> [u8; 20] {
        self.address
    }

    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address {
            address: bytes
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.address.to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub signature: Ed25519Signature,
}

impl Signature {
    pub fn to_vec(&self) -> Vec<u8> {
        self.signature.as_ref().to_vec()
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(self.signature.as_ref());
        bytes    
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self {
            signature: Ed25519Signature::from_bytes(&bytes).unwrap()
        }
    }

    pub fn v_to_bytes(&self) -> [u8; 64] {
        vec_to_bytes(&self.signature.as_ref().to_vec())
    }

    pub fn signature_from_vec(vec_signature: &[u8]) -> Signature {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(vec_signature);
        Signature {
            signature: Ed25519Signature::from_bytes(&bytes).unwrap(),
        }
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.signature.to_bytes()))
    }
}

impl std::convert::From<[u8; 64]> for Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self::from_bytes(bytes)
    }
}

pub fn vec_to_bytes(vec: &Vec<u8>) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    let num_bytes = std::cmp::min(vec.len(), 64);
    bytes[..num_bytes].copy_from_slice(&vec[..num_bytes]);
    bytes
}

impl std::fmt::Display for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}, {:?}, {:?}", self.private, self.optional_private, self.public)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.address)
    }
}

impl std::convert::From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Self::from_bytes(bytes)    
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("private", &self.private)
            .field("optional_private", &self.optional_private)
            .field("public", &self.public)
            .finish()
    }
}
