use ed25519_dalek::{SecretKey, ExpandedSecretKey, PublicKey, Signature as Ed25519Signature};
use ed25519_dalek::{Verifier};
use rand::{Rng, thread_rng};
use rand::{rngs::OsRng, RngCore};
use sha3::{Sha3_256, Digest};
use arrayref::{array_ref};
use std::fmt;
use serde::{Serializer, Deserializer, Serialize, Deserialize, de::Error as DeError};

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
    let mut hasher = Sha3_256::new();
    hasher.update(array_ref![t_seed, 0, 32]);
    hasher.update(array_ref![o_seed, 0, 32]);
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    seed
}
pub struct NodeKeypair {
    pub private: SecretKey,
    pub expanded_private_key: ExpandedSecretKey,
    pub public: PublicKey,
}

impl NodeKeypair {
    pub fn generate_keypair() -> Self {
        let seed = inherit_seed();
        let private_key = SecretKey::from_bytes(&seed).unwrap();
        let expanded_secret_key = ExpandedSecretKey::from(&private_key);
        let public_key = PublicKey::from(&expanded_secret_key);
        NodeKeypair {
            private: private_key,
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

    pub fn public_to_vec(&self) -> Vec<u8> {
        let vec_public = self.public.as_bytes().to_vec();
        vec_public
    }

    pub fn public_key_from_vec(vec_public: &[u8]) -> PublicKey {
        PublicKey::from_bytes(vec_public).unwrap()
    }
}

impl Clone for NodeKeypair {
    fn clone(&self) -> Self {
        let private = SecretKey::from_bytes(&self.private.to_bytes()).expect("Unable to clone SecretKey");
        let expanded_private_key = ExpandedSecretKey::from_bytes(&self.expanded_private_key.to_bytes()).expect("Unable to clone ExpandedSecretKey");
        let public = PublicKey::from_bytes(&self.public.to_bytes()).expect("Unable to clone PublicKey");
        Self {
            private,
            expanded_private_key,
            public,
        }
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

impl std::fmt::Display for NodeKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}, {:?}", self.private, self.public)
    }
}

impl fmt::Debug for NodeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("private", &self.private)
            .field("public", &self.public)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct SerializableKeypair {
    private: Vec<u8>,
    expanded_private_key: Vec<u8>,
    public: Vec<u8>,
}

impl Serialize for NodeKeypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = SerializableKeypair {
            private: self.private.to_bytes().to_vec(),
            expanded_private_key: self.expanded_private_key.to_bytes().to_vec(),
            public: self.public.to_bytes().to_vec(),
        };
        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NodeKeypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serializable = SerializableKeypair::deserialize(deserializer)?;
        let private = SecretKey::from_bytes(&serializable.private).map_err(DeError::custom)?;
        let expanded_private_key = ExpandedSecretKey::from_bytes(&serializable.expanded_private_key).map_err(DeError::custom)?;
        let public = PublicKey::from_bytes(&serializable.public).map_err(DeError::custom)?;
        let keypair = NodeKeypair {
            private,
            expanded_private_key,
            public,
        };
        Ok(keypair)
    }
}