use sha3::{Sha3_256, Digest};

#[derive(Clone, Debug)]
pub enum MerkleTree {
    Empty,
    Leaf { hash: Vec<u8>, data: Vec<u8> },
    Node { hash: Vec<u8>, left: Box<MerkleTree>, right: Box<MerkleTree> },
}

impl MerkleTree {
    pub fn from_list(data_list: &[Vec<u8>]) -> MerkleTree {
        match data_list.len() {
            0 => MerkleTree::Empty,
            1 => {
                let data = data_list[0].clone();
                let hash = compute_hash(&data);
                MerkleTree::Leaf { hash, data }
            }
            _ => {
                let middle = data_list.len() / 2;
                let left_tree = MerkleTree::from_list(&data_list[..middle]);
                let right_tree = MerkleTree::from_list(&data_list[middle..]);
                let combined_hash = combine_hash(
                    &left_tree.get_hash(),
                    &right_tree.get_hash()
                );
                MerkleTree::Node { 
                    hash: combined_hash,
                    left: Box::new(left_tree),
                    right: Box::new(right_tree)
                }
            }
        }
    }

    pub fn get_hash(&self) -> Vec<u8> {
        match self {
            MerkleTree::Empty => compute_hash(&[]),
            MerkleTree::Leaf { hash, .. } => hash.clone(),
            MerkleTree::Node { hash, .. } => hash.clone(),
        }
    }

    pub fn get_proof(&self, data: &[u8]) -> Option<Vec<(Vec<u8>, bool)>> {
        match self {
            MerkleTree::Empty => None,
            MerkleTree::Leaf { data: leaf_data, .. } => {
                if data == leaf_data {
                    Some(vec![])
                } else {
                    None
                }
            },
            MerkleTree::Node { left, right, .. } => {
                if let Some(mut proof) = left.get_proof(data) {
                    proof.push((right.get_hash(), true));
                    Some(proof)
                } else if let Some(mut proof) = right.get_proof(data) {
                    proof.push((left.get_hash(), false));
                    Some(proof)
                } else {
                    None
                }
            }
        }
    }

    pub fn verify(&self, data: &[u8], proof: &[(Vec<u8>, bool)]) -> bool {
        let mut current_hash = compute_hash(data);
        for (proof_hash, is_right_sibling) in proof {
            current_hash = if *is_right_sibling {
                combine_hash(&current_hash, proof_hash)
            } else {
                combine_hash(proof_hash, &current_hash)
            };
        }
        current_hash == self.get_hash()
    }
}

pub fn compute_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn combine_hash(hash1: &[u8], hash2: &[u8]) -> Vec<u8> {
    compute_hash(&[hash1, hash2].concat())
}
