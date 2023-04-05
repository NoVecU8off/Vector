use sha3::{Digest, Sha3_512};
use sn_proto::messages::{Transaction};
use prost::Message;

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: Vec<u8>,
    pub depth: u64,
    pub leaves: Vec<TransactionWrapper>,
    pub nodes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TransactionWrapper {
    pub transaction: Transaction,
    pub hash: Vec<u8>,
}

impl MerkleTree {
    pub fn new(transactions: &[Transaction]) -> MerkleTree {
        let leaves: Vec<TransactionWrapper> = compute_hashes(transactions);
    
        let mut nodes = leaves.iter().map(|wrapper| wrapper.hash.clone()).collect::<Vec<_>>();
    
        let (root, depth) = MerkleTree::build(&mut nodes);
    
        MerkleTree {
            root,
            depth,
            leaves,
            nodes,
        }
    }

    pub fn build(nodes: &[Vec<u8>]) -> (Vec<u8>, u64) {
        if nodes.is_empty() {
            return (Vec::new(), 0);
        }
    
        let mut level = nodes.to_vec();
        let mut next_level = Vec::new();
        let mut depth = 0;
    
        while level.len() > 1 {
            if level.len() % 2 != 0 {
                level.push(level.last().unwrap().clone());
            }
    
            for i in (0..level.len()).step_by(2) {
                let mut hasher = Sha3_512::new();
    
                hasher.update(&level[i]);
                hasher.update(&level[i + 1]);
    
                let hash = hasher.finalize().to_vec();
                next_level.push(hash);
            }
    
            level = next_level.drain(..).collect();
            depth += 1;
        }
    
        (level[0].clone(), depth)
    }
    
    pub fn verify(&self, leaf: &Transaction, index: usize, proof: &[Vec<u8>]) -> bool {
        let mut hasher = Sha3_512::new();
        let mut bytes = Vec::new();
        leaf.encode(&mut bytes).unwrap();
        hasher.update(&bytes);
        let mut current_hash = hasher.finalize().to_vec();
        let mut current_index = index;
    
        // Check if the proof is empty, and if so, compare the leaf hash with the root directly
        if proof.is_empty() {
            return current_hash == self.root;
        }
    
        println!("Initial hash: {:?}", current_hash);
    
        for sibling in proof {
            let mut new_hasher = Sha3_512::new();
    
            if current_index % 2 == 0 {
                new_hasher.update(&current_hash);
                new_hasher.update(sibling);
            } else {
                new_hasher.update(sibling);
                new_hasher.update(&current_hash);
            }
    
            current_hash = new_hasher.finalize().to_vec();
            current_index /= 2;
    
            println!("Updated hash: {:?}", current_hash);
        }
    
        current_hash == self.root
    }

    pub fn get_proof(&self, transaction: &Transaction) -> Option<(usize, Vec<Vec<u8>>)> {
        let leaf_index = self.leaves.iter().position(|wrapper| &wrapper.transaction == transaction)?;
    
        let mut proof = Vec::new();
        let mut index = leaf_index;
    
        let max_depth = self.depth as isize;
        for _i in (0..max_depth).rev() {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
    
            if sibling_index >= self.leaves.len() {
                break;
            }
    
            proof.push(self.leaves[sibling_index].hash.clone());
    
            // Print the current index, sibling index, current node hash, sibling node hash, and current proof
            println!("Current index: {}", index);
            println!("Sibling index: {}", sibling_index);
            println!("Current node hash: {:?}", self.leaves[index].hash);
            println!("Sibling node hash: {:?}", self.leaves[sibling_index].hash);
            println!("Current proof: {:?}", proof);
    
            index /= 2;
        }
    
        Some((leaf_index, proof))
    }

    pub fn add_leaf(&mut self, transaction: Transaction) {
        if self.leaves.len() == 1 {
            let new_transactions = vec![self.leaves[0].transaction.clone(), transaction];
            *self = MerkleTree::new(&new_transactions);
            self.depth = 1; // Update the depth after reconstructing the tree
            return;
        }

        let wrapper = compute_hashes(&[transaction.clone()]).into_iter().next().unwrap();
        self.leaves.push(wrapper.clone());
        self.nodes.push(wrapper.hash.clone());
    
        let mut index = self.leaves.len() - 1;
        let mut current_hash = wrapper.hash;
    
        while index > 0 {
            let sibling_index = if index % 2 == 0 { index - 1 } else { index + 1 };
            let parent_index = (index - 1) / 2;
    
            if sibling_index >= self.nodes.len() {
                break;
            }
    
            let mut hasher = Sha3_512::new();
            if index % 2 == 0 {
                hasher.update(&self.nodes[sibling_index]);
                hasher.update(&current_hash);
            } else {
                hasher.update(&current_hash);
                hasher.update(&self.nodes[sibling_index]);
            }
    
            current_hash = hasher.finalize().to_vec();
            self.nodes[parent_index] = current_hash.clone();
            index = parent_index;
        }
    
        self.root = current_hash;
    }

    pub fn remove_leaf(&mut self, transaction: &Transaction) -> bool {
        if let Some(index) = self.leaves.iter().position(|wrapper| &wrapper.transaction == transaction) {
            self.leaves.remove(index);
            self.nodes.remove(index);

            let mut current_hash = vec![0u8; 64]; // Placeholder hash for the removed leaf
            let mut parent_index = index;

            while parent_index > 0 {
                let sibling_index = if parent_index % 2 == 0 { parent_index - 1 } else { parent_index + 1 };
                parent_index = (parent_index - 1) / 2;

                let mut hasher = Sha3_512::new();
                if parent_index % 2 == 0 {
                    hasher.update(&self.nodes[sibling_index]);
                    hasher.update(&current_hash);
                } else {
                    hasher.update(&current_hash);
                    hasher.update(&self.nodes[sibling_index]);
                }

                current_hash = hasher.finalize().to_vec();
                self.nodes[parent_index] = current_hash.clone();
            }

            self.root = current_hash;
            true
        } else {
            false
        }
    }

    pub fn get_root(&self) -> &[u8] {
        &self.root
    }

    pub fn get_leaves(&self) -> Vec<TransactionWrapper> {
        self.leaves.clone()
    }

    pub fn get_nodes(&self) -> Vec<Vec<u8>> {
        self.nodes.clone()
    }

    pub fn get_depth(&self) -> u64 {
        self.depth
    }

    pub fn get_node(&self, index: usize) -> Option<&[u8]> {
        self.nodes.get(index).map(|node| &node[..])
    }
}

pub fn compute_hashes(transactions: &[Transaction]) -> Vec<TransactionWrapper> {
    transactions
        .iter()
        .map(|transaction| {
            let mut bytes = Vec::new();
            transaction.encode(&mut bytes).unwrap();
            let mut hasher = Sha3_512::new();
            hasher.update(&bytes);
            let hash = hasher.finalize().to_vec();
            TransactionWrapper {
                transaction: transaction.clone(),
                hash,
            }
        })
        .collect()
}