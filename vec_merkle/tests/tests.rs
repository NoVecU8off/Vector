#[cfg(test)]
mod tests {
    use vec_merkle::merkle::*;

    #[test]
    fn test_compute_hash() {
        let data = b"Hello, world!";
        let hash = compute_hash(data);
        assert_eq!(hash.len(), 32); // SHA3-256 produces a 32-byte hash
    }

    #[test]
    fn test_tree_creation() {
        let data_list = vec![
            b"Transaction 1".to_vec(),
            b"Transaction 2".to_vec(),
            b"Transaction 3".to_vec(),
            b"Transaction 4".to_vec(),
        ];

        let tree = MerkleTree::from_list(&data_list);

        // The root hash should not be empty
        assert_ne!(tree.get_hash(), compute_hash(&[]));
    }

    #[test]
    fn test_proof_and_verification() {
        let data_list = vec![
            b"Transaction 1".to_vec(),
            b"Transaction 2".to_vec(),
            b"Transaction 3".to_vec(),
            b"Transaction 4".to_vec(),
        ];

        let tree = MerkleTree::from_list(&data_list);

        // Let's get a proof for "Transaction 1"
        let data = b"Transaction 1";
        let proof = tree.get_proof(data).expect("Proof generation failed");

        // Verify the proof
        let is_valid = tree.verify(data, &proof);
        assert_eq!(is_valid, true);

        // Let's test a proof for non-existing data
        let data = b"Non-existing transaction";
        let proof = tree.get_proof(data);
        assert_eq!(proof.is_none(), true);
    }
}