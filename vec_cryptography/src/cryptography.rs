use bs58;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    constants, ristretto::CompressedRistretto, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use rand::prelude::SliceRandom;
use sha3::{Digest, Keccak256};
use vec_proto::messages::{TransactionInput, TransactionOutput};
use vec_storage::output_db::{self, OutputStorer};

#[derive(Debug, Clone)]
pub struct Wallet {
    pub secret_spend_key: Scalar,
    pub secret_view_key: Scalar,
    pub public_spend_key: CompressedRistretto,
    pub public_view_key: CompressedRistretto,
    pub address: String,
}

#[derive(Clone)]
pub struct BLSAGSignature {
    pub i: CompressedRistretto,
    pub c: Scalar,
    pub s: Vec<Scalar>,
}

impl Wallet {
    // Constructs new Wallet
    pub fn generate() -> Wallet {
        let mut rng = rand::thread_rng();
        let secret_spend_key: Scalar = Scalar::random(&mut rng);
        let mut hasher = Keccak256::new();
        hasher.update(secret_spend_key.as_bytes());
        let hashed_key = hasher.finalize();
        let secret_view_key = Scalar::from_bytes_mod_order(hashed_key.into());
        let public_spend_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_view_key;
        let data = [
            public_spend_key.compress().to_bytes().as_slice(),
            public_view_key.compress().to_bytes().as_slice(),
        ]
        .concat();
        let address = bs58::encode(&data).into_string();

        Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key: public_spend_key.compress(),
            public_view_key: public_view_key.compress(),
            address,
        }
    }

    // Recover the keys using secret spend key
    pub fn reconstruct(secret_spend_key: Scalar) -> Wallet {
        let mut hasher = Keccak256::new();
        hasher.update(secret_spend_key.as_bytes());
        let hashed_key = hasher.finalize();
        let secret_view_key = Scalar::from_bytes_mod_order(hashed_key.into());
        let public_spend_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_view_key;
        let data = [
            public_spend_key.compress().to_bytes().as_slice(),
            public_view_key.compress().to_bytes().as_slice(),
        ]
        .concat();
        let address = bs58::encode(&data).into_string();

        Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key: public_spend_key.compress(),
            public_view_key: public_view_key.compress(),
            address,
        }
    }

    // Ordinary ECSDA signing function
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut rng = rand::thread_rng();
        let nonce = Scalar::random(&mut rng);
        let r_ep = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let r = r_ep.compress();
        let mut hasher = Keccak256::new();
        hasher.update(r_ep.compress().as_bytes());
        hasher.update(self.public_spend_key.as_bytes());
        hasher.update(message);
        let h = hasher.finalize();
        let h_scalar = Scalar::from_bits(h.into());
        let s = nonce - h_scalar * self.secret_spend_key;

        Signature { r, s }
    }

    // Collects outputs from OutputDB and constructs Inputs for transaction
    pub async fn prepare_inputs(&self) -> (Vec<TransactionInput>, u64) {
        let owned_db = sled::open("C:/Vector/outputs").expect("failed to open database");
        let output_db = output_db::OutputDB::new(owned_db);
        let output_set = output_db.get().await.unwrap();
        let mut total_input_amount = 0;
        let mut inputs = Vec::new();
        for owned_output in &output_set {
            let decrypted_amount = owned_output.decrypted_amount as u64;
            total_input_amount += decrypted_amount;
            let owned_stealth_addr = &owned_output.output.stealth;
            let ristretto_stealth = Wallet::public_spend_key_from_vec(&owned_stealth_addr).unwrap();
            let wallets: Vec<Wallet> = (0..9).map(|_| Wallet::generate()).collect();
            let mut s_addrs: Vec<CompressedRistretto> =
                wallets.iter().map(|w| w.public_spend_key).collect();
            s_addrs.push(ristretto_stealth);
            s_addrs.shuffle(&mut rand::thread_rng());
            let s_addrs_vec: Vec<Vec<u8>> =
                s_addrs.iter().map(|key| key.to_bytes().to_vec()).collect();
            let m = b"Message example";
            let blsag = self.gen_blsag(&s_addrs, m, &ristretto_stealth);
            let image = blsag.i;
            let input = TransactionInput {
                msg_ring: s_addrs_vec,
                msg_blsag: blsag.to_vec(),
                msg_message: m.to_vec(),
                msg_key_image: image.to_bytes().to_vec(),
            };
            inputs.push(input);
        }

        (inputs, total_input_amount)
    }

    // Constructs Outputs for the transaction by given Recipient address, output index and amount
    pub fn prepare_output(
        &self,
        recipient_address: &str,
        output_index: u64,
        amount: u64,
    ) -> TransactionOutput {
        let (recipient_spend_key, recipient_view_key) =
            derive_keys_from_address(recipient_address).unwrap();
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let recipient_view_key_point = recipient_view_key.decompress().unwrap();
        let q = r * recipient_view_key_point;
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&q_bytes);
        hasher.update(&output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let recipient_spend_key_point = recipient_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + recipient_spend_key_point).compress();
        let encrypted_amount = self.encrypt_amount(&q_bytes, output_index, amount);
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

        TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: proof.to_bytes().to_vec(),
            msg_commitment: commitment.to_bytes().to_vec(),
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        }
    }

    // Constructs change output in case the sum of inputs exceeds the amount we want to spend
    pub fn prepare_change_output(&self, change: u64, output_index: u64) -> TransactionOutput {
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let view_key_point = &self.public_view_key.decompress().unwrap();
        let q = r * view_key_point;
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&q_bytes);
        hasher.update(&output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let spend_key_point = &self.public_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + spend_key_point).compress();
        let encrypted_amount = self.encrypt_amount(&q_bytes, output_index, change);
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

        TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: proof.to_bytes().to_vec(),
            msg_commitment: commitment.to_bytes().to_vec(),
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        }
    }

    // Used to scan the output to check if the output belongs to the user
    pub fn check_property(
        &self,
        output_key: CompressedRistretto,
        output_index: u64,
        stealth: CompressedRistretto,
    ) -> bool {
        let q = self.secret_view_key * output_key.decompress().unwrap();
        let q_bytes = q.compress().as_bytes().to_vec();
        let mut hasher = Keccak256::new();
        hasher.update(&q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_scalar;
        let result = stealth.decompress().unwrap() - hs_g;

        result.compress() == self.public_spend_key
    }

    // Standard transaction amount encryption using Shamir's Secret Sharing
    pub fn encrypt_amount(&self, q_bytes: &[u8], output_index: u64, amount: u64) -> [u8; 8] {
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash_qi = hasher.finalize();
        let mut hasher = Keccak256::new();
        hasher.update(b"amount");
        hasher.update(hash_qi);
        let hash = hasher.finalize();
        let hash_8: [u8; 8] = hash[0..8].try_into().unwrap();
        let amount_in_scalars = Scalar::from(amount).to_bytes();
        let amount_in_scalars_8 = amount_in_scalars[0..8].try_into().unwrap();
        let encrypted_amount = xor8(amount_in_scalars_8, hash_8);

        encrypted_amount
    }

    pub fn decrypt_amount(
        &self,
        output_key: CompressedRistretto,
        output_index: u64,
        encrypted_amount: &[u8],
    ) -> u64 {
        let q = self.secret_view_key * output_key.decompress().unwrap();
        let q_bytes = q.compress().as_bytes().to_vec();
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash_qi = hasher.finalize();
        let mut hasher = Keccak256::new();
        hasher.update(b"amount");
        hasher.update(hash_qi);
        let hash = hasher.finalize();
        let hash_8: [u8; 8] = hash[0..8].try_into().unwrap();
        let decrypted_amount = xor8(encrypted_amount.try_into().unwrap(), hash_8);
        let value = u64::from_le_bytes(decrypted_amount);

        value
    }

    // Complete Back’s Linkable Spontaneous Anonymous Group signature
    pub fn gen_blsag(
        &self,
        p: &[CompressedRistretto],
        m: &[u8],
        stealth: &CompressedRistretto,
    ) -> BLSAGSignature {
        let a = Scalar::random(&mut rand::thread_rng());
        let n = p.len();
        let mut c: Vec<Scalar> = vec![Scalar::zero(); n];
        let mut s: Vec<Scalar> = vec![Scalar::zero(); n];
        let mut l: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
        let mut r: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
        let mut j = 0;
        for (i, rk) in p.iter().enumerate() {
            if stealth == rk {
                j = i;
                break;
            }
        }
        let image = (self.secret_spend_key * hash_to_point(&p[j])).compress();
        for i in 0..n {
            if i == j {
                continue;
            }
            s[i] = Scalar::random(&mut rand::thread_rng());
        }
        let j1 = (j + 1) % n;
        l[j] = a * &constants::RISTRETTO_BASEPOINT_POINT;
        r[j] = a * hash_to_point(&p[j]);
        let mut hasher = Keccak256::new();
        hasher.update(m);
        hasher.update(l[j].compress().to_bytes());
        hasher.update(r[j].compress().to_bytes());
        let hash = hasher.finalize();
        c[(j + 1) % n] = Scalar::from_bytes_mod_order(hash.into());
        for k in 0..(n - 1) {
            let i = (j1 + k) % n;
            let ip1 = (j1 + k + 1) % n;
            l[i] = s[i] * &constants::RISTRETTO_BASEPOINT_POINT + c[i] * p[i].decompress().unwrap();
            r[i] = s[i] * hash_to_point(&p[i]) + c[i] * image.decompress().unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(m);
            hasher.update(l[i].compress().to_bytes());
            hasher.update(r[i].compress().to_bytes());
            let hash = hasher.finalize();
            c[ip1] = Scalar::from_bytes_mod_order(hash.into());
        }
        s[j] = a - c[j] * self.secret_spend_key;

        BLSAGSignature {
            i: image,
            c: c[0],
            s,
        }
    }
}

impl Wallet {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.secret_spend_key.as_bytes());
        v.extend_from_slice(self.secret_view_key.as_bytes());
        v.extend_from_slice(self.public_spend_key.as_bytes());
        v.extend_from_slice(self.public_view_key.as_bytes());
        v.extend_from_slice(self.address.as_bytes());

        v
    }

    pub fn from_vec(v: &[u8]) -> Option<Wallet> {
        if v.len() < 160 {
            return None;
        }
        let secret_spend_key = Scalar::from_canonical_bytes(v[0..32].try_into().unwrap()).unwrap();
        let secret_view_key = Scalar::from_canonical_bytes(v[32..64].try_into().unwrap()).unwrap();
        let public_spend_key = CompressedRistretto::from_slice(&v[64..96]);
        let public_view_key = CompressedRistretto::from_slice(&v[96..128]);
        let address = String::from_utf8(v[128..].to_vec()).unwrap();

        Some(Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key,
            public_view_key,
            address,
        })
    }

    pub fn secret_spend_key_to_vec(&self) -> Vec<u8> {
        self.secret_spend_key.as_bytes().to_vec()
    }

    pub fn secret_spend_key_from_vec(v: &[u8]) -> Option<Scalar> {
        Scalar::from_canonical_bytes(v.try_into().unwrap())
    }

    pub fn secret_view_key_to_vec(&self) -> Vec<u8> {
        self.secret_view_key.as_bytes().to_vec()
    }

    pub fn secret_view_key_from_vec(v: &[u8]) -> Option<Scalar> {
        Scalar::from_canonical_bytes(v.try_into().unwrap())
    }

    pub fn public_spend_key_to_vec(&self) -> Vec<u8> {
        self.public_spend_key.as_bytes().to_vec()
    }

    pub fn public_spend_key_from_vec(v: &[u8]) -> Option<CompressedRistretto> {
        Some(CompressedRistretto::from_slice(v))
    }

    pub fn public_view_key_to_vec(&self) -> Vec<u8> {
        self.public_view_key.as_bytes().to_vec()
    }

    pub fn public_view_key_from_vec(v: &[u8]) -> Option<CompressedRistretto> {
        Some(CompressedRistretto::from_slice(v))
    }

    pub fn address_to_vec(&self) -> Vec<u8> {
        self.address.as_bytes().to_vec()
    }

    pub fn address_from_vec(v: &[u8]) -> Option<String> {
        String::from_utf8(v.to_vec()).ok()
    }
}

pub struct SerializableWallet {
    secret_spend_key: [u8; 32],
    secret_view_key: [u8; 32],
    public_spend_key: [u8; 32],
    public_view_key: [u8; 32],
    address: Vec<u8>,
}

impl Wallet {
    pub fn to_serializable(&self) -> SerializableWallet {
        SerializableWallet {
            secret_spend_key: self.secret_spend_key.to_bytes(),
            secret_view_key: self.secret_view_key.to_bytes(),
            public_spend_key: self.public_spend_key.to_bytes(),
            public_view_key: self.public_view_key.to_bytes(),
            address: self.address.as_bytes().to_vec(),
        }
    }

    pub fn from_serializable(s: &SerializableWallet) -> Wallet {
        Wallet {
            secret_spend_key: Scalar::from_bytes_mod_order(s.secret_spend_key.into()),
            secret_view_key: Scalar::from_bytes_mod_order(s.secret_view_key),
            public_spend_key: CompressedRistretto::from_slice(&s.public_spend_key),
            public_view_key: CompressedRistretto::from_slice(&s.public_view_key),
            address: String::from_utf8(s.address.clone()).unwrap(),
        }
    }
}

impl BLSAGSignature {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.i.as_bytes());
        v.extend_from_slice(self.c.as_bytes());
        v.extend_from_slice(&(self.s.len() as u64).to_le_bytes());
        for scalar in &self.s {
            v.extend_from_slice(scalar.as_bytes());
        }

        v
    }

    pub fn from_vec(v: &[u8]) -> Option<BLSAGSignature> {
        if v.len() < 72 {
            return None;
        }
        let i = CompressedRistretto::from_slice(&v[0..32]);
        let c = Scalar::from_canonical_bytes(v[32..64].try_into().unwrap()).unwrap();
        let s_len = u64::from_le_bytes(v[64..72].try_into().unwrap()) as usize;
        let mut s = Vec::new();
        for n in 0..s_len {
            let start = 72 + n * 32;
            let end = start + 32;
            s.push(Scalar::from_canonical_bytes(v[start..end].try_into().unwrap()).unwrap());
        }

        Some(BLSAGSignature { i, c, s })
    }
}

pub fn verify(
    public_spend_key: &CompressedRistretto,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let r = signature.r.decompress().unwrap();
    let public_spend_key_point = public_spend_key;
    let mut hasher = Keccak256::new();
    hasher.update(signature.r.to_bytes());
    hasher.update(public_spend_key.to_bytes());
    hasher.update(message);
    let h = hasher.finalize();
    let h_scalar = Scalar::from_bits(h.into());
    let r_prime = &constants::RISTRETTO_BASEPOINT_TABLE * &signature.s
        + public_spend_key_point.decompress().unwrap() * &h_scalar;

    r == r_prime
}

pub fn derive_keys_from_address(
    address: &str,
) -> Result<(CompressedRistretto, CompressedRistretto), bs58::decode::Error> {
    let data = bs58::decode(address).into_vec()?;
    let (public_spend_key_data, public_view_key_data) = data.split_at(32);
    let public_spend_key = CompressedRistretto::from_slice(public_spend_key_data);
    let public_view_key = CompressedRistretto::from_slice(public_view_key_data);

    Ok((public_spend_key, public_view_key))
}

#[derive(Clone, Copy)]
pub struct Signature {
    r: CompressedRistretto,
    s: Scalar,
}

impl Signature {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.r.as_bytes());
        v.extend_from_slice(self.s.as_bytes());

        v
    }

    pub fn from_vec(v: &[u8]) -> Option<Signature> {
        if v.len() != 64 {
            return None;
        }
        let r = CompressedRistretto::from_slice(&v[0..32]);
        let s = Scalar::from_canonical_bytes(v[32..64].try_into().unwrap());
        match s {
            Some(scalar) => Some(Signature { r, s: scalar }),
            None => None,
        }
    }
}

pub fn hash_to_point(point: &CompressedRistretto) -> RistrettoPoint {
    let mut hasher = Keccak256::new();
    hasher.update(point.to_bytes());
    let hash = hasher.finalize();
    let scalar = Scalar::from_bytes_mod_order(hash.into());

    &constants::RISTRETTO_BASEPOINT_TABLE * &scalar
}

pub fn xor8(a: [u8; 8], b: [u8; 8]) -> [u8; 8] {
    let mut c = [0u8; 8];
    for i in 0..8 {
        c[i] = a[i] ^ b[i];
    }

    c
}

pub fn vec_to_string(v: &Vec<u8>) -> String {
    bs58::encode(&v).into_string()
}

pub fn string_to_vec(string: &str) -> Vec<u8> {
    bs58::decode(string).into_vec().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate();
        assert_ne!(wallet.secret_spend_key, Scalar::zero());
        assert_ne!(wallet.secret_view_key, Scalar::zero());
        assert_ne!(*wallet.public_spend_key.as_bytes(), [0; 32]);
        assert_ne!(*wallet.public_view_key.as_bytes(), [0; 32]);
        assert_eq!(
            wallet.public_spend_key.decompress().unwrap(),
            (&constants::RISTRETTO_BASEPOINT_TABLE * &wallet.secret_spend_key)
        );
        assert_eq!(
            wallet.public_view_key.decompress().unwrap(),
            (&constants::RISTRETTO_BASEPOINT_TABLE * &wallet.secret_view_key)
        );
        let decoded_address = bs58::decode(&wallet.address).into_vec().unwrap();
        assert_eq!(
            decoded_address[0..32],
            wallet.public_spend_key.as_bytes()[..]
        );
        assert_eq!(
            decoded_address[32..64],
            wallet.public_view_key.as_bytes()[..]
        );
    }

    #[test]
    fn test_reconstruct_wallet() {
        let original_wallet = Wallet::generate();
        let reconstructed_wallet = Wallet::reconstruct(original_wallet.secret_spend_key);

        assert_eq!(
            original_wallet.secret_spend_key,
            reconstructed_wallet.secret_spend_key
        );
        assert_eq!(
            original_wallet.secret_view_key,
            reconstructed_wallet.secret_view_key
        );
        assert_eq!(
            original_wallet.public_spend_key,
            reconstructed_wallet.public_spend_key
        );
        assert_eq!(
            original_wallet.public_view_key,
            reconstructed_wallet.public_view_key
        );
        assert_eq!(original_wallet.address, reconstructed_wallet.address);
    }

    #[test]
    fn test_wallet_signature() {
        let wallet = Wallet::generate();
        let message = b"Hello, World!";
        let signature = wallet.sign(message);
        assert!(verify(&wallet.public_spend_key, message, &signature));
        let different_message = b"Goodbye, World!";
        assert!(!verify(
            &wallet.public_spend_key,
            different_message,
            &signature
        ));
        let different_wallet = Wallet::generate();
        assert!(!verify(
            &different_wallet.public_spend_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_wallet_reconstruction() {
        let wallet = Wallet::generate();
        let reconstructed_wallet = Wallet::reconstruct(wallet.secret_spend_key);
        assert_eq!(
            wallet.secret_spend_key,
            reconstructed_wallet.secret_spend_key
        );
        assert_eq!(wallet.secret_view_key, reconstructed_wallet.secret_view_key);
        assert_eq!(
            *wallet.public_spend_key.as_bytes(),
            *reconstructed_wallet.public_spend_key.as_bytes()
        );
        assert_eq!(
            *wallet.public_view_key.as_bytes(),
            *reconstructed_wallet.public_view_key.as_bytes()
        );
        assert_eq!(wallet.address, reconstructed_wallet.address);
    }

    #[test]
    fn test_encrypt_decrypt_amount() {
        let output_index: u64 = 1;
        let amount: u64 = 5000;

        let my_wallet = Wallet::generate();
        let re_wallet = Wallet::generate();
        let r = Scalar::random(&mut rand::thread_rng());
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let q = &r * &re_wallet.public_view_key.decompress().unwrap();
        let q_bytes = q.compress().to_bytes();
        let encrypted_amount = my_wallet.encrypt_amount(&q_bytes, output_index, amount);
        let decrypted_amount =
            re_wallet.decrypt_amount(output_key, output_index, &encrypted_amount);
        assert_eq!(
            decrypted_amount, amount,
            "Decrypted amount does not match the original amount"
        );
    }
}
