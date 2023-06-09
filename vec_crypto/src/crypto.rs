use bs58;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    constants, ristretto::CompressedRistretto, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use rand::seq::SliceRandom;
use sha3::{Digest, Keccak256};
use vec_errors::errors::*;
use vec_macros::hash;
use vec_proto::messages::{Transaction, TransactionInput, TransactionOutput};
use vec_storage::{
    lazy_traits::OUTPUT_STORER,
    output_db::{Output, OutputStorer, OwnedOutput},
};

pub type SSK = Scalar;
pub type SVK = Scalar;
pub type PSK = CompressedRistretto;
pub type PVK = CompressedRistretto;
pub type ADS = [u8; 64];

#[derive(Debug, Clone)]
pub struct Wallet {
    pub secret_spend_key: SSK,
    pub secret_view_key: SVK,
    pub public_spend_key: PSK,
    pub public_view_key: PVK,
    pub address: ADS,
}

#[derive(Clone)]
pub struct BLSAGSignature {
    pub i: CompressedRistretto,
    pub c: Scalar,
    pub s: Vec<Scalar>,
}

impl Wallet {
    // Constructs new Wallet
    pub fn generate() -> Result<Wallet, CryptoOpsError> {
        let mut rng = rand::thread_rng();
        let secret_spend_key: Scalar = Scalar::random(&mut rng);
        let hashed_key = hash!(secret_spend_key.as_bytes());
        let secret_view_key = Scalar::from_bytes_mod_order(hashed_key.into());
        let public_spend_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_spend_key;
        let public_view_key = &constants::RISTRETTO_BASEPOINT_TABLE * &secret_view_key;
        let data = [
            public_spend_key.compress().to_bytes().as_slice(),
            public_view_key.compress().to_bytes().as_slice(),
        ]
        .concat();
        let address = data.as_slice().try_into().unwrap();

        Ok(Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key: public_spend_key.compress(),
            public_view_key: public_view_key.compress(),
            address,
        })
    }

    // Recover the keys using secret spend key
    pub fn reconstruct(secret_spend_key: Scalar) -> Result<Wallet, CryptoOpsError> {
        let hashed_key = hash!(secret_spend_key.as_bytes());
        let secret_view_key = Scalar::from_bytes_mod_order(hashed_key.into());
        let public_spend_key =
            (&constants::RISTRETTO_BASEPOINT_TABLE * &secret_spend_key).compress();
        let public_view_key = (&constants::RISTRETTO_BASEPOINT_TABLE * &secret_view_key).compress();
        let data = [
            public_spend_key.to_bytes().as_slice(),
            public_view_key.to_bytes().as_slice(),
        ]
        .concat();
        let address = data.as_slice().try_into().unwrap();

        Ok(Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key,
            public_view_key,
            address,
        })
    }

    // Ordinary ECSDA signing function
    pub fn sign(&self, message: &[u8]) -> Result<Signature, CryptoOpsError> {
        let mut rng = rand::thread_rng();
        let nonce = Scalar::random(&mut rng);
        let r_ep = &constants::RISTRETTO_BASEPOINT_TABLE * &nonce;
        let r = r_ep.compress();
        let h = hash!(
            r_ep.compress().as_bytes(),
            self.public_spend_key.as_bytes(),
            message
        );
        let h_scalar = Scalar::from_bits(h.into());
        let s = nonce - h_scalar * self.secret_spend_key;

        Ok(Signature { r, s })
    }

    pub fn check_property(
        &self,
        output_key: CompressedRistretto,
        output_index: u32,
        stealth: CompressedRistretto,
    ) -> Result<bool, CryptoOpsError> {
        let decompressed_output = output_key
            .decompress()
            .ok_or(CryptoOpsError::DecompressionFailed)?;
        let q = self.secret_view_key * decompressed_output;
        let q_bytes = q.compress().as_bytes().to_vec();
        let hash = hash!(&q_bytes, output_index.to_le_bytes());
        let hash_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_scalar;
        let decompressed_stealth = stealth
            .decompress()
            .ok_or(CryptoOpsError::DecompressionFailed)?;
        let result = decompressed_stealth - hs_g;

        Ok(result.compress() == self.public_spend_key)
    }

    pub async fn process_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<(), ChainOpsError> {
        for output in &transaction.msg_outputs {
            let index = output.msg_index;
            let key = CompressedRistretto::from_slice(&output.msg_output_key);
            let stealth = CompressedRistretto::from_slice(&output.msg_stealth_address);

            if self.check_property(key, index, stealth)? {
                let decrypted_amount = self.decrypt_amount(key, index, &output.msg_amount)?;
                let owned_output = OwnedOutput {
                    output: Output {
                        stealth: output.msg_stealth_address.clone(),
                        output_key: output.msg_output_key.clone(),
                        amount: output.msg_amount.clone(),
                        commitment: output.msg_commitment.clone(),
                        range_proof: output.msg_proof.clone(),
                    },
                    decrypted_amount,
                };
                OUTPUT_STORER.put(&owned_output).await?;
            }
        }
        Ok(())
    }

    // Collects outputs from OutputDB and constructs Inputs for transaction
    pub async fn prepare_inputs(&self) -> Result<(Vec<TransactionInput>, u64), ChainOpsError> {
        let output_set = OUTPUT_STORER.get().await.unwrap();
        let mut total_input_amount = 0;
        let mut inputs = Vec::new();
        for owned_output in &output_set {
            let decrypted_amount = owned_output.decrypted_amount;
            total_input_amount += decrypted_amount;
            let owned_stealth_addr = &owned_output.output.stealth;
            let compressed_stealth = CompressedRistretto::from_slice(owned_stealth_addr);
            let wallets_res: Result<Vec<Wallet>, _> = (0..9).map(|_| Wallet::generate()).collect();
            let wallets = wallets_res?;
            let mut s_addrs: Vec<CompressedRistretto> =
                wallets.iter().map(|w| w.public_spend_key).collect();
            s_addrs.push(compressed_stealth);
            s_addrs.shuffle(&mut rand::thread_rng());
            let s_addrs_vec: Vec<Vec<u8>> =
                s_addrs.iter().map(|key| key.to_bytes().to_vec()).collect();
            let m = b"Message example";
            let blsag = self.gen_blsag(&s_addrs, m, &compressed_stealth)?;
            let image = blsag.i;
            let input = TransactionInput {
                msg_ring: s_addrs_vec,
                msg_blsag: blsag.to_vec(),
                msg_message: m.to_vec(),
                msg_key_image: image.to_bytes().to_vec(),
            };
            inputs.push(input);
        }

        Ok((inputs, total_input_amount))
    }

    // Constructs Outputs for the transaction by given Recipient address, output index and amount
    pub fn prepare_output(
        &self,
        recipient_address: &str,
        output_index: u32,
        amount: u64,
    ) -> Result<TransactionOutput, ChainOpsError> {
        let (recipient_spend_key, recipient_view_key) =
            derive_keys_from_address(recipient_address).unwrap();
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let recipient_view_key_point = recipient_view_key.decompress().unwrap();
        let q = r * recipient_view_key_point;
        let q_bytes = q.compress().to_bytes();
        let hash = hash!(q_bytes, output_index.to_le_bytes());
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let recipient_spend_key_point = recipient_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + recipient_spend_key_point).compress();
        let encrypted_amount = self.encrypt_amount(&q_bytes, output_index, amount)?;
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

        Ok(TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: proof.to_bytes().to_vec(),
            msg_commitment: commitment.to_bytes().to_vec(),
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        })
    }

    // Constructs change output in case the sum of inputs exceeds the amount we want to spend
    pub fn prepare_change_output(
        &self,
        change: u64,
        output_index: u32,
    ) -> Result<TransactionOutput, ChainOpsError> {
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let view_key_point = self.public_view_key.decompress().unwrap();
        let q = r * view_key_point;
        let q_bytes = q.compress().to_bytes();
        let hash = hash!(q_bytes, output_index.to_le_bytes());
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let spend_key_point = self.public_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + spend_key_point).compress();
        let encrypted_amount = self.encrypt_amount(&q_bytes, output_index, change)?;
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

        Ok(TransactionOutput {
            msg_stealth_address: stealth.to_bytes().to_vec(),
            msg_output_key: output_key.to_bytes().to_vec(),
            msg_proof: proof.to_bytes().to_vec(),
            msg_commitment: commitment.to_bytes().to_vec(),
            msg_amount: encrypted_amount.to_vec(),
            msg_index: output_index,
        })
    }

    pub fn encrypt_amount(
        &self,
        q_bytes: &[u8],
        output_index: u32,
        amount: u64,
    ) -> Result<[u8; 8], CryptoOpsError> {
        let hash_qi = hash!(q_bytes, output_index.to_le_bytes());
        let hash = hash!(b"amount", hash_qi);
        let hash_8: [u8; 8] = hash[0..8]
            .try_into()
            .map_err(|_| CryptoOpsError::TryIntoError)?;
        let amount_in_scalars = Scalar::from(amount).to_bytes();
        let amount_in_scalars_8 = amount_in_scalars[0..8]
            .try_into()
            .map_err(|_| CryptoOpsError::TryIntoError)?;

        Ok(xor8(amount_in_scalars_8, hash_8))
    }

    pub fn decrypt_amount(
        &self,
        output_key: CompressedRistretto,
        output_index: u32,
        encrypted_amount: &[u8],
    ) -> Result<u64, CryptoOpsError> {
        let decompressed_output = output_key
            .decompress()
            .ok_or(CryptoOpsError::DecompressionFailed)?;
        let q = self.secret_view_key * decompressed_output;
        let q_bytes = q.compress().as_bytes().to_vec();
        let hash_qi = hash!(q_bytes, output_index.to_le_bytes());
        let hash = hash!(b"amount", hash_qi);
        let hash_8: [u8; 8] = hash[0..8]
            .try_into()
            .map_err(|_| CryptoOpsError::TryIntoError)?;
        let encrypted_amount_8 = encrypted_amount
            .try_into()
            .map_err(|_| CryptoOpsError::TryIntoError)?;
        let decrypted_amount = xor8(encrypted_amount_8, hash_8);

        Ok(u64::from_le_bytes(decrypted_amount))
    }

    // Complete Back’s Linkable Spontaneous Anonymous Group signature
    pub fn gen_blsag(
        &self,
        p: &[CompressedRistretto],
        m: &[u8],
        stealth: &CompressedRistretto,
    ) -> Result<BLSAGSignature, CryptoOpsError> {
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
        for (i, item) in s.iter_mut().enumerate().take(n) {
            if i == j {
                continue;
            }
            *item = Scalar::random(&mut rand::thread_rng());
        }
        let j1 = (j + 1) % n;
        l[j] = a * constants::RISTRETTO_BASEPOINT_POINT;
        r[j] = a * hash_to_point(&p[j]);
        let hash = hash!(m, l[j].compress().to_bytes(), r[j].compress().to_bytes());
        c[(j + 1) % n] = Scalar::from_bytes_mod_order(hash.into());
        for k in 0..(n - 1) {
            let i = (j1 + k) % n;
            let ip1 = (j1 + k + 1) % n;
            l[i] = s[i] * constants::RISTRETTO_BASEPOINT_POINT
                + c[i]
                    * p[i]
                        .decompress()
                        .ok_or(CryptoOpsError::DecompressionFailed)?;
            r[i] = s[i] * hash_to_point(&p[i])
                + c[i]
                    * image
                        .decompress()
                        .ok_or(CryptoOpsError::DecompressionFailed)?;
            let hash = hash!(m, l[i].compress().to_bytes(), r[i].compress().to_bytes());
            c[ip1] = Scalar::from_bytes_mod_order(hash.into());
        }
        s[j] = a - c[j] * self.secret_spend_key;

        Ok(BLSAGSignature {
            i: image,
            c: c[0],
            s,
        })
    }
}

pub fn verify_blsag(sig: &BLSAGSignature, p: &[CompressedRistretto], m: &[u8]) -> bool {
    let n = p.len();
    let c1 = sig.c;
    let s = sig.s.clone();
    let image = sig.i;
    let mut l: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
    let mut r: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
    let mut c: Vec<Scalar> = vec![Scalar::zero(); n];
    c[0] = c1;
    for j in 0..n {
        let i = j % n;
        let ip1 = (j + 1) % n;
        l[i] = s[i] * constants::RISTRETTO_BASEPOINT_POINT + c[i] * p[i].decompress().unwrap();
        r[i] = s[i] * hash_to_point(&p[i]) + c[i] * image.decompress().unwrap();
        let hash = hash!(m, l[i].compress().to_bytes(), r[i].compress().to_bytes());
        c[ip1] = Scalar::from_bytes_mod_order(hash.into());
    }

    if c1 == c[0] {
        return true;
    }
    false
}

impl Wallet {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.secret_spend_key.as_bytes());
        v.extend_from_slice(self.secret_view_key.as_bytes());
        v.extend_from_slice(self.public_spend_key.as_bytes());
        v.extend_from_slice(self.public_view_key.as_bytes());
        v.extend(&self.address);

        v
    }

    pub fn from_vec(v: &[u8]) -> Result<Wallet, CryptoOpsError> {
        if v.len() < 160 {
            return Err(CryptoOpsError::InvalidVecLength);
        }

        let secret_spend_key = Scalar::from_canonical_bytes(
            v[0..32]
                .try_into()
                .map_err(|_| CryptoOpsError::TryIntoError)?,
        )
        .ok_or(CryptoOpsError::DecompressionFailed)?;

        let secret_view_key = Scalar::from_canonical_bytes(
            v[32..64]
                .try_into()
                .map_err(|_| CryptoOpsError::TryIntoError)?,
        )
        .ok_or(CryptoOpsError::DecompressionFailed)?;

        let public_spend_key = CompressedRistretto::from_slice(&v[64..96]);
        let public_view_key = CompressedRistretto::from_slice(&v[96..128]);
        let address = v[128..].try_into().unwrap();

        Ok(Wallet {
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

    pub fn secret_spend_key_from_vec(v: &[u8]) -> Result<Scalar, CryptoOpsError> {
        Scalar::from_canonical_bytes(v.try_into().map_err(|_| CryptoOpsError::TryIntoError)?)
            .ok_or(CryptoOpsError::DecompressionFailed)
    }

    pub fn secret_view_key_to_vec(&self) -> Vec<u8> {
        self.secret_view_key.as_bytes().to_vec()
    }

    pub fn secret_view_key_from_vec(v: &[u8]) -> Result<Scalar, CryptoOpsError> {
        Scalar::from_canonical_bytes(v.try_into().map_err(|_| CryptoOpsError::TryIntoError)?)
            .ok_or(CryptoOpsError::DecompressionFailed)
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

    pub fn address_from_vec(v: &[u8]) -> Result<String, CryptoOpsError> {
        Ok(bs58::encode(v).into_string())
    }
}

pub struct SerializableWallet {
    secret_spend_key: [u8; 32],
    secret_view_key: [u8; 32],
    public_spend_key: [u8; 32],
    public_view_key: [u8; 32],
    address: [u8; 64],
}

impl Wallet {
    pub fn to_serializable(&self) -> SerializableWallet {
        SerializableWallet {
            secret_spend_key: self.secret_spend_key.to_bytes(),
            secret_view_key: self.secret_view_key.to_bytes(),
            public_spend_key: self.public_spend_key.to_bytes(),
            public_view_key: self.public_view_key.to_bytes(),
            address: self.address,
        }
    }

    pub fn from_serializable(s: &SerializableWallet) -> Wallet {
        Wallet {
            secret_spend_key: Scalar::from_bytes_mod_order(s.secret_spend_key),
            secret_view_key: Scalar::from_bytes_mod_order(s.secret_view_key),
            public_spend_key: CompressedRistretto::from_slice(&s.public_spend_key),
            public_view_key: CompressedRistretto::from_slice(&s.public_view_key),
            address: s.address,
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

    pub fn from_vec(v: &[u8]) -> Result<BLSAGSignature, CryptoOpsError> {
        if v.len() < 72 {
            return Err(CryptoOpsError::InvalidBLSAGLength);
        }
        let i = CompressedRistretto::from_slice(&v[0..32]);
        let c = Scalar::from_canonical_bytes(
            v[32..64]
                .try_into()
                .map_err(|_| CryptoOpsError::TryIntoError)?,
        )
        .ok_or(CryptoOpsError::DecompressionFailed)?;
        let s_len = u64::from_le_bytes(
            v[64..72]
                .try_into()
                .map_err(|_| CryptoOpsError::TryIntoError)?,
        ) as usize;
        let mut s = Vec::new();
        for n in 0..s_len {
            let start = 72 + n * 32;
            let end = start + 32;
            s.push(
                Scalar::from_canonical_bytes(
                    v[start..end]
                        .try_into()
                        .map_err(|_| CryptoOpsError::TryIntoError)?,
                )
                .ok_or(CryptoOpsError::DecompressionFailed)?,
            );
        }

        Ok(BLSAGSignature { i, c, s })
    }
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

pub fn hash_to_point(point: &CompressedRistretto) -> RistrettoPoint {
    let hash = hash!(point.to_bytes());
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

pub fn verify(
    public_spend_key: &CompressedRistretto,
    message: &[u8],
    signature: &Signature,
) -> bool {
    let r = signature.r.decompress().unwrap();
    let public_spend_key_point = public_spend_key;
    let hash = hash!(signature.r.to_bytes(), public_spend_key.to_bytes(), message);
    let h_scalar = Scalar::from_bits(hash.into());
    let r_prime = &constants::RISTRETTO_BASEPOINT_TABLE * &signature.s
        + public_spend_key_point.decompress().unwrap() * h_scalar;

    r == r_prime
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
        s.map(|scalar| Signature { r, s: scalar })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate().unwrap();
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
        let original_wallet = Wallet::generate().unwrap();
        let reconstructed_wallet = Wallet::reconstruct(original_wallet.secret_spend_key).unwrap();

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
        let wallet = Wallet::generate().unwrap();
        let message = b"Hello, World!";
        let signature = wallet.sign(message).unwrap();
        assert!(verify(&wallet.public_spend_key, message, &signature));
        let different_message = b"Goodbye, World!";
        assert!(!verify(
            &wallet.public_spend_key,
            different_message,
            &signature
        ));
        let different_wallet = Wallet::generate().unwrap();
        assert!(!verify(
            &different_wallet.public_spend_key,
            message,
            &signature
        ));
    }

    #[test]
    fn test_wallet_reconstruction() {
        let wallet = Wallet::generate().unwrap();
        let reconstructed_wallet = Wallet::reconstruct(wallet.secret_spend_key).unwrap();
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
        let output_index: u32 = 1;
        let amount: u64 = 5000;

        let my_wallet = Wallet::generate().unwrap();
        let re_wallet = Wallet::generate().unwrap();
        let r = Scalar::random(&mut rand::thread_rng());
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let q = &r * &re_wallet.public_view_key.decompress().unwrap();
        let q_bytes = q.compress().to_bytes();
        let encrypted_amount = my_wallet
            .encrypt_amount(&q_bytes, output_index, amount)
            .unwrap();
        let decrypted_amount = re_wallet
            .decrypt_amount(output_key, output_index, &encrypted_amount)
            .unwrap();
        assert_eq!(
            decrypted_amount, amount,
            "Decrypted amount does not match the original amount"
        );
    }
}
