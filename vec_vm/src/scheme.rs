use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    constants, ristretto::CompressedRistretto, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use merlin::Transcript;
use rand::seq::SliceRandom;
use sha3::{Digest, Keccak256};
use vec_errors::errors::{CryptoOpsError, SchemeError};
use vec_proto::messages::TransactionOutput;

pub struct Output {
    pub stealth: Vec<u8>,
    pub output_key: Vec<u8>,
    pub amount: Vec<u8>,
    pub commitment: Vec<u8>,
    pub range_proof: Vec<u8>,
}

pub struct Input {
    pub ring: Vec<Vec<u8>>,
    pub blsag: Vec<u8>,
    pub message: Vec<u8>,
    pub image: Vec<u8>,
}

pub struct Parties {
    pub addresses: Vec<Vec<u8>>,
}

pub struct Storage {
    pub outputs: Vec<Output>,
}

pub struct Wallet {
    secret_spend_key: Scalar,
    secret_view_key: Scalar,
    pub public_spend_key: CompressedRistretto,
    pub public_view_key: CompressedRistretto,
    pub address: Vec<u8>,
}

pub struct BLSAG {
    pub i: CompressedRistretto,
    pub c: Scalar,
    pub s: Vec<Scalar>,
}

impl BLSAG {
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
}

impl Wallet {
    pub fn new() -> Result<Wallet, SchemeError> {
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
        let address = data;

        Ok(Wallet {
            secret_spend_key,
            secret_view_key,
            public_spend_key: public_spend_key.compress(),
            public_view_key: public_view_key.compress(),
            address,
        })
    }

    pub fn gen_blsag(
        &self,
        p: &[CompressedRistretto],
        m: &[u8],
        stealth: &CompressedRistretto,
    ) -> Result<BLSAG, SchemeError> {
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
        l[j] = a * constants::RISTRETTO_BASEPOINT_POINT;
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
            let mut hasher = Keccak256::new();
            hasher.update(m);
            hasher.update(l[i].compress().to_bytes());
            hasher.update(r[i].compress().to_bytes());
            let hash = hasher.finalize();
            c[ip1] = Scalar::from_bytes_mod_order(hash.into());
        }
        s[j] = a - c[j] * self.secret_spend_key;

        Ok(BLSAG {
            i: image,
            c: c[0],
            s,
        })
    }

    pub fn encrypt_amount(
        &self,
        q_bytes: &[u8],
        output_index: u64,
        amount: u64,
    ) -> Result<[u8; 8], CryptoOpsError> {
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash_qi = hasher.finalize();
        let mut hasher = Keccak256::new();
        hasher.update(b"amount");
        hasher.update(hash_qi);
        let hash = hasher.finalize();
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
        output_index: u64,
        encrypted_amount: &[u8],
    ) -> Result<u64, CryptoOpsError> {
        let decompressed_output = output_key
            .decompress()
            .ok_or(CryptoOpsError::DecompressionFailed)?;
        let q = self.secret_view_key * decompressed_output;
        let q_bytes = q.compress().as_bytes().to_vec();
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash_qi = hasher.finalize();
        let mut hasher = Keccak256::new();
        hasher.update(b"amount");
        hasher.update(hash_qi);
        let hash = hasher.finalize();
        let hash_8: [u8; 8] = hash[0..8]
            .try_into()
            .map_err(|_| CryptoOpsError::TryIntoError)?;
        let encrypted_amount_8 = encrypted_amount
            .try_into()
            .map_err(|_| CryptoOpsError::TryIntoError)?;
        let decrypted_amount = xor8(encrypted_amount_8, hash_8);

        Ok(u64::from_le_bytes(decrypted_amount))
    }
}

impl Storage {
    pub fn new() -> Storage {
        let outputs = Vec::new();
        Storage { outputs }
    }
}

impl Parties {
    pub fn new() -> Parties {
        Parties {
            addresses: Vec::new(),
        }
    }
}

pub struct Scheme {
    pub wallet: Wallet,
    pub storage: Storage,
    pub parties: Parties,
}

impl Scheme {
    pub fn new() -> Result<Scheme, SchemeError> {
        let wallet = Wallet::new().unwrap();
        let storage = Storage::new();
        let parties = Parties::new();
        Ok(Scheme {
            wallet,
            storage,
            parties,
        })
    }

    pub fn prepare_inputs(&mut self) -> Result<Vec<Input>, SchemeError> {
        let output_set = &self.storage.outputs;
        let mut inputs = Vec::new();
        for output in output_set {
            let stealth = &output.stealth;
            let compressed = CompressedRistretto::from_slice(&stealth);
            let wallet_res: Result<Vec<Wallet>, _> = (0..9).map(|_| Wallet::new()).collect();
            let wallets = wallet_res?;
            let mut s_addrs: Vec<CompressedRistretto> =
                wallets.iter().map(|w| w.public_spend_key).collect();
            s_addrs.push(compressed);
            s_addrs.shuffle(&mut rand::thread_rng());
            let ring: Vec<Vec<u8>> = s_addrs.iter().map(|key| key.to_bytes().to_vec()).collect();
            let m = b"Message example";
            let blsag = self.wallet.gen_blsag(&s_addrs, m, &compressed)?;
            let image = blsag.i;
            let input = Input {
                ring,
                blsag: blsag.to_vec(),
                message: m.to_vec(),
                image: image.to_bytes().to_vec(),
            };
            inputs.push(input);
        }
        Ok(inputs)
    }

    pub fn prepare_output(
        &self,
        recipient_address: &str,
        output_index: u64,
        amount: u64,
    ) -> Result<TransactionOutput, SchemeError> {
        let (recipient_spend_key, recipient_view_key) =
            derive_keys_from_address(recipient_address).unwrap();
        let mut rng = rand::thread_rng();
        let r = Scalar::random(&mut rng);
        let output_key = (&r * &constants::RISTRETTO_BASEPOINT_TABLE).compress();
        let recipient_view_key_point = recipient_view_key.decompress().unwrap();
        let q = r * recipient_view_key_point;
        let q_bytes = q.compress().to_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(q_bytes);
        hasher.update(output_index.to_le_bytes());
        let hash = hasher.finalize();
        let hash_in_scalar = Scalar::from_bytes_mod_order(hash.into());
        let hs_times_g = &constants::RISTRETTO_BASEPOINT_TABLE * &hash_in_scalar;
        let recipient_spend_key_point = recipient_spend_key.decompress().unwrap();
        let stealth = (hs_times_g + recipient_spend_key_point).compress();
        let encrypted_amount = self.wallet.encrypt_amount(&q_bytes, output_index, amount)?;
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
}

pub fn hash_to_point(point: &CompressedRistretto) -> RistrettoPoint {
    let mut hasher = Keccak256::new();
    hasher.update(point.to_bytes());
    let hash = hasher.finalize();
    let scalar = Scalar::from_bytes_mod_order(hash.into());

    &constants::RISTRETTO_BASEPOINT_TABLE * &scalar
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

pub fn xor8(a: [u8; 8], b: [u8; 8]) -> [u8; 8] {
    let mut c = [0u8; 8];
    for i in 0..8 {
        c[i] = a[i] ^ b[i];
    }

    c
}
