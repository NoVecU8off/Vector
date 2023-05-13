use tokio::fs::{File};
use sn_cryptography::cryptography::Keypair;
use anyhow::{Result};
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::path::PathBuf;
use std::fs;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub cfg_is_validator: bool,
    pub cfg_version: String,
    pub cfg_addr: String,
    pub cfg_keypair: Keypair,
    pub cfg_pem_certificate: Vec<u8>,
    pub cfg_pem_key: Vec<u8>,
    pub cfg_root_crt: Vec<u8>,
}

impl ServerConfig {
    pub async fn default() -> Self {
        let (cfg_pem_certificate, cfg_pem_key, cfg_root_crt) = read_server_certs_and_keys().unwrap();
        ServerConfig {
            cfg_is_validator: true,
            cfg_version: "1".to_string(),
            cfg_addr: "127.0.0.1:8080".to_string(),
            cfg_keypair: Keypair::generate_keypair(),
            cfg_pem_certificate,
            cfg_pem_key,
            cfg_root_crt,
        }
    }

    pub async fn default_b() -> Self {
        let (cfg_pem_certificate, cfg_pem_key, cfg_root_crt) = read_server_certs_and_keys().unwrap();
        ServerConfig {
            cfg_is_validator: true,
            cfg_version: "1".to_string(),
            cfg_addr: "127.0.0.1:8084".to_string(),
            cfg_keypair: Keypair::generate_keypair(),
            cfg_pem_certificate,
            cfg_pem_key,
            cfg_root_crt,
        }
    }

    pub async fn default_c() -> Self {
        let (cfg_pem_certificate, cfg_pem_key, cfg_root_crt) = read_server_certs_and_keys().unwrap();
        ServerConfig {
            cfg_is_validator: true,
            cfg_version: "1".to_string(),
            cfg_addr: "127.0.0.1:8088".to_string(),
            cfg_keypair: Keypair::generate_keypair(),
            cfg_pem_certificate,
            cfg_pem_key,
            cfg_root_crt,
        }
    }

    pub async fn new(
        is_validator: bool,
        version: &str,
        address: &str,
        keypair: Keypair,
        certificate_pem: Vec<u8>,
        key_pem: Vec<u8>,
        root_pem: Vec<u8>,
    ) -> Self {
        ServerConfig {
            cfg_is_validator: is_validator,
            cfg_version: version.to_string(),
            cfg_addr: address.to_string(),
            cfg_keypair: keypair,
            cfg_pem_certificate: certificate_pem,
            cfg_pem_key: key_pem,
            cfg_root_crt: root_pem,
        }
    }
}

#[allow(dead_code)]
async fn save_config(config: &ServerConfig, config_path: PathBuf) -> Result<(), anyhow::Error> {
    let serialized_data = serialize(config)?;
    let mut file = File::create(config_path).await?;
    file.write_all(&serialized_data).await?;
    Ok(())
}

#[allow(dead_code)]
async fn load_config(config_path: PathBuf) -> Result<ServerConfig, anyhow::Error> {
    let mut file = File::open(config_path).await?;
    let mut serialized_data = Vec::new();
    file.read_to_end(&mut serialized_data).await?;
    let config: ServerConfig = deserialize(&serialized_data)?;
    Ok(config)
}

pub fn read_server_certs_and_keys() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_file_path = "./certs/server.crt";
    let key_file_path = "./certs/server.key";
    let root_file_path = "./certs/root.crt";
    let cert_pem = fs::read(cert_file_path)?;
    let key_pem = fs::read(key_file_path)?;
    let root_pem = fs::read(root_file_path)?;
    Ok((cert_pem, key_pem, root_pem))
}

pub async fn read_client_certs_and_keys() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_file_path = "./certs/client.crt";
    let key_file_path = "./certs/client.key";
    let root_file_path = "./certs/root.crt";
    let cert_pem = fs::read(cert_file_path)?;
    let key_pem = fs::read(key_file_path)?;
    let root_pem = fs::read(root_file_path)?;
    Ok((cert_pem, key_pem, root_pem))
}