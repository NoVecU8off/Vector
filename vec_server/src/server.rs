// use tokio::fs::{File};
use vec_cryptography::cryptography::Wallet;
use vec_errors::errors::*;
// use serde::{Serialize, Deserialize};
// use bincode::{serialize, deserialize};
// use tokio::io::{AsyncWriteExt, AsyncReadExt};
// use std::path::PathBuf;

#[derive(Clone)]
pub struct ServerConfig {
    pub cfg_version: String,
    pub cfg_ip: String,
    pub cfg_wallet: Wallet,
    pub cfg_height: u64,
}

impl ServerConfig {
    pub async fn default_v() -> Self {
        ServerConfig {
            cfg_version: "1".to_string(),
            cfg_ip: get_ip().await.expect("Failed to get IP"),
            cfg_wallet: Wallet::generate(),
            cfg_height: 0,
        }
    }

    pub async fn default_n() -> Self {
        ServerConfig {
            cfg_version: "1".to_string(),
            cfg_ip: get_ip().await.expect("Failed to get IP"),
            cfg_wallet: Wallet::generate(),
            cfg_height: 0,
        }
    }
}

// #[allow(dead_code)]
// async fn save_config(config: &ServerConfig, config_path: PathBuf) -> Result<(), ServerConfigError> {
//     let serialized_data = serialize(config).map_err(ServerConfigError::FailedToSerializeConfig)?;
//     let mut file = File::create(config_path).await.map_err(ServerConfigError::FailedToCreateConfigFile)?;
//     file.write_all(&serialized_data).await.map_err(ServerConfigError::FailedToWriteToConfigFile)?;
//     Ok(())
// }

// #[allow(dead_code)]
// async fn load_config(config_path: PathBuf) -> Result<ServerConfig, ServerConfigError> {
//     let mut file = File::open(config_path).await.map_err(ServerConfigError::FailedToOpenConfigFile)?;
//     let mut serialized_data = Vec::new();
//     file.read_to_end(&mut serialized_data).await.map_err(ServerConfigError::FailedToReadFromConfigFile)?;
//     let config: ServerConfig = deserialize(&serialized_data).map_err(ServerConfigError::FailedToDeserializeConfig)?;
//     Ok(config)
// }

async fn get_ip() -> Result<String, ServerConfigError> {
    let response = reqwest::get("https://api.ipify.org").await?;
    let ip = response.text().await?;
    let ip_port = format!("{}:8088", ip);
    Ok(ip_port)
}