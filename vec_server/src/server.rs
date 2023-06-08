use vec_errors::errors::*;

#[derive(Clone)]
pub struct ServerConfig {
    pub cfg_version: u32,
    pub cfg_ip: String,
    pub cfg_secret_spend_key: String,
}

impl ServerConfig {
    pub async fn local(secret_key: String, port: String) -> Self {
        ServerConfig {
            cfg_version: 1,
            cfg_ip: format!("192.168.0.120:{}", port),
            cfg_secret_spend_key: secret_key,
        }
    }
    pub async fn global(secret_key: String) -> Self {
        ServerConfig {
            cfg_version: 1,
            cfg_ip: get_ip().await.expect("Failed to get IP"),
            cfg_secret_spend_key: secret_key,
        }
    }
}

async fn get_ip() -> Result<String, ServerConfigError> {
    let response = reqwest::get("https://api.ipify.org").await?;
    let ip = response.text().await?;
    let ip_port = format!("{}:8080", ip);
    Ok(ip_port)
}
