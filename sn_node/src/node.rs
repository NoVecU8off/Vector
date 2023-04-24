use std::{collections::{HashMap}, sync::{Arc}, time::{Duration}, any::{Any}};
use tonic::{transport::{Server, Channel}, Status, Request, Response};
use hex::encode;
use slog::{o, Drain, Logger, info, error};
use tokio::sync::{Mutex, RwLock};
use tokio::fs::{File};
use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_transaction::transaction::*;
use sn_cryptography::cryptography::Keypair;
use anyhow::{Context, Result};
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use std::path::PathBuf;
use tonic::transport::{ClientTlsConfig, ServerTlsConfig, Certificate, Identity};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub cfg_version: String,
    pub cfg_addr: String,
    pub cfg_keypair: Keypair,
    pub cfg_certificate: Vec<u8>,
    pub cfg_cert_key: Vec<u8>,
}

impl ServerConfig {
    pub async fn new() -> Self {
        let (cfg_certificate, cfg_cert_key) = generate_ssl_self_signed_cert_and_key().await.unwrap();
        ServerConfig {
            cfg_version:"1".to_string(),
            cfg_addr: "192.168.0.120:8080".to_string(), 
            cfg_keypair: Keypair::generate_keypair(), 
            cfg_certificate, 
            cfg_cert_key, 
        }
    }
}

#[derive(Clone)]
pub struct NodeService {
    pub server_config: ServerConfig,
    pub logger: Logger,
    pub peer_lock: Arc<RwLock<HashMap<String, (Arc<Mutex<NodeClient<Channel>>>, Version)>>>,
    pub mempool: Arc<Mempool>,
    pub self_ref: Option<Arc<NodeService>>,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(
        &self,
        request: Request<Version>,
    ) -> Result<Response<Version>, Status> {
        let version = request.into_inner();
        let version_clone = version.clone();
        let listen_addr = version.msg_listen_address;
        let server_certificate = &self.server_config.cfg_certificate;
        let (client_cert_pem, client_key_pem) = generate_ssl_self_signed_cert_and_key().await.unwrap();
        let c = make_node_client(&listen_addr, server_certificate, &client_cert_pem, &client_key_pem).await.unwrap();
        self.add_peer(c, version_clone).await;
        let reply = self.get_version().await;
        Ok(Response::new(reply))
    }

    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
    ) -> Result<Response<Confirmed>, Status> {
        let request_inner = request.get_ref().clone();
        let tx = request_inner;
        let tx_clone = tx.clone();
        let hash = hex::encode(hash_transaction(&tx));
        if self.mempool.add(tx).await {
            info!(self.logger, "{}: received transaction: {}", self.server_config.cfg_addr, hash);
            let self_clone = self.self_ref.as_ref().unwrap().clone();
            tokio::spawn(async move {
                if let Err(_err) = self_clone.broadcast(Box::new(tx_clone)).await {
                }
            });
        }
        Ok(Response::new(Confirmed {}))
    }
}

impl NodeService {
    pub fn new(cfg: ServerConfig) -> Self {
        let logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        info!(logger, "NodeService {} created", cfg.cfg_addr);
        NodeService {
            server_config: cfg,
            logger,
            peer_lock: Arc::new(RwLock::new(HashMap::new())),
            mempool: Arc::new(Mempool::new()),
            self_ref: None,
        }
    }

    pub async fn start(&mut self, bootstrap_nodes: Vec<String>) -> Result<()> {
        let node_service = self.clone();
        let addr = self.server_config.cfg_addr.parse().unwrap();
        info!(self.logger, "NodeServer {} starting listening", self.server_config.cfg_addr);
        let (cert_pem, key_pem) = generate_ssl_self_signed_cert_and_key().await?;
        let cert = Certificate::from_pem(cert_pem.clone());
        let server_tls_config = ServerTlsConfig::new()
            .identity(Identity::from_pem(cert_pem, &key_pem))
            .client_ca_root(cert.clone());
        Server::builder()
            .tls_config(server_tls_config)?
            .add_service(NodeServer::new(node_service))
            .serve(addr)
            .await?;
        if !bootstrap_nodes.is_empty() {
            let node_clone = self.clone();
            info!(self.logger, "{}: bootstrapping network with nodes: {:?}", self.server_config.cfg_addr, bootstrap_nodes);
            tokio::spawn(async move {
                if let Err(e) = node_clone.bootstrap_network(bootstrap_nodes).await {
                    error!(node_clone.logger, "Error bootstrapping network: {:?}", e);
                }
            });
        }
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                node_clone.validator_tick().await;
            }
        });
        Ok(())
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version)> {
        let mut c = NodeClient::connect(format!("https://{}", addr))
            .await
            .context("Failed to connect to remote node")?;
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .context("Failed to perform handshake with remote node")?
            .into_inner();
        info!(self.logger, "{}: dialed remote node: {}", self.server_config.cfg_addr, addr);
        Ok((c, v))
    }
    
    pub async fn validator_tick(&self) {
        let keypair = &self.server_config.cfg_keypair;
        let public_key_hex = hex::encode(keypair.public.as_bytes());
        let txx = self.mempool.clear().await;
        info!(self.logger, "{}: new block created by {} with {} transactions", self.server_config.cfg_addr, public_key_hex, txx.len());
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    
    pub async fn broadcast(&self, msg: Box<dyn Any + Send + Sync>) -> Result<()> {
        let peers = self.peer_lock.read().await;
        for (addr, (peer_client, _)) in peers.iter() {
            if let Some(tx) = msg.downcast_ref::<Transaction>() {
                let peer_client_clone = Arc::clone(peer_client);
                let mut peer_client_lock = peer_client_clone.lock().await;
                let mut req = Request::new(tx.clone());
                // req.metadata_mut().insert_bin("peer", MetadataValue::from_bytes(addr.as_bytes()));
                req.metadata_mut().insert("peer", addr.parse().unwrap());
                if addr != &self.server_config.cfg_addr {
                    if let Err(err) = peer_client_lock.handle_transaction(req).await {
                        error!(self.logger, "Failed to broadcast transaction {} to {}: {:?}", hex::encode(hash_transaction(tx)), addr, err);
                        return Err(err.into());
                    } else {
                        info!(self.logger, "{}: broadcasted transaction \n {} \n to \n {}", self.server_config.cfg_addr, hex::encode(hash_transaction(tx)), addr);
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn bootstrap_network(&self, addrs: Vec<String>) -> Result<()> {
        for addr in addrs {
            if !self.can_connect_with(&addr).await {
                continue;
            }
            let (c, v) = self.dial_remote_node(&addr).await?;
            self.add_peer(c, v).await;
            info!(self.logger, "{}: bootstrapped node: {}", self.server_config.cfg_addr, addr);
        }
        Ok(())
    }
    
    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let mut peers = self.peer_lock.write().await;
        let remote_addr = v.msg_listen_address.clone();
        peers.insert(remote_addr.clone(), (Arc::new(c.into()), v.clone()));
        info!(self.logger, "{}: new peer added: {}", self.server_config.cfg_addr, remote_addr);
    }
    
    pub async fn delete_peer(&self, addr: &str) {
        let mut peers = self.peer_lock.write().await;
        if peers.remove(addr).is_some() {
            info!(self.logger, "{}: peer removed: {}", self.server_config.cfg_addr, addr);
        }
    }

    pub async fn get_peer_list(&self) -> Vec<String> {
        let peers = self.peer_lock.read().await;
        peers.values().map(|(_, version)| version.msg_listen_address.clone()).collect()
    }

    pub async fn get_version(&self) -> Version {
        Version {
            msg_version: "test-1".to_string(),
            msg_height: 0,
            msg_listen_address: self.server_config.cfg_addr.clone(),
            msg_peer_list: self.get_peer_list().await,
        }
    }

    pub async fn can_connect_with(&self, addr: &str) -> bool {
        if self.server_config.cfg_addr == addr {
            return false;
        }
        let connected_peers = self.get_peer_list().await;
        for connected_addr in connected_peers {
            if addr == connected_addr {
                return false;
            }
        }
        true
    }
}

pub async fn make_node_client(
    remote_addr: &str,
    server_cert_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> Result<NodeClient<Channel>> {
    let addr = format!("https://{}", remote_addr);
    let addr_uri = addr.parse().unwrap();
    let cert = Certificate::from_pem(server_cert_pem);
    let tls_config = ClientTlsConfig::new()
        .domain_name("")
        .ca_certificate(cert.clone())
        .identity(Identity::from_pem(client_cert_pem, client_key_pem));
    let channel = Channel::builder(addr_uri)
        .tls_config(tls_config)?
        .connect()
        .await?;
    let node_client = NodeClient::new(channel);
    Ok(node_client)
}

pub async fn generate_ssl_self_signed_cert_and_key() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut subject_name_builder = X509NameBuilder::new()?;
    subject_name_builder.append_entry_by_text("CN", "localhost")?;
    let subject_name = subject_name_builder.build();

    let mut issuer_name_builder = X509NameBuilder::new()?;
    issuer_name_builder.append_entry_by_text("CN", "my_custom_ca")?;
    let issuer_name = issuer_name_builder.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&subject_name)?;
    builder.set_issuer_name(&issuer_name)?;
    builder.set_pubkey(&pkey)?;

    let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
    let not_after = openssl::asn1::Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    // builder.append_extension(BasicConstraints::new().critical().build()?)?;

    builder.sign(&pkey, openssl::hash::MessageDigest::sha256())?;

    let certificate = builder.build();
    let certificate_pem = certificate.to_pem()?;
    let private_key_pem = pkey.private_key_to_pem_pkcs8()?;

    // let mut cert_file = File::create("self_signed_certificate.pem").await?;
    // let mut key_file = File::create("self_signed_private_key.pem").await?;

    // cert_file.write_all(&certificate_pem).await?;
    // key_file.write_all(&private_key_pem).await?;

    Ok((certificate_pem, private_key_pem))
}

pub struct Mempool {
    pub lock: RwLock<HashMap<String, Transaction>>,
    pub logger: Logger,
}

impl Mempool {
    pub fn new() -> Self {
        let logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        info!(logger, "Mempool created");
        Mempool {
            lock: RwLock::new(HashMap::new()),
            logger,
        }
    }

    pub async fn clear(&self) -> Vec<Transaction> {
        let mut lock = self.lock.write().await;
        let txx = lock.values().cloned().collect::<Vec<_>>();
        lock.clear();
        info!(self.logger, "Mempool cleared, {} transactions removed", txx.len());
        txx
    }

    pub async fn len(&self) -> usize {
        let lock = self.lock.read().await;
        lock.len()
    }

    pub async fn has(&self, tx: &Transaction) -> bool {
        let lock = self.lock.read().await;
        let hex_hash = encode(hash_transaction(tx));
        lock.contains_key(&hex_hash)
    }

    pub async fn add(&self, tx: Transaction) -> bool {
        if self.has(&tx).await {
            return false;
        }
        let mut lock = self.lock.write().await;
        let hash = hex::encode(hash_transaction(&tx));
        lock.insert(hash.clone(), tx);
        info!(self.logger, "Transaction added to mempool: {}", hash);
        true
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn shutdown(shutdown_tx: tokio::sync::oneshot::Sender<()>) -> Result<(), &'static str> {
    shutdown_tx.send(()).map_err(|_| "Failed to send shutdown signal")
}

#[allow(dead_code)]
pub async fn save_config(config: &ServerConfig, config_path: PathBuf) -> Result<(), anyhow::Error> {
    let serialized_data = serialize(config)?;
    let mut file = File::create(config_path).await?;
    file.write_all(&serialized_data).await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn load_config(config_path: PathBuf) -> Result<ServerConfig, anyhow::Error> {
    let mut file = File::open(config_path).await?;
    let mut serialized_data = Vec::new();
    file.read_to_end(&mut serialized_data).await?;
    let config: ServerConfig = deserialize(&serialized_data)?;
    Ok(config)
}


// let current_exe_path = match env::current_exe() {
//     Ok(path) => path,
//     Err(e) => {
//         println!("Error getting current executable path: {:?}", e);
//         return;
//     }
// };

// let config_path = current_exe_path.parent().unwrap().join(CONFIG_FILE);