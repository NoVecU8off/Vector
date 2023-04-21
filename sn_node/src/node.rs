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
use rcgen::{generate_simple_self_signed, CertificateParams};
use rcgen::{SanType};

pub const BLOCK_TIME: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub version: String,
    pub server_listen_addr: String,
    pub keypair: Option<Keypair>,
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
        let c = make_node_client(&listen_addr).await.unwrap();
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
            info!(self.logger, "{}: received transaction: {}", self.server_config.server_listen_addr, hash);
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
        info!(logger, "NodeService {} created", cfg.server_listen_addr);
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
        let addr = self.server_config.server_listen_addr.parse().unwrap();
        info!(self.logger, "NodeServer {} starting listening", self.server_config.server_listen_addr);
        let (cert_pem, key_pem) = generate_self_signed_cert_and_key()?;
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
            info!(self.logger, "{}: bootstrapping network with nodes: {:?}", self.server_config.server_listen_addr, bootstrap_nodes);
            tokio::spawn(async move {
                if let Err(e) = node_clone.bootstrap_network(bootstrap_nodes).await {
                    error!(node_clone.logger, "Error bootstrapping network: {:?}", e);
                }
            });
        }
        if self.server_config.keypair.is_some() {
            let node_clone = self.clone();
            tokio::spawn(async move {
                loop {
                    node_clone.validator_tick().await;
                }
            });
        }
        Ok(())
    }
    
    pub async fn validator_tick(&self) {
        if let Some(keypair) = self.server_config.keypair.as_ref() {
            let public_key_hex = hex::encode(keypair.public.as_bytes());
            let txx = self.mempool.clear().await;
            info!(self.logger, "{}: new block created by {} with {} transactions", self.server_config.server_listen_addr, public_key_hex, txx.len());
            tokio::time::sleep(BLOCK_TIME).await;
        } else {
            error!(self.logger, "{}: no keypair provided, validator loop cannot start", self.server_config.server_listen_addr);
        }
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
                if addr != &self.server_config.server_listen_addr {
                    if let Err(err) = peer_client_lock.handle_transaction(req).await {
                        error!(self.logger, "Failed to broadcast transaction {} to {}: {:?}", hex::encode(hash_transaction(tx)), addr, err);
                        return Err(err.into());
                    } else {
                        info!(self.logger, "{}: broadcasted transaction \n {} \n to \n {}", self.server_config.server_listen_addr, hex::encode(hash_transaction(tx)), addr);
                    }
                }
            }
        }
        Ok(())
    }
    
    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let mut peers = self.peer_lock.write().await;
        let remote_addr = v.msg_listen_address.clone();
        peers.insert(remote_addr.clone(), (Arc::new(c.into()), v.clone()));
        info!(self.logger, "{}: new peer added: {}", self.server_config.server_listen_addr, remote_addr);
    }
    
    pub async fn delete_peer(&self, addr: &str) {
        let mut peers = self.peer_lock.write().await;
        if peers.remove(addr).is_some() {
            info!(self.logger, "{}: peer removed: {}", self.server_config.server_listen_addr, addr);
        }
    }

    pub async fn get_peer_list(&self) -> Vec<String> {
        let peers = self.peer_lock.read().await;
        peers.values().map(|(_, version)| version.msg_listen_address.clone()).collect()
    }
    
    pub async fn bootstrap_network(&self, addrs: Vec<String>) -> Result<()> {
        for addr in addrs {
            if !self.can_connect_with(&addr).await {
                continue;
            }
            let (c, v) = self.dial_remote_node(&addr).await?;
            self.add_peer(c, v).await;
            info!(self.logger, "{}: bootstrapped node: {}", self.server_config.server_listen_addr, addr);
        }
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
        info!(self.logger, "{}: dialed remote node: {}", self.server_config.server_listen_addr, addr);
        Ok((c, v))
    }

    pub async fn get_version(&self) -> Version {
        Version {
            msg_version: "test-1".to_string(),
            msg_height: 0,
            msg_listen_address: self.server_config.server_listen_addr.clone(),
            msg_peer_list: self.get_peer_list().await,
        }
    }

    pub async fn can_connect_with(&self, addr: &str) -> bool {
        if self.server_config.server_listen_addr == addr {
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

pub async fn make_node_client(remote_addr: &str) -> Result<NodeClient<Channel>> {
    let addr = format!("https://{}", remote_addr);
    let addr_uri = addr.parse().unwrap();
    let (cert_pem, key_pem) = generate_self_signed_cert_and_key()?;
    let cert = Certificate::from_pem(cert_pem.clone());
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(cert.clone())
        .identity(Identity::from_pem(&cert_pem, &key_pem));
    let channel = Channel::builder(addr_uri)
        .tls_config(tls_config)?
        .connect()
        .await?;
    let node_client = NodeClient::new(channel);
    Ok(node_client)
}


pub fn generate_self_signed_cert_and_key() -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let subject_alt_names = params
        .subject_alt_names
        .iter()
        .filter_map(|san| match san {
            SanType::DnsName(name) => Some(name.clone()),
            _ => None,
        })
        .collect::<Vec<String>>();
        let rcgen_cert = generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_pem = rcgen_cert.serialize_pem().unwrap();
        let key_pem = rcgen_cert.serialize_private_key_pem();
    Ok((cert_pem, key_pem))
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


// let current_exe_path = match env::current_exe() {
//     Ok(path) => path,
//     Err(e) => {
//         println!("Error getting current executable path: {:?}", e);
//         return;
//     }
// };

// let config_path = current_exe_path.parent().unwrap().join(CONFIG_FILE);
