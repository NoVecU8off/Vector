use std::{collections::{HashMap}, sync::{Arc}, time::{Duration}, any::{Any}};
use tonic::{transport::{Server, Channel, ClientTlsConfig}, Status, Request, Response};
use tonic::transport::ServerTlsConfig;
use tonic::transport::Identity;
use tonic::transport::Certificate;
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
use tokio::fs;

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
        info!(logger, "\nMempool created");
        Mempool {
            lock: RwLock::new(HashMap::new()),
            logger,
        }
    }

    pub async fn clear(&self) -> Vec<Transaction> {
        let mut lock = self.lock.write().await;
        let txx = lock.values().cloned().collect::<Vec<_>>();
        lock.clear();
        info!(self.logger, "\nMempool cleared, {} transactions removed", txx.len());
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
        info!(self.logger, "\nTransaction added to mempool: {}", hash);
        true
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub cfg_version: String,
    pub cfg_addr: String,
    pub cfg_keypair: Keypair,
    pub cfg_pem_certificate: Vec<u8>,
    pub cfg_pem_key: Vec<u8>,
}

impl ServerConfig {
    pub async fn default() -> Self {
        let (cfg_pem_certificate, cfg_pem_key) = read_server_certs_and_keys().await.unwrap();
        ServerConfig {
            cfg_version: "1".to_string(),
            cfg_addr: "192.168.0.120:8080".to_string(),
            cfg_keypair: Keypair::generate_keypair(),
            cfg_pem_certificate,
            cfg_pem_key,
        }
    }

    pub async fn default_b() -> Self {
        let (cfg_pem_certificate, cfg_pem_key) = read_server_certs_and_keys().await.unwrap();
        ServerConfig {
            cfg_version: "1".to_string(),
            cfg_addr: "192.168.0.120:8000".to_string(),
            cfg_keypair: Keypair::generate_keypair(),
            cfg_pem_certificate,
            cfg_pem_key,
        }
    }

    pub async fn new(
        version: &str,
        address: &str,
        keypair: Keypair,
        certificate_pem: Vec<u8>,
        key_pem: Vec<u8>,
    ) -> Self {
        ServerConfig {
            cfg_version: version.to_string(),
            cfg_addr: address.to_string(),
            cfg_keypair: keypair,
            cfg_pem_certificate: certificate_pem,
            cfg_pem_key: key_pem,
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
        info!(self.logger, "\nStarting handshaking");
        let version = request.into_inner();
        let version_clone = version.clone();
        let addr = version.msg_listen_address;
        info!(self.logger, "\nRecieved version, address: {}", addr);
        match make_node_client(&addr).await {
            Ok(c) => {
                info!(self.logger, "Created node client successfully");
                self.add_peer(c, version_clone).await;

                let reply = self.get_version().await;

                info!(self.logger, "Returning version: {:?}", reply);
                Ok(Response::new(reply))
            }
            Err(e) => {
                error!(self.logger, "Failed to create node client: {:?}", e);
                Err(Status::internal("Failed to create node client"))
            }
        }
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
            info!(self.logger, "\n{}: received transaction: {}", self.server_config.cfg_addr, hash);
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
        info!(logger, "\nNodeService {} created", cfg.cfg_addr);
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
        let addr = format!("{}", self.server_config.cfg_addr)
            .parse()
            .unwrap();
        info!(self.logger, "\nNodeServer {} starting listening", self.server_config.cfg_addr);
        let server_tls_config = ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.server_config.cfg_pem_certificate, &self.server_config.cfg_pem_key))
            .client_ca_root(Certificate::from_pem(&self.server_config.cfg_pem_certificate));
        Server::builder()
            .tls_config(server_tls_config)
            .unwrap()
            .accept_http1(true)
            .add_service(NodeServer::new(node_service))
            .serve(addr)
            .await
            .map_err(|err| {
                error!(self.logger, "Error listening for incoming connections: {:?}", err);
                err
            })?;
        if !bootstrap_nodes.is_empty() {
            let node_clone = self.clone();
            info!(self.logger, "\n{}: bootstrapping network with nodes: {:?}", self.server_config.cfg_addr, bootstrap_nodes);
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
    
    pub async fn validator_tick(&self) {
        let public_key_hex = hex::encode(&self.server_config.cfg_keypair.public.as_bytes());
        let txx = self.mempool.clear().await;
        info!(self.logger, "\n{}: new block created by {} with {} transactions", self.server_config.cfg_addr, public_key_hex, txx.len());
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    
    pub async fn broadcast(&self, msg: Box<dyn Any + Send + Sync>) -> Result<()> {
        let peers = self.peer_lock.read().await;
        for (addr, (peer_client, _)) in peers.iter() {
            if let Some(tx) = msg.downcast_ref::<Transaction>() {
                let peer_client_clone = Arc::clone(peer_client);
                let mut peer_client_lock = peer_client_clone.lock().await;
                let mut req = Request::new(tx.clone());
                req.metadata_mut().insert("peer", addr.parse().unwrap());
                if addr != &self.server_config.cfg_addr {
                    if let Err(err) = peer_client_lock.handle_transaction(req).await {
                        error!(self.logger, "Failed to broadcast transaction {} to {}: {:?}", hex::encode(hash_transaction(tx)), addr, err);
                        return Err(err.into());
                    } else {
                        info!(self.logger, "\n{}: broadcasted transaction \n {} \nto \n {}", self.server_config.cfg_addr, hex::encode(hash_transaction(tx)), addr);
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
        info!(self.logger, "\n{}: new peer added: {}", self.server_config.cfg_addr, remote_addr);
    }
    
    pub async fn delete_peer(&self, addr: &str) {
        let mut peers = self.peer_lock.write().await;
        if peers.remove(addr).is_some() {
            info!(self.logger, "\n{}: peer removed: {}", self.server_config.cfg_addr, addr);
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
            info!(self.logger, "\n{}: bootstrapped node: {}", self.server_config.cfg_addr, addr);
        }
        Ok(())
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version)> {
        let mut c = make_node_client(addr)
            .await
            .map_err(|err| {
                error!(self.logger, "Failed to create node client: {:?}", err);
                err
            })
            .context("Failed to create node for dial")?;
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(|err| {
                error!(self.logger, "Failed to perform handshake with remote node: {:?}", err);
                err
            })
            .context("Handshake failure")?
            .into_inner();
        info!(self.logger, "\n{}: dialed remote node: {}", self.server_config.cfg_addr, addr);
        Ok((c, v))
    }

    pub async fn get_version(&self) -> Version {
        Version {
            msg_version: self.server_config.cfg_version.clone(),
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

pub async fn make_node_client(addr: &str) -> Result<NodeClient<Channel>> {
    let (cli_pem_certificate, cli_pem_key) = read_client_certs_and_keys().await.unwrap();
    let uri = format!("https://{}", addr).parse().unwrap();
    let client_tls_config = ClientTlsConfig::new()
        .domain_name("testserver.com")
        .ca_certificate(Certificate::from_pem(cli_pem_certificate.clone()))
        .identity(Identity::from_pem(cli_pem_certificate, cli_pem_key));
    let channel = Channel::builder(uri)
        .tls_config(client_tls_config)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let node_client = NodeClient::new(channel);
    Ok(node_client)
}

pub async fn shutdown(shutdown_tx: tokio::sync::oneshot::Sender<()>) -> Result<(), &'static str> {
    shutdown_tx.send(()).map_err(|_| "Failed to send shutdown signal")
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

pub async fn read_server_certs_and_keys() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_file_path = "./certs/end.fullchain";
    let key_file_path = "./certs/end.key";
    let cert_pem = fs::read(cert_file_path).await?;
    let key_pem = fs::read(key_file_path).await?;
    Ok((cert_pem, key_pem))
}

pub async fn read_client_certs_and_keys() -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let cert_file_path = "./certs/ca.cert";
    let key_file_path = "./certs/ca.key";
    let cert_pem = fs::read(cert_file_path).await?;
    let key_pem = fs::read(key_file_path).await?;
    Ok((cert_pem, key_pem))
}
