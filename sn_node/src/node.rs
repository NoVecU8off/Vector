use std::{collections::{HashMap}, sync::{Arc}, time::{Duration}, any::{Any}};
use tonic::{transport::{Server, Channel}, metadata::{MetadataKey}, Status, Request, Response};
use hex::encode;
use slog::{o, Drain, Logger, info, debug, error};
use tokio::sync::{Mutex, RwLock};
use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_transaction::transaction::*;
use sn_cryptography::cryptography::Keypair;
use anyhow::{Context, Result};

pub const BLOCK_TIME: Duration = Duration::from_secs(5);

pub struct Mempool {
    pub lock: RwLock<HashMap<String, Transaction>>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            lock: RwLock::new(HashMap::new()),
        }
    }

    pub async fn clear(&self) -> Vec<Transaction> {
        let mut lock = self.lock.write().await;
        let txx = lock.values().cloned().collect::<Vec<_>>();
        lock.clear();
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
        lock.insert(hash, tx);
        true
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub version: String,
    pub server_listen_addr: String,
    pub keypair: Option<Arc<Keypair>>,
}

#[derive(Clone)]
pub struct NodeService {
    pub server_config: ServerConfig,
    pub logger: Logger,
    pub peer_lock: Arc<RwLock<HashMap<String, (Arc<Mutex<NodeClient<Channel>>>, Version)>>>,
    pub mempool: Arc<Mempool>,
    pub self_ref: Option<Arc<NodeService>>, // Add this field
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(
        &self,
        request: Request<Version>,
    ) -> Result<Response<Version>, Status> {
        println!("Got a request: {:?}", request);
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
        let peer = request
            .metadata()
            .get(MetadataKey::from_static("peer"))
            .and_then(|peer_str| peer_str.to_str().ok())
            .unwrap_or("unknown");
        let tx = request_inner;
        let tx_clone = tx.clone();
        let hash = hex::encode(hash_transaction(&tx));
        if self.mempool.add(tx).await {
            let log_msg = format!(
                "received tx: from={} hash={} we={}",
                peer,
                hash,
                self.server_config.server_listen_addr
            );
            println!("{:?}", &log_msg);
            let self_clone = self.self_ref.as_ref().unwrap().clone();
            tokio::spawn(async move {
                if let Err(err) = self_clone.broadcast(Box::new(tx_clone)).await {
                    let log_msg = format!("broadcast error: err={}", err);
                    println!("{:?}", &log_msg);
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
            let drain = slog_term::CompactFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
    
        NodeService {
            server_config: cfg,
            logger,
            peer_lock: Arc::new(RwLock::new(HashMap::new())),
            mempool: Arc::new(Mempool::new()),
            self_ref: None,
        }
    }

    pub async fn start(&mut self, listen_addr: &str, bootstrap_nodes: Vec<String>) -> Result<()> {
        self.server_config.server_listen_addr = listen_addr.to_string();
        let node_service = self.clone();
        let addr = listen_addr.parse().unwrap();
        Server::builder()
            .add_service(NodeServer::new(node_service))
            .serve(addr)
            .await?;
        info!(self.logger, "Node started"; "port" => &self.server_config.server_listen_addr);
        if !bootstrap_nodes.is_empty() {
            let node_clone = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node_clone.bootstrap_network(bootstrap_nodes).await {
                    error!(node_clone.logger, "Error bootstrapping network: {:?}", e);
                } else {
                    info!(node_clone.logger, "Nodes are bootstraped successfully");
                }
            });
        }
        if self.server_config.keypair.is_some() {
            let node_clone = self.clone();
            tokio::spawn(async move {
                info!(node_clone.logger, "Validator tick started successfully");
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
            info!(self.logger, "starting validator tick"; "pubkey" => public_key_hex, "block_time" => BLOCK_TIME.as_secs());
            let txx = self.mempool.clear().await;
            debug!(self.logger, "time to create a new block"; "len_tx" => txx.len());
            tokio::time::sleep(BLOCK_TIME).await;
        } else {
            error!(self.logger, "No keypair provided, validator loop cannot start");
        }
    }
    
    pub async fn broadcast(&self, msg: Box<dyn Any + Send + Sync>) -> Result<()> {
        let peers = self.peer_lock.read().await;
        for (_, (peer_client, _)) in peers.iter() {
            if let Some(tx) = msg.downcast_ref::<Transaction>() {
                let peer_client_clone = Arc::clone(peer_client);
                let mut peer_client_lock = peer_client_clone.lock().await;
                if let Err(err) = peer_client_lock.handle_transaction(Request::new(tx.clone())).await {
                    return Err(err.into());
                }
            }
        }
        Ok(())
    }
    
    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let mut peers = self.peer_lock.write().await;
        let remote_addr = v.msg_listen_address.clone();
        peers.insert(remote_addr, (Arc::new(c.into()), v.clone()));
        debug!(self.logger, "new peer successfully connected"; "listen_addr" => &self.server_config.server_listen_addr, "remote_node" => v.msg_listen_address, "height" => v.msg_height);
    }
    
    pub async fn delete_peer(&self, c: &Arc<Mutex<NodeClient<Channel>>>) {
        let mut peers = self.peer_lock.write().await;
        let to_remove = peers
            .iter()
            .find(|(_, (peer, _))| Arc::ptr_eq(peer, c))
            .map(|(addr, _)| addr.clone());
        if let Some(addr) = to_remove {
            peers.remove(&addr);
        }
    }

    pub async fn bootstrap_network(&self, addrs: Vec<String>) -> Result<()> {
        for addr in addrs {
            if !self.can_connect_with(&addr).await {
                continue;
            }
            let (c, v) = self.dial_remote_node(&addr).await?;
            self.add_peer(c, v).await;
        }
        Ok(())
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version)> {
        let mut c = NodeClient::connect(addr.to_string())
            .await
            .context("Failed to connect to remote node")?;
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .context("Failed to perform handshake with remote node")?
            .into_inner();
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

    pub async fn get_peer_list(&self) -> Vec<String> {
        let peers = self.peer_lock.read().await;
        peers.values().map(|(_, version)| version.msg_listen_address.clone()).collect()
    }
}

pub async fn make_node_client(remote_addr: &str) -> Result<NodeClient<Channel>> {
    let node_client = NodeClient::connect(format!("http://{}", remote_addr)).await?;
    Ok(node_client)
}

pub async fn shutdown(shutdown_tx: tokio::sync::oneshot::Sender<()>) -> Result<(), &'static str> {
    shutdown_tx.send(()).map_err(|_| "Failed to send shutdown signal")
}