use std::collections::HashMap;
use std::sync::{RwLock, Arc};
use std::time::Duration;
use std::any::Any;
use hex::encode;
use slog::{o, Drain, Logger, info, debug, error};
use tonic::transport::{Server, Channel, Body};
use tonic::Status;
use tonic::Request;
use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_transaction::transaction::*;
use ed25519_dalek::SecretKey;
use anyhow::{Context, Result};

pub const BLOCK_TIME: Duration = Duration::from_secs(5);

pub struct Mempool {
    lock: RwLock<HashMap<String, Transaction>>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            lock: RwLock::new(HashMap::new()),
        }
    }

    pub fn clear(&self) -> Vec<Transaction> {
        let mut lock = self.lock.write().unwrap();
        let txx = lock.values().cloned().collect::<Vec<_>>();
        lock.clear();
        txx
    }

    pub fn len(&self) -> usize {
        let lock = self.lock.read().unwrap();
        lock.len()
    }

    pub fn has(&self, tx: &Transaction) -> bool {
        let lock = self.lock.read().unwrap();
        let hash = hex::encode(hash_transaction(tx));
        lock.contains_key(&hash)
    }

    pub fn add(&self, tx: Transaction) -> bool {
        if self.has(&tx) {
            return false;
        }
        let mut lock = self.lock.write().unwrap();
        let hash = hex::encode(hash_transaction(&tx));
        lock.insert(hash, tx);
        true
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub version: String,
    pub listen_addr: String,
    pub private_key: Option<Arc<SecretKey>>,
}

#[derive(Clone)]
pub struct NodeService {
    pub server_config: ServerConfig,
    pub logger: Logger,
    pub peer_lock: Arc<RwLock<HashMap<String, (Arc<NodeClient<Channel>>, Version)>>>,
    pub mempool: Arc<Mempool>,
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
            logger: logger,
            peer_lock: Arc::new(RwLock::new(HashMap::new())),
            mempool: Arc::new(Mempool::new()),
        }
    }

    pub async fn start(&self, listen_addr: &str, bootstrap_nodes: Vec<String>) -> Result<()> {
        self.server_config.listen_addr = listen_addr.to_owned();
        let node_service = NodeServer::new(self.clone());
        let addr = listen_addr.parse().unwrap();
        info!(self.logger, "node started..."; "port" => self.server_config.listen_addr);
        if !bootstrap_nodes.is_empty() {
            let node_clone = self.clone();
            tokio::spawn(async move {
                node_clone.bootstrap_network(bootstrap_nodes).await;
            });
        }
        if let Some(ref _private_key) = self.server_config.private_key {
            let node_clone = self.clone();
            tokio::spawn(async move {
                node_clone.validator_loop().await;
            });
        }
        Server::builder()
            .add_service(node_service)
            .serve(addr)
            .await?;

        Ok(())
    }

    pub async fn validator_loop(&self) {
        info!(self.logger, "starting validator loop"; "pubkey" => self.server_config.private_key.as_ref().unwrap().public_key(), "block_time" => BLOCK_TIME.as_secs());
        let mut interval = tokio::time::interval(BLOCK_TIME);
        loop {
            interval.tick().await;
            let txx = self.mempool.clear();
            debug!(self.logger, "time to create a new block"; "len_tx" => txx.len());
        }
    }

    pub async fn broadcast<T: 'static + Send + Sync>(&self, msg: T) -> Result<()> {
        let peers = self.peer_lock.read().unwrap();
        for (peer, _) in peers.iter() {
            if let Some(tx) = msg.downcast_ref::<Transaction>() {
                let _ = peer.handle_transaction(Request::new(tx.clone())).await?;
            }
        }
        Ok(())
    }

    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let mut peers = self.peer_lock.write().unwrap();
        let remote_addr = v.msg_listen_address.clone();
        peers.insert(remote_addr, (Arc::new(c), v.clone()));
        debug!(self.logger, "new peer successfully connected"; "listen_addr" => &self.server_config.listen_addr, "remote_node" => v.msg_listen_address, "height" => v.msg_height);
    }
    
    pub async fn delete_peer(&self, c: &Arc<NodeClient<Channel>>) {
        let mut peers = self.peer_lock.write().unwrap();
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
            if !self.can_connect_with(&addr) {
                continue;
            }
            let (c, v) = self.dial_remote_node(&addr).await?;
            self.add_peer(c, v).await;
        }
        Ok(())
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version)> {
        let mut c = NodeClient::connect(addr.to_owned())
            .await
            .context("Failed to connect to remote node")?;
        let v = c
            .handshake(Request::new(self.get_version()))
            .await
            .context("Failed to perform handshake with remote node")?
            .into_inner();
        Ok((c, v))
    }

    pub fn get_version(&self) -> Version {
        Version {
            msg_version: "blocker-0.1".to_string(),
            msg_height: 0,
            msg_listen_address: self.server_config.listen_addr.clone(),
            msg_peer_list: self.get_peer_list(),
        }
    }

    pub fn can_connect_with(&self, addr: &str) -> bool {
        if self.server_config.listen_addr == addr {
            return false;
        }
        let connected_peers = self.get_peer_list();
        for connected_addr in connected_peers {
            if addr == connected_addr {
                return false;
            }
        }
        true
    }

    pub fn get_peer_list(&self) -> Vec<String> {
        let peers = self.peer_lock.read().unwrap();
        peers.values().map(|version| version.listen_addr.clone()).collect()
    }
}

pub async fn make_node_client(listen_addr: &str) -> Result<NodeClient<Channel>> {
    let node_client = NodeClient::connect(listen_addr.to_owned()).await?;
    Ok(node_client)
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(
        &self,
        request: Request<Version>,
    ) -> Result<tonic::Response<Version>, Status> {
        let v = request.into_inner();
        match self.handshake(v).await {
            Ok(version) => Ok(tonic::Response::new(version)),
            Err(err) => Err(Status::internal(err.to_string())),
        }
    }

    async fn handle_transaction(
        &self,
        request: Request<Transaction>,
    ) -> Result<tonic::Response<Confirmed>, Status> {
        let tx = request.into_inner();
        match self.handle_transaction(tx).await {
            Ok(confirmed) => Ok(tonic::Response::new(confirmed)),
            Err(err) => Err(Status::internal(err.to_string())),
        }
    }
}
