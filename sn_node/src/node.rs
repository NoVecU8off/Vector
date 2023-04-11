use std::collections::HashMap;
use std::sync::{Arc};
use hex::encode;
use sn_proto::messages::{Transaction, Version, Confirmed};
use std::time::Duration;
use sn_transaction::transaction::*;
use sn_cryptography::cryptography::Keypair;
use tonic::transport::Channel;
use sn_proto::messages::{node_server::{Node, NodeServer}, node_client::NodeClient};
use tonic::transport::{Endpoint, Server};
use tonic::{Request, Response, Status};
use tokio::net::{TcpListener};
use tracing::{info, Span};
use tokio::time::interval;
use tokio::sync::{RwLock, Mutex};
use std::hash::{Hash, Hasher};
use std::net::{SocketAddr, Ipv6Addr};
use hyper::Uri;
use anyhow::Error;
use async_recursion::async_recursion;

pub const BLOCK_TIME: Duration = Duration::from_secs(10);

pub struct Mempool {
    lock: RwLock<()>,
    txx: HashMap<String, Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            lock: RwLock::new(()),
            txx: HashMap::new(),
        }
    }

    pub async fn clear(&mut self) -> Vec<Transaction> {
        let mut _guard = self.lock.write().await;
        let txx: Vec<Transaction> = self.txx.drain().map(|(_, v)| v).collect();
        txx
    }

    pub async fn len(&self) -> usize {
        let _guard = self.lock.read().await;
        self.txx.len()
    }

    pub async fn has(&self, tx: &Transaction) -> bool {
        let _guard = self.lock.read().await;
        let hash = encode(hash_transaction(tx));
        self.txx.contains_key(&hash)
    }

    pub async fn add(&mut self, tx: &Transaction) -> bool {
        if self.has(tx).await {
            return false;
        }
        let mut _guard = self.lock.write().await;
        let hash = encode(hash_transaction(tx));
        self.txx.insert(hash, tx.clone());
        true
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub version: String,
    pub listen_addr: String,
    pub keypair: Keypair,
}

pub struct OperationalNode {
    pub config: ServerConfig,
    pub logger: Span,
    pub peer_lock: RwLock<()>,
    pub peers: RwLock<HashMap<NodeClientWrapper, Version>>,
    pub mempool: Mutex<Mempool>,
}

pub struct OperationalNodeArc(Arc<OperationalNode>);

pub enum BroadcastMsg {
    Transaction(Transaction),
}

pub async fn get_available_port() -> String {
    let loopback = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let socket = SocketAddr::new(loopback.into(), 0);
    let listener = TcpListener::bind(socket).await.expect("Failed to bind to address");
    let available_port = listener.local_addr().expect("Failed to get local address").port();
    format!("[::1]:{}", available_port)
}

impl OperationalNode {
    pub fn new(config: ServerConfig) -> Self {
        let logger = tracing::info_span!("OperationalNode", listen_addr = %config.listen_addr);
        OperationalNode {
            config,
            logger,
            peer_lock: RwLock::new(()),
            peers: RwLock::new(HashMap::new()),
            mempool: Mutex::new(Mempool::new()),
        }
    }

    pub async fn start(mut config: ServerConfig, bootstrap_nodes: Vec<String>) -> Result<(), Error> {
        let listen_addr = get_available_port().await;
        config.listen_addr = listen_addr;
        let node = Arc::new(Self::new(config.clone()));
        let addr = config.listen_addr.parse().unwrap();
        let node_server = NodeServer::new(OperationalNodeArc(node.clone()));
        let _logger_guard = node.logger.enter();
        info!("Node started on {}", config.listen_addr);
        if !bootstrap_nodes.is_empty() {
            tokio::spawn(node.clone().bootstrap_network(bootstrap_nodes));
        }
        if node.config.keypair.optional_private.is_some() {
            tokio::spawn(node.clone().validator_loop());
        }
        Server::builder().add_service(node_server).serve(addr).await?;
        Ok(())
    }

    pub async fn validator_loop(self: Arc<Self>) {
        let _logger_guard = self.logger.enter();
        let mut interval = interval(Duration::from_secs(5));
        info!(
            "Starting validator loop, pubkey: {:?}, blockTime: {:?}",
            self.config.keypair.public,
            Duration::from_secs(5)
        );
        loop {
            interval.tick().await;
            let mut mempool_guard = self.mempool.lock().await;
            let txx = mempool_guard.clear().await;
            println!("Time to create a new block, lenTx: {}", txx.len());
        }
    }

    pub async fn broadcast(&self, msg: BroadcastMsg) -> Result<(), Error> {
        let peers = self.peers.read().await;
        let peer_keys: Vec<Arc<Mutex<NodeClient<Channel>>>> = peers
            .keys()
            .cloned()
            .map(|wrapper| wrapper.client.clone())
            .collect();
        for peer in peer_keys {
            match msg {
                BroadcastMsg::Transaction(ref tx) => {
                    let _ = peer.lock().await.handle_transaction(Request::new(tx.clone())).await?;
                }
            }
        }
        Ok(())
    }

    #[async_recursion]
    pub async fn add_peer(self: Arc<Self>, c: NodeClient<Channel>, v: Version) {
        let _logger_guard = self.logger.enter();
        let mut peers = self.peers.write().await;
        peers.insert(
            NodeClientWrapper {
                client: Arc::new(Mutex::new(c)),
            },
            v.clone(),
        );
        let peer_list = v.msg_peer_list.clone();
        let node_clone = self.clone();
        if let Err(e) = node_clone.bootstrap_network(peer_list).await {
            eprintln!("Error while bootstrapping network: {}", e);
        }
    }

    pub async fn delete_peer(&self, c: &NodeClient<Channel>) {
        let mut peers = self.peers.write().await;
        peers.remove(&NodeClientWrapper { client: Arc::new(Mutex::new(c.clone())) });
    }

    pub async fn bootstrap_network(
        self: Arc<Self>,
        bootstrap_nodes: Vec<String>,
    ) -> Result<(), anyhow::Error> {
        for node in &bootstrap_nodes {
            let addr: SocketAddr = node.parse()?;
            match self.dial_remote_node(&addr).await {
                Ok((c, v)) => {
                    self.add_peer(c, v).await; // No changes required here
                    break;
                }
                Err(e) => log::error!("Failed to connect to bootstrap node {}: {:?}", node, e),
            }
        }
        Ok(())
    }

    pub async fn dial_remote_node(&self, addr: &SocketAddr) -> Result<(NodeClient<Channel>, Version), Box<dyn std::error::Error + Send + Sync>> {
        let addr_string = addr.to_string();
        let mut c = make_node_client(addr_string).await?;
        let version = self.get_version().await;
        let v = c.handshake(version).await?.into_inner();
        Ok((c, v))
    }

    pub async fn get_version(&self) -> Version {
        Version {
            msg_version: "saturn-0.0.0.1".to_string(),
            msg_height: 0,
            msg_listen_address: self.config.listen_addr.clone(),
            msg_peer_list: self.get_peer_list().await,
        }
    }

    pub async fn can_connect_with(&self, addr: &str) -> bool {
        if self.config.listen_addr == addr {
            return false;
        }
        let connected_peers = self.get_peer_list().await; // Add .await here
        for connected_addr in connected_peers {
            if addr == connected_addr {
                return false;
            }
        }
        true
    }

    pub async fn get_peer_list(&self) -> Vec<String> {
        let _guard = self.peer_lock.read().await;
        self.peers
            .read()
            .await
            .values()
            .map(|version| version.msg_listen_address.clone())
            .collect()
    }
}

#[tonic::async_trait]
impl Node for OperationalNodeArc {
    async fn handshake(&self, request: Request<Version>) -> Result<Response<Version>, Status> {
        let v = request.into_inner();
        let c = make_node_client(v.msg_listen_address.clone()).await.unwrap();
        let add_peer_task = self.0.clone().add_peer(c, v.clone());
        tokio::spawn(add_peer_task);
        Ok(Response::new(self.0.get_version().await))
    }

    async fn handle_transaction(&self, request: Request<Transaction>) -> Result<Response<Confirmed>, Status> {
        let peer = request.remote_addr().unwrap();
        let tx = request.into_inner();
        let hash = encode(hash_transaction(&tx));
        if self.0.mempool.lock().await.add(&tx).await {
            println!("Received tx from {} with hash {} (we are {})", peer, hash, self.0.config.listen_addr);
            let node_clone = Arc::clone(&self.0);
            tokio::spawn(async move {
                if let Err(e) = node_clone.broadcast(BroadcastMsg::Transaction(tx)).await {
                    println!("Broadcast error: {}", e);
                }
            });
        }
        Ok(Response::new(Confirmed::default()))
    }
}


pub async fn make_node_client(listen_addr: String) -> Result<NodeClient<Channel>, Box<dyn std::error::Error + Send + Sync>> {
    let uri = listen_addr.parse::<Uri>()?;
    let channel: Channel = Endpoint::new(uri)?.connect().await?;
    Ok(NodeClient::new(channel))
}

#[derive(Clone)]
pub struct NodeClientWrapper {
    pub client: Arc<Mutex<NodeClient<Channel>>>,
}

impl PartialEq for NodeClientWrapper {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.client, &other.client)
    }
}

impl Eq for NodeClientWrapper {}

impl Hash for NodeClientWrapper {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let address = Arc::as_ptr(&self.client) as *const _ as usize;
        address.hash(state);
    }
}

////////////////////////////////////////////////////////////////
// use tracing_subscriber::FmtSubscriber;

// fn main() {
//     let subscriber = FmtSubscriber::builder()
//         .with_max_level(tracing::Level::INFO)
//         .finish();

//     tracing::subscriber::set_global_default(subscriber)
//         .expect("Setting initial tracing subscriber failed");

//     // ...
// }
////////////////////////////////////////////////////////////////
