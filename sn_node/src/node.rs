use std::{collections::{HashMap}, sync::{Arc}, time::{Duration}, any::{Any}};
use tonic::{transport::{Server, Channel, ClientTlsConfig}, Status, Request, Response};
use tonic::transport::ServerTlsConfig;
use tonic::transport::Identity;
use tonic::transport::Certificate;
use slog::{o, Drain, Logger, info, error};
use tokio::sync::{Mutex, RwLock};
use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_transaction::transaction::*;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use sn_mempool::mempool::*;
use sn_server::server::*;

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
        let hash = hex::encode(hash_transaction(&tx).await);
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
        self.setup_server(node_service, addr).await?;
        if !bootstrap_nodes.is_empty() {
            self.bootstrap(bootstrap_nodes).await?;
        }
        self.start_validator_tick().await;
        Ok(())
    }
    
    pub async fn setup_server(&self, node_service: NodeService, addr: SocketAddr) -> Result<()> {
        let server_tls_config = ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.server_config.cfg_pem_certificate, &self.server_config.cfg_pem_key))
            .client_ca_root(Certificate::from_pem(&self.server_config.cfg_root_crt))
            .client_auth_optional(true);
        Ok(Server::builder()
            .tls_config(server_tls_config)
            .unwrap()
            .accept_http1(true)
            .add_service(NodeServer::new(node_service))
            .serve(addr)
            .await
            .map_err(|err| {
                error!(self.logger, "Error listening for incoming connections: {:?}", err);
                err
            })?)
    }
    
    pub async fn bootstrap(&self, bootstrap_nodes: Vec<String>) -> Result<()> {
        let node_clone = self.clone();
        info!(self.logger, "\n{}: bootstrapping network with nodes: {:?}", self.server_config.cfg_addr, bootstrap_nodes);
        tokio::spawn(async move {
            if let Err(e) = node_clone.bootstrap_network(bootstrap_nodes).await {
                error!(node_clone.logger, "Error bootstrapping network: {:?}", e);
            }
        });
        Ok(())
    }
    
    pub async fn start_validator_tick(&self) {
        let node_clone = self.clone();
        tokio::spawn(async move {
            loop {
                node_clone.validator_tick().await;
            }
        });
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
                        error!(self.logger, "Failed to broadcast transaction {} to {}: {:?}", hex::encode(hash_transaction(tx).await), addr, err);
                        return Err(err.into());
                    } else {
                        info!(self.logger, "\n{}: broadcasted transaction \n {} \nto \n {}", self.server_config.cfg_addr, hex::encode(hash_transaction(tx).await), addr);
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
            .unwrap()
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
    let (cli_pem_certificate, cli_pem_key, cli_root) = read_client_certs_and_keys().await.unwrap();
    let uri = format!("https://{}", addr).parse().unwrap();
    let client_tls_config = ClientTlsConfig::new()
        .domain_name("cryptotron.test.com")
        .ca_certificate(Certificate::from_pem(cli_root))
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