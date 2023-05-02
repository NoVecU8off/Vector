use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_transaction::transaction::*;
use sn_mempool::mempool::*;
use sn_server::server::*;
use std::{collections::{HashMap}, sync::{Arc}, time::{Duration}};
use std::net::SocketAddr;
use tonic::{transport::{Server, Channel, ClientTlsConfig, ServerTlsConfig, Identity, Certificate}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use slog::{o, Drain, Logger, info, error};
use anyhow::{Context, Result};

#[derive(Clone)]
pub enum Message {
    Transaction(Transaction),
    TransactionBatch(TransactionsBatch),
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
        let hash = hex::encode(hash_transaction(&tx).await);
        if self.mempool.add(tx).await {
            info!(self.logger, "\n{}: received transaction: {}", self.server_config.cfg_addr, hash);
            let self_clone = self.self_ref.as_ref().unwrap().clone();
            tokio::spawn(async move {
                if let Err(_err) = self_clone.collect_and_broadcast_transactions(Message::Transaction(tx_clone)).await {
                }
            });
        }
        Ok(Response::new(Confirmed {}))
    }
    
    async fn handle_transactions_batch(
        &self,
        request: Request<TransactionsBatch>,
    ) -> Result<Response<Confirmed>, Status> {
        let request_inner = request.get_ref().clone();
        let txb = request_inner;
        let txb_clone = txb.clone();
        let hashes = hash_transactions_batch(&txb).await;
        let hashes_str = hashes
            .into_iter()
            .map(|hash| hex::encode(hash))
            .collect::<Vec<_>>()
            .join(", ");
        
        if self.mempool.add_batch(txb).await {
            info!(self.logger, "\n{}: received transactions: {}", self.server_config.cfg_addr, hashes_str);
            let self_clone = self.self_ref.as_ref().unwrap().clone();
            tokio::spawn(async move {
                if let Err(_err) = self_clone.collect_and_broadcast_transactions(Message::TransactionBatch(txb_clone)).await {
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

    pub async fn broadcast_batch(&self, messages: Vec<Message>) -> Result<()> {
        let peers_data = {
            let peers = self.peer_lock.read().await;
            peers
                .iter()
                .map(|(addr, (peer_client, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let messages_clone = messages.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                for msg in messages_clone {
                    match msg {
                        Message::Transaction(tx) => {
                            let tx_clone = tx.clone();
                            let mut req = Request::new(tx_clone.clone());
                            req.metadata_mut().insert("peer", addr.parse().unwrap());
                            if addr != self_clone.server_config.cfg_addr {
                                if let Err(err) = peer_client_lock.handle_transaction(req).await {
                                    error!(
                                        self_clone.logger,
                                        "Failed to broadcast transaction {} to {}: {:?}",
                                        hex::encode(hash_transaction(&tx_clone).await),
                                        addr,
                                        err
                                    );
                                } else {
                                    info!(
                                        self_clone.logger,
                                        "\n{}: broadcasted transaction \n {} \nto \n {}",
                                        self_clone.server_config.cfg_addr,
                                        hex::encode(hash_transaction(&tx_clone.clone()).await),
                                        addr
                                    );
                                }
                            }
                        }
                        Message::TransactionBatch(txb) => {
                            let txb_clone = txb.clone();
                            let mut req = Request::new(txb_clone.clone());
                            req.metadata_mut().insert("peer", addr.parse().unwrap());
                            if addr != self_clone.server_config.cfg_addr {
                                if let Err(err) = peer_client_lock.handle_transactions_batch(req).await {
                                    error!(
                                        self_clone.logger,
                                        "Failed to broadcast transactions batch to {}: {:?}",
                                        addr,
                                        err
                                    );
                                } else {
                                    info!(
                                        self_clone.logger,
                                        "\n{}: broadcasted transactions batch to \n {}",
                                        self_clone.server_config.cfg_addr,
                                        addr
                                    );
                                }
                            }
                        }
                    }
                }
            });
            tasks.push(task);
        }
        for task in tasks {
            task.await?;
        }
        Ok(())
    }

    pub async fn collect_and_broadcast_transactions(
        &self,
        message: Message,
    ) -> Result<()> {
        match message {
            Message::Transaction(tx) => {
                self.broadcast_batch(vec![Message::Transaction(tx)]).await
            }
            Message::TransactionBatch(txb) => {
                self.broadcast_batch(vec![Message::TransactionBatch(txb)]).await
            }
        }
    }
    
    pub async fn bootstrap_network(&self, addrs: Vec<String>) -> Result<()> {
        let mut tasks = Vec::new();
        for addr in addrs {
            if !self.can_connect_with(&addr).await {
                continue;
            }
            let node_service_clone = self.clone();
            let addr_clone = addr.clone();
            let task = tokio::spawn(async move {
                match node_service_clone.dial_remote_node(&addr_clone).await {
                    Ok((c, v)) => {
                        node_service_clone.add_peer(c, v).await;
                        info!(node_service_clone.logger, "\n{}: bootstrapped node: {}", node_service_clone.server_config.cfg_addr, addr_clone);
                    }
                    Err(e) => {
                        error!(node_service_clone.logger, "Error dialing remote node {}: {:?}", addr_clone, e);
                    }
                }
            });
            tasks.push(task);
        }
        for task in tasks {
            task.await?;
        }
        Ok(())
    }

    pub async fn can_connect_with(&self, addr: &str) -> bool {
        if self.server_config.cfg_addr == addr {
            return false;
        }
        let connected_peers = self.get_peer_list().await;
        let addr_owned = addr.to_owned();
        let check_tasks: Vec<_> = connected_peers
            .into_iter()
            .map(|connected_addr| {
                let addr_clone = addr_owned.clone();
                tokio::spawn(async move { addr_clone == connected_addr })
            })
            .collect();
        let results = futures::future::join_all(check_tasks).await;
        !results.into_iter().any(|res| res.unwrap_or(false))
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