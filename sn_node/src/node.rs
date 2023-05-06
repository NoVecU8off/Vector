use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_transaction::transaction::*;
use sn_mempool::mempool::*;
use sn_server::server::*;
use std::{collections::{HashMap}, sync::{Arc}};
use std::net::SocketAddr;
use tonic::{transport::{Server, Channel, ClientTlsConfig, ServerTlsConfig, Identity, Certificate}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use log::{info, error};
use anyhow::{Context, Result};
use crate::validator::*;

#[derive(Clone, Debug)]
pub struct NodeService {
    pub server_config: ServerConfig,
    pub peer_lock: Arc<RwLock<HashMap<String, (Arc<Mutex<NodeClient<Channel>>>, Version)>>>,
    pub mempool: Arc<Mempool>,
    pub is_validator: bool,
    pub validator: Option<Arc<Validator>>,
    pub self_ref: Option<Arc<NodeService>>,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(
        &self,
        request: Request<Version>,
    ) -> Result<Response<Version>, Status> {
        info!("\nStarting handshaking");
        let version = request.into_inner();
        let version_clone = version.clone();
        let addr = version.msg_listen_address;
        info!("\nRecieved version, address: {}", addr);
        match make_node_client(&addr).await {
            Ok(c) => {
                info!("Created node client successfully");
                self.add_peer(c, version_clone).await;
                let reply = self.get_version().await;
                info!("Returning version: {:?}", reply);
                Ok(Response::new(reply))
            }
            Err(e) => {
                error!("Failed to create node client: {:?}", e);
                Err(Status::internal("Failed to create node client"))
            }
        }
    }
    
    async fn handle_transactions(
        &self,
        request: Request<TransactionBatch>,
    ) -> Result<Response<Confirmed>, Status> {
        let request_inner = request.get_ref().clone();
        let txb = request_inner;
        let transactions = txb.transactions.clone();
        let hashes = hash_transactions_batch(&txb).await;
        let hashes_str = hashes
            .iter()
            .map(|hash| hex::encode(hash))
            .collect::<Vec<_>>()
            .join(", ");
        if self.mempool.add_batch(txb.clone()).await {
            info!("\n{}: received transactions: {}", self.server_config.cfg_addr, hashes_str);
            let self_clone = self.self_ref.as_ref().unwrap().clone();
            let transactions_clone = transactions.clone();
            tokio::spawn(async move {
                if let Err(_err) = self_clone.collect_and_broadcast_transactions(transactions_clone).await {
                }
            });
            if self.is_validator {
                if let Some(validator) = &self.validator {
                    for hash in hashes {
                        validator.generate_poh_entry(Some(hash)).await;
                    }
                }
            }
        }
        Ok(Response::new(Confirmed {}))
    }

    async fn handle_votes(
        &self,
        request: Request<VoteBatch>,
    ) -> Result<Response<Confirmed>, Status> {
        if let Some(validator) = &self.validator {
            let vote_batch = request.into_inner();
            let mut tower = validator.tower.lock().await;
            for vote in vote_batch.votes {
                validator.process_vote(&vote, &mut *tower).await;
            }
            Ok(Response::new(Confirmed {}))
        } else {
            error!("Node is not a validator, cannot handle votes");
            Err(Status::internal("Node is not a validator, cannot handle votes"))
        }
    }
}

impl NodeService {
    pub fn new(cfg: ServerConfig) -> Self {
        info!("\nNodeService {} created", cfg.cfg_addr);
        let node_service = NodeService {
            server_config: cfg,
            peer_lock: Arc::new(RwLock::new(HashMap::new())),
            mempool: Arc::new(Mempool::new()),
            is_validator: true,
            validator: None,
            self_ref: None,
        };
        let mut arc_node_service = Arc::new(node_service);
        if arc_node_service.is_validator {
            let tower = Arc::new(Mutex::new(Tower { locks: HashMap::new() })); // Initialize Tower
            let validator = Validator {
                validator_id: 0,
                poh_sequence: Arc::new(Mutex::new(Vec::<PoHEntry>::new())),
                node_service: Arc::clone(&arc_node_service),
                tower: Arc::clone(&tower),
            };
            if let Some(node_service_mut) = Arc::get_mut(&mut arc_node_service) {
                node_service_mut.validator = Some(Arc::new(validator));
            }
        }
        Arc::try_unwrap(arc_node_service).unwrap_or_else(|_| panic!("NodeService creation failed"))
    }

    pub async fn start(&mut self, nodes_to_bootstrap: Vec<String>) -> Result<()> {
        let node_service = self.clone();
        let addr = format!("{}", self.server_config.cfg_addr)
            .parse()
            .unwrap();
        info!("\nNodeServer {} starting listening", self.server_config.cfg_addr);
        self.setup_server(node_service, addr).await?;
        if !nodes_to_bootstrap.is_empty() {
            self.bootstrap(nodes_to_bootstrap).await?;
        }
        if self.is_validator {
            if let Some(validator) = &self.validator {
                validator.start_poh_tick().await;
                validator.start_validator_tick().await;
            }
        }
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
                error!("Error listening for incoming connections: {:?}", err);
                err
            })?)
    }
    
    pub async fn bootstrap(&self, unbootstraped_nodes: Vec<String>) -> Result<()> {
        let node_clone = self.clone();
        info!("\n{}: bootstrapping network with nodes: {:?}", self.server_config.cfg_addr, unbootstraped_nodes);
        tokio::spawn(async move {
            if let Err(e) = node_clone.bootstrap_network(unbootstraped_nodes).await {
                error!("Error bootstrapping network: {:?}", e);
            }
        });
        Ok(())
    }
    
    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version) {
        let mut peers = self.peer_lock.write().await;
        let remote_addr = v.msg_listen_address.clone();
        peers.insert(remote_addr.clone(), (Arc::new(c.into()), v.clone()));
        info!("\n{}: new peer added: {}", self.server_config.cfg_addr, remote_addr);
    }
    
    pub async fn delete_peer(&self, addr: &str) {
        let mut peers = self.peer_lock.write().await;
        if peers.remove(addr).is_some() {
            info!("\n{}: peer removed: {}", self.server_config.cfg_addr, addr);
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
                error!("Failed to create node client: {:?}", err);
                err
            })
            .context("Failed to create node for dial")?;
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(|err| {
                error!("Failed to perform handshake with remote node: {:?}", err);
                err
            })
            .unwrap()
            .into_inner();
        info!("\n{}: dialed remote node: {}", self.server_config.cfg_addr, addr);
        Ok((c, v))
    }

    pub async fn get_version(&self) -> Version {
        let keypair = &self.server_config.cfg_keypair;
        let msg_public_key = keypair.public.to_bytes().to_vec();
        Version {
            msg_version: self.server_config.cfg_version.clone(),
            msg_public_key,
            msg_height: 0,
            msg_listen_address: self.server_config.cfg_addr.clone(),
            msg_peer_list: self.get_peer_list().await,
        }
    }

    pub async fn broadcast_batch(&self, transaction_batches: Vec<TransactionBatch>) -> Result<()> {
        let peers_data = {
            let peers = self.peer_lock.read().await;
            peers
                .iter()
                .map(|(addr, (peer_client, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let transactions_batches_clone = transaction_batches.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                for txb in transactions_batches_clone {
                    let txb_clone = txb.clone();
                    let mut req = Request::new(txb_clone.clone());
                    req.metadata_mut().insert("peer", addr.parse().unwrap());
                    if addr != self_clone.server_config.cfg_addr {
                        if let Err(err) = peer_client_lock.handle_transactions(req).await {
                            error!(
                                "Failed to broadcast transactions batch to {}: {:?}",
                                addr,
                                err
                            );
                        } else {
                            info!(
                                "\n{}: broadcasted transactions batch to \n {}",
                                self_clone.server_config.cfg_addr,
                                addr
                            );
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
        transactions: Vec<Transaction>,
    ) -> Result<()> {
        let transaction_batch = TransactionBatch { transactions };
        self.broadcast_batch(vec![transaction_batch]).await
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
                        info!("\n{}: bootstrapped node: {}", node_service_clone.server_config.cfg_addr, addr_clone);
                    }
                    Err(e) => {
                        error!("\n{}: Error dialing remote node {}: {:?}", node_service_clone.server_config.cfg_addr, addr_clone, e);
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