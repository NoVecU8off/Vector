use crate::validator::*;
use sn_proto::messages::*;
use sn_proto::messages::{node_client::NodeClient, node_server::{NodeServer, Node}};
use sn_chain::chain::Chain;
use sn_store::store::{MemoryBlockStore, BlockStorer, MemoryTXStore, TXStorer};
use sn_mempool::mempool::*;
use sn_server::server::*;
use std::{collections::HashMap, sync::Arc, net::SocketAddr};
use tonic::{transport::{Server, Channel, ClientTlsConfig, ServerTlsConfig, Identity, Certificate}, Status, Request, Response};
use tokio::sync::{Mutex, RwLock};
use anyhow::{Context, Result};
use futures::future::try_join_all;
use slog::{o, Logger, info, Drain, error};

#[derive(Clone)]
pub struct NodeService {
    pub server_config: ServerConfig,
    pub peer_lock: Arc<RwLock<HashMap<String, (Arc<Mutex<NodeClient<Channel>>>, Version, bool)>>>,
    pub validator: Option<Arc<ValidatorService>>,
    pub logger: Logger,
}

#[tonic::async_trait]
impl Node for NodeService {
    async fn handshake(
        &self,
        request: Request<Version>,
    ) -> Result<Response<Version>, Status> {
        info!(self.logger, "Starting handshaking");
        let version = request.into_inner();
        let version_clone = version.clone();
        let addr = version.msg_listen_address;
        info!(self.logger, "Recieved version, address: {}", addr);
        match make_node_client(&addr).await {
            Ok(c) => {
                info!(self.logger, "Created node client successfully");
                if version_clone.msg_validator {
                    self.add_peer(c, version_clone.clone(), version_clone.msg_validator).await;
                }
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
        if let Some(validator) = &self.validator {
            validator.handle_transaction(request).await
        } else {
            Err(Status::unimplemented("Node is not a validator (transaction-handling process)"))
        }
    }

    async fn handle_agreement(
        &self,
        request: Request<HashAgreement>,
    ) -> Result<Response<Agreement>, Status> {
        if let Some(validator) = &self.validator {
            validator.handle_agreement(request).await
        } else {
            Err(Status::internal("Node is not a validator (agreement process)"))
        }
    }

    async fn handle_vote(
        &self,
        request: Request<Vote>,
    ) -> Result<Response<Confirmed>, Status> {
        if let Some(validator) = &self.validator {
            validator.handle_vote(request).await
        } else {
            Err(Status::internal("Node is not a validator (voting process)"))
        }
    }

    async fn handle_block(
        &self,
        request: Request<Block>,
    ) -> Result<Response<Confirmed>, Status> {
        if let Some(validator) = &self.validator {
            validator.handle_block(request).await
        } else {
            Err(Status::internal("Node is not a validator (synchronisation process)"))
        }
    }
}

impl NodeService {
    pub async fn new(cfg: ServerConfig) -> Self {
        let logger = {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!())
        };
        info!(logger, "NodeService {} created", cfg.cfg_addr);
        let peer_lock = Arc::new(RwLock::new(HashMap::new()));
        let block_storer: Box<dyn BlockStorer> = Box::new(MemoryBlockStore::new());
        let tx_storer: Box<dyn TXStorer> = Box::new(MemoryTXStore::new());
        let chain = match Chain::new_chain(block_storer, tx_storer).await {
            Ok(chain) => Arc::new(RwLock::new(chain)),
            Err(e) => panic!("Failed to create chain: {:?}", e),
        };
        let node_service = NodeService {
            server_config: cfg.clone(),
            peer_lock: Arc::clone(&peer_lock),
            validator: None,
            logger: logger.clone(),
        };
        let validator = if cfg.cfg_is_validator {
            let validator = ValidatorService {
                validator_id: 0,
                node_service: Arc::new(node_service.clone()),
                mempool: Arc::new(Mempool::new()),
                round_transactions: Arc::new(Mutex::new(Vec::new())),
                created_block: Arc::new(Mutex::new(None)),
                agreement_count: Arc::new(Mutex::new(0)),
                vote_count: Arc::new(Mutex::new(HashMap::new())),
                received_responses_count: Arc::new(Mutex::new(0)),
                chain: Arc::clone(&chain),
                trigger_sender: Arc::new(Mutex::new(None)),
            };
            Some(Arc::new(validator))
        } else {
            None
        };
        NodeService {
            server_config: cfg,
            peer_lock,
            validator,
            logger,
        }
    }    

    pub async fn start(&mut self, nodes_to_bootstrap: Vec<String>) -> Result<()> {
        let node_service = self.clone();
        let addr = format!("{}", self.server_config.cfg_addr)
            .parse()
            .unwrap();
        info!(self.logger, "NodeServer {} starting listening", self.server_config.cfg_addr);
        self.setup_server(node_service, addr).await.unwrap();
        if !nodes_to_bootstrap.is_empty() {
            self.bootstrap(nodes_to_bootstrap).await.unwrap();
        }
        if self.server_config.cfg_is_validator {
            if let Some(validator) = &self.validator {
                validator.initialize_validating().await;
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
                error!(self.logger, "Error listening for incoming connections: {:?}", err);
                err
            }).unwrap())
    }

    pub async fn broadcast_transaction(&self, transaction: Transaction) -> Result<()> {
        let peers_data = {
            let peers = self.peer_lock.read().await;
            peers
                .iter()
                .filter(|(_, (_, _, is_validator))| *is_validator)
                .map(|(addr, (peer_client, _, _))| (addr.clone(), Arc::clone(peer_client)))
                .collect::<Vec<_>>()
        };
        let mut tasks = Vec::new();
        for (addr, peer_client) in peers_data {
            let transaction_clone = transaction.clone();
            let self_clone = self.clone();
            let task = tokio::spawn(async move {
                let mut peer_client_lock = peer_client.lock().await;
                let req = Request::new(transaction_clone.clone());
                if addr != self_clone.server_config.cfg_addr {
                    if let Err(e) = peer_client_lock.handle_transaction(req).await {
                        error!(self_clone.logger, "{}: Broadcast error: {:?}", self_clone.server_config.cfg_addr, e)
                    } else {
                        info!(self_clone.logger, "{}: Broadcasted tx to: {:?}", self_clone.server_config.cfg_addr, addr)
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.unwrap();
        Ok(())
    }
    
    pub async fn bootstrap(&self, unbootstraped_nodes: Vec<String>) -> Result<()> {
        let node_clone = self.clone();
        info!(self.logger, "{}: bootstrapping network with nodes: {:?}", self.server_config.cfg_addr, unbootstraped_nodes);
        tokio::spawn(async move {
            if let Err(e) = node_clone.bootstrap_network(unbootstraped_nodes).await {
                error!(node_clone.logger, "{}: Failed to bootstrap: {:?}", node_clone.server_config.cfg_addr, e);
            }
        });
        Ok(())
    }
    
    pub async fn add_peer(&self, c: NodeClient<Channel>, v: Version, is_validator: bool) {
        if !is_validator {
            return;
        }
        let mut peers = self.peer_lock.write().await;
        let remote_addr = v.msg_listen_address.clone();
        peers.insert(remote_addr.clone(), (Arc::new(c.into()), v.clone(), is_validator));
        info!(self.logger, "{}: new validator peer added: {}", self.server_config.cfg_addr, remote_addr);
    }
    
    pub async fn delete_peer(&self, addr: &str) {
        let mut peers = self.peer_lock.write().await;
        if peers.remove(addr).is_some() {
            info!(self.logger, "{}: peer removed: {}", self.server_config.cfg_addr, addr);
        }
    }

    pub async fn get_peer_list(&self) -> Vec<String> {
        let peers = self.peer_lock.read().await;
        peers.values().map(|(_, version, _)| version.msg_listen_address.clone()).collect()
    }

    pub async fn dial_remote_node(&self, addr: &str) -> Result<(NodeClient<Channel>, Version)> {
        let mut c = make_node_client(addr)
            .await
            .map_err(|err| {
                error!(self.logger, "{}: Failed to make node client: {:?}", self.server_config.cfg_addr, err);
                err
            })
            .context("Failed to create node for dial").unwrap();
        let v = c
            .handshake(Request::new(self.get_version().await))
            .await
            .map_err(|err| {
                error!(self.logger, "{}: Failed to perform handshake with remote node: {:?}", self.server_config.cfg_addr, err);
                err
            })
            .unwrap()
            .into_inner();
        info!(self.logger, "{}: Dialed remote node: {}", self.server_config.cfg_addr, addr);
        Ok((c, v))
    }

    pub async fn get_version(&self) -> Version {
        let keypair = &self.server_config.cfg_keypair;
        let msg_public_key = keypair.public.to_bytes().to_vec();
        let msg_validator_id = match &self.validator {
            Some(validator_service) => validator_service.validator_id,
            None => 10101010,
        };
        Version {
            msg_validator: self.server_config.cfg_is_validator,
            msg_version: self.server_config.cfg_version.clone(),
            msg_public_key,
            msg_height: 0,
            msg_listen_address: self.server_config.cfg_addr.clone(),
            msg_peer_list: self.get_peer_list().await,
            msg_validator_id,
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
                        let is_validator = v.msg_validator;
                        node_service_clone.add_peer(c, v, is_validator).await;
                    }
                    Err(e) => {
                        error!(node_service_clone.logger, "{}: Failed bootstrap and dial: {:?}", node_service_clone.server_config.cfg_addr, e);
                    }
                }
            });
            tasks.push(task);
        }
        try_join_all(tasks).await.unwrap();
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