use std::sync::{Arc};
use sn_proto::messages::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction};
use sn_node::node::*;
use log::info;
use std::sync::Once;
use anyhow::{Context, Error};
use std::net::{TcpListener, SocketAddr};

static INIT_LOGGING: Once = Once::new();

pub fn init_test_logging() {
    INIT_LOGGING.call_once(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .init();
    });
}

fn create_random_transaction() -> Transaction {
    let input = TransactionInput {
        msg_previous_tx_hash: (0..64).map(|_| rand::random::<u8>()).collect(),
        msg_previous_out_index: rand::random::<u32>(),
        msg_public_key: (0..32).map(|_| rand::random::<u8>()).collect(),
        msg_signature: vec![],
    };
    let output = TransactionOutput {
        msg_amount: rand::random::<i64>(),
        msg_address: (0..32).map(|_| rand::random::<u8>()).collect(),
    };
    Transaction {
        msg_version: rand::random::<i32>(),
        msg_inputs: vec![input],
        msg_outputs: vec![output],
    }
}

#[tokio::test]
async fn test_mempool_add() {
    let mempool = Mempool::new();
    let tx = create_random_transaction();
    assert_eq!(mempool.add(tx.clone()).await, true);
    assert_eq!(mempool.add(tx.clone()).await, false);
}

#[tokio::test]
async fn test_mempool_has() {
    let mempool = Mempool::new();
    let tx = create_random_transaction();
    assert_eq!(mempool.has(&tx).await, false);
    mempool.add(tx.clone()).await;
    assert_eq!(mempool.has(&tx).await, true);
}

#[tokio::test]
async fn test_mempool_clear() {
    let mempool = Mempool::new();
    let tx = create_random_transaction();
    mempool.add(tx.clone()).await;
    let cleared_transactions = mempool.clear().await;
    assert_eq!(cleared_transactions.len(), 1);
    assert_eq!(mempool.len().await, 0);
}

#[tokio::test]
async fn test_mempool_len() {
    let mempool = Mempool::new();
    let tx = create_random_transaction();
    assert_eq!(mempool.len().await, 0);
    mempool.add(tx.clone()).await;
    assert_eq!(mempool.len().await, 1);
}

#[tokio::test]
async fn test_node_service_new() {
    let server_config = ServerConfig {
        version: "1.0.0".to_string(),
        listen_addr: "127.0.0.1:8080".to_string(),
        keypair: None,
    };
    let node_service = NodeService::new(server_config.clone());
    assert_eq!(node_service.peer_lock.read().await.len(), 0);
    assert_eq!(node_service.mempool.len().await, 0);
}

pub fn test_get_available_port(addr: &str) -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind(addr)?;
    let local_addr = listener.local_addr()?;
    drop(listener);
    Ok(local_addr)
}

#[tokio::test]
async fn test_node_start() -> Result<(), Error> {
    init_test_logging();
    // Generate keypairs for the nodes
    let keypair1 = Arc::new(Keypair::generate_keypair());
    let keypair2 = Arc::new(Keypair::generate_keypair());
    // Obtain dynamic listening addresses for the nodes
    let listen_addr1 = get_available_port("127.0.0.1:0").context("Failed to get an available port for node 1")?;
    let listen_addr2 = get_available_port("127.0.0.1:0").context("Failed to get an available port for node 2")?;
    // Create server configurations for the nodes
    let server_config1 = ServerConfig {
        version: "blocker-0.1".to_string(),
        listen_addr: listen_addr1,
        keypair: Some(Arc::clone(&keypair1)),
    };
    let server_config2 = ServerConfig {
        version: "blocker-0.1".to_string(),
        listen_addr: listen_addr2,
        keypair: Some(Arc::clone(&keypair2)),
    };
    // Create NodeService instances for the nodes
    let mut node_service1 = NodeService::new(server_config1);
    let mut node_service2 = NodeService::new(server_config2);
    // Get actual listening addresses of the nodes
    let node1_listen_addr = node_service1.get_actual_listen_addr();
    let node2_listen_addr = node_service2.get_actual_listen_addr();
    info!("Node 1 address: {}", node1_listen_addr);
    info!("Node 2 address: {}", node2_listen_addr);
    // Start the first node
    info!("Starting node_service 1...");
    let bootstrap_nodes = vec![];
    let node1_listen_addr_clone = node1_listen_addr.clone();
    let node1_handle = tokio::spawn(async move {
        node_service1.start(&node1_listen_addr_clone, bootstrap_nodes).await?;
        Ok::<(), Error>(())
    });
    // Start the second node and connect to the first node
    info!("Starting node_service 2...");
    let bootstrap_nodes = vec![node1_listen_addr];
    let node2_handle = tokio::spawn(async move {
        node_service2.start(&node2_listen_addr, bootstrap_nodes).await?;
        Ok::<(), Error>(())
    });
    // Wait for nodes to start
    let _ = node1_handle.await??;
    let _ = node2_handle.await??;

    Ok(())
}



// #[tokio::test]
// async fn test_node_service_start() {
//     init_test_logging();
//     info!("Starting test_node_service_start...");
//     let server_config_1 = ServerConfig {
//         version: "1.0.0".to_string(),
//         listen_addr: "127.0.0.1:0".to_string(),
//         keypair: None,
//     };
//     let server_config_2 = ServerConfig {
//         version: "1.0.0".to_string(),
//         listen_addr: "127.0.0.1:0".to_string(),
//         keypair: None,
//     };
//     let mut node_service_1 = NodeService::new(server_config_1);
//     let mut node_service_2 = NodeService::new(server_config_2);
//     let node_service_1_listen_addr = node_service_1.server_config.listen_addr.clone();
//     info!("Node_service 1's listen_addr: {}", node_service_1_listen_addr);
//     let node_service_2_listen_addr = node_service_2.server_config.listen_addr.clone();
//     info!("Node_service 2's listen_addr: {}", node_service_2_listen_addr);
//     info!("Starting node_service 1...");
//     let node_service_1_start_future = node_service_1.start(&node_service_1_listen_addr, vec![]);
//     info!("Node_service 1's actual listen_addr: {}", node_service_1_actual_listen_addr);
//     let node_service_1_start_result = timeout(Duration::from_secs(10), node_service_1_start_future).await;
//     let node_service_1_actual_listen_addr = node_service_1.get_actual_listen_addr();
//     info!("Starting node_service 2...");
//     let node_service_2_start_future = node_service_2.start(&node_service_2_listen_addr, vec![node_service_1_actual_listen_addr]);
//     let node_service_2_start_result = timeout(Duration::from_secs(10), node_service_2_start_future).await;
//     info!("Starting 5 sec delay...");
//     tokio::time::sleep(std::time::Duration::from_secs(5)).await;
//     info!("Getting peer counts...");
//     let node_service_1_peer_count = node_service_1.peer_lock.read().await.len();
//     let node_service_2_peer_count = node_service_2.peer_lock.read().await.len();
//     info!("node_service_1_peer_count: {}, node_service_2_peer_count: {}", node_service_1_peer_count, node_service_2_peer_count);
//     assert_eq!(node_service_1_peer_count, 1);
//     assert_eq!(node_service_2_peer_count, 1);
// }
// #[tokio::test]
// async fn test_node_start() {
//     init_test_logging();
//     // Generate keypairs for the nodes
//     let keypair1 = Arc::new(Keypair::generate_keypair());
//     let keypair2 = Arc::new(Keypair::generate_keypair());
//     // Create server configurations for the nodes
//     let server_config1 = ServerConfig {
//         version: "blocker-0.1".to_string(),
//         listen_addr: "127.0.0.1:0".to_string(),
//         keypair: Some(Arc::clone(&keypair1)),
//     };
//     let server_config2 = ServerConfig {
//         version: "blocker-0.1".to_string(),
//         listen_addr: "127.0.0.1:0".to_string(),
//         keypair: Some(Arc::clone(&keypair2)),
//     };
//     // Create NodeService instances for the nodes
//     let mut node_service1 = NodeService::new(server_config1);
//     let mut node_service2 = NodeService::new(server_config2);
//     // Get actual listening addresses of the nodes
//     let node1_listen_addr = node_service1.get_actual_listen_addr();
//     let node2_listen_addr = node_service2.get_actual_listen_addr();
//     // Start the first node
//     info!("Starting node_service 1...");
//     let bootstrap_nodes = vec![];
//     let node1_listen_addr_clone = node1_listen_addr.clone();
//     let node1_handle = tokio::spawn(async move {
//         node_service1.start(&node1_listen_addr_clone, bootstrap_nodes).await.unwrap();
//     });
//     // Start the second node and connect to the first node
//     info!("Starting node_service 2...");
//     let bootstrap_nodes = vec![node1_listen_addr];
//     let node2_handle = tokio::spawn(async move {
//         node_service2.start(&node2_listen_addr, bootstrap_nodes).await.unwrap();
//     });
//     // Wait for nodes to start
//     let _ = node1_handle.await;
//     let _ = node2_handle.await;
// }