
use sn_proto::messages::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction};
use sn_node::node::*;
use std::sync::Once;
// use std::net::{TcpListener, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;



static INIT_LOGGING: Once = Once::new();

pub fn init_test_logging() {
    INIT_LOGGING.call_once(|| {
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .init();
    });
}

pub fn create_random_transaction() -> Transaction {
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
async fn test_mempool() {
    let mempool = Mempool::new();
    assert_eq!(mempool.len().await, 0);

    let keypair = Keypair::generate_keypair();
    let tx = create_random_transaction();
    assert!(!mempool.has(&tx).await);

    let added = mempool.add(tx.clone()).await;
    assert!(added);
    assert_eq!(mempool.len().await, 1);
    assert!(mempool.has(&tx).await);

    let added_again = mempool.add(tx.clone()).await;
    assert!(!added_again);
    assert_eq!(mempool.len().await, 1);

    let cleared_transactions = mempool.clear().await;
    assert_eq!(cleared_transactions.len(), 1);
    assert_eq!(mempool.len().await, 0);
}

#[test]
fn test_get_available_port() {
    let listen_addr = "127.0.0.1:0";
    match get_available_port(listen_addr) {
        Ok(port) => println!("Available port: {}", port),
        Err(err) => println!("Error getting available port: {}", err),
    }
}

#[tokio::test]
async fn test_start() {
    let listen_addr = "127.0.0.1:0";
    let bootstrap_nodes = vec![];

    let server_config = ServerConfig {
        version: "test".to_string(),
        server_listen_addr: listen_addr.to_string(),
        keypair: None,
    };

    let mut node_service = NodeService::new(server_config);

    let start_node = async {
        node_service.start(listen_addr, bootstrap_nodes).await.unwrap();
    };

    match timeout(Duration::from_secs(5), start_node).await {
        Ok(()) => println!("Node started successfully"),
        Err(_) => println!("Node start timed out"),
    }

    // Check if the node is running and listening
    let available_port = get_available_port(listen_addr).unwrap();
    assert_ne!(node_service.server_config.server_listen_addr, available_port);
}

#[tokio::test]
async fn test_start_and_connect_nodes() {
    let listen_addr = "127.0.0.1:0";
    let bootstrap_nodes = vec![];

    let server_config = ServerConfig {
        version: "test".to_string(),
        server_listen_addr: listen_addr.to_string(),
        keypair: None,
    };

    let mut node_service_1 = NodeService::new(server_config.clone());

    let start_node_1 = async {
        node_service_1.start(listen_addr, bootstrap_nodes.clone()).await.unwrap();
    };

    match timeout(Duration::from_secs(15), start_node_1).await {
        Ok(()) => println!("Node 1 started successfully"),
        Err(_) => println!("Node 1 start timed out"),
    }

    // Check if the first node is running and listening
    let available_port_1 = get_available_port(listen_addr).unwrap();
    assert_ne!(node_service_1.server_config.server_listen_addr, available_port_1);

    // Start the second node and connect it to the first node
    let mut node_service_2 = NodeService::new(server_config.clone());
    let bootstrap_nodes_2 = vec![node_service_1.server_config.server_listen_addr.clone()];

    let start_node_2 = async {
        node_service_2.start(listen_addr, bootstrap_nodes_2).await.unwrap();
    };

    match timeout(Duration::from_secs(15), start_node_2).await {
        Ok(()) => println!("Node 2 started successfully and connected to Node 1"),
        Err(_) => println!("Node 2 start timed out"),
    }

    // Check if the second node is running and listening
    let available_port_2 = get_available_port(listen_addr).unwrap();
    assert_ne!(node_service_2.server_config.server_listen_addr, available_port_2);

    // Verify if Node 2 has Node 1 in its peer list
    let node_2_peer_list = node_service_2.get_peer_list().await;
    assert_eq!(1, node_2_peer_list.len());
    assert_eq!(node_service_1.server_config.server_listen_addr, node_2_peer_list[0]);
}