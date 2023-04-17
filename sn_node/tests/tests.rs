use sn_node::node::*;
use std::sync::{Arc, Mutex};
use sn_proto::messages::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction};
use tokio::runtime::Runtime;
use std::thread;
use std::time::Duration;
use tonic::{Request};
use tokio::sync::{ oneshot};

fn create_test_server_config() -> ServerConfig {
    let version = "1.0.0".to_string();
    let server_listen_addr = "127.0.0.1:8080".to_string();
    let keypair = Some(Arc::new(Keypair::generate_keypair()));

    ServerConfig {
        version,
        server_listen_addr,
        keypair,
    }
}

pub fn create_random_transaction() -> Transaction {
    let keypair = Keypair::generate_keypair();
    let input = TransactionInput {
        msg_previous_tx_hash: (0..64).map(|_| rand::random::<u8>()).collect(),
        msg_previous_out_index: rand::random::<u32>(),
        msg_public_key: keypair.public.to_bytes().to_vec(),
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
async fn test_mempool() {
    let mempool = Mempool::new();

    // Test empty mempool
    assert_eq!(mempool.len().await, 0);

    // Generate a sample transaction
    let tx = create_random_transaction();

    // Test adding a transaction
    assert!(mempool.add(tx.clone()).await);
    assert_eq!(mempool.len().await, 1);

    // Test adding a duplicate transaction
    assert!(!mempool.add(tx.clone()).await);
    assert_eq!(mempool.len().await, 1);

    // Test clearing the mempool
    let cleared = mempool.clear().await;
    assert_eq!(mempool.len().await, 0);
    assert_eq!(cleared.len(), 1);
}

#[test]
fn test_server_config() {
    let version = "1.0.0".to_string();
    let server_listen_addr = "127.0.0.1:8080".to_string();
    let keypair = Some(Arc::new(Keypair::generate_keypair()));

    let server_config = ServerConfig {
        version: version.clone(),
        server_listen_addr: server_listen_addr.clone(),
        keypair: keypair.clone(),
    };

    assert_eq!(server_config.version, version);
    assert_eq!(server_config.server_listen_addr, server_listen_addr);
    assert_eq!(server_config.keypair.as_ref().unwrap().public, keypair.as_ref().unwrap().public);
}

#[tokio::test]
async fn test_node_service_new() {
    let server_config = create_test_server_config();
    let node_service = NodeService::new(server_config.clone());

    assert!(node_service.peer_lock.read().await.is_empty());
    assert_eq!(node_service.mempool.len().await, 0);
}

#[tokio::test]
async fn test_node_service_get_version() {
    let server_config = create_test_server_config();
    let node_service = NodeService::new(server_config.clone());

    let version = node_service.get_version().await;

    assert_eq!(version.msg_version, "blocker-0.1");
    assert_eq!(version.msg_height, 0);
    assert_eq!(version.msg_listen_address, server_config.server_listen_addr);
    assert!(version.msg_peer_list.is_empty());
}

#[tokio::test]
async fn test_node_service_can_connect_with() {
    let server_config = create_test_server_config();
    let node_service = NodeService::new(server_config.clone());

    let same_addr = &server_config.server_listen_addr;
    assert!(!node_service.can_connect_with(same_addr).await);

    let unconnected_addr = "127.0.0.1:8081";
    assert!(node_service.can_connect_with(unconnected_addr).await);
}

#[test]
fn test_start_stage_1() {
    let rt = Arc::new(Mutex::new(Runtime::new().unwrap()));
    let bootstrap_nodes = vec![];
    let server_config = create_test_server_config();
    println!("Server configurated successfully");
    let listen_addr = server_config.server_listen_addr.clone();
    println!("listen_addr: {:?}", listen_addr);
    let mut node_service = NodeService::new(server_config);
    println!("NodeServise created successfully");
    let rt_clone = Arc::clone(&rt);
    let node_handle = thread::spawn(move || {
        let rt_guard = rt_clone.lock().unwrap();
        rt_guard.block_on(async {
            println!("Starting the NodeService");
            node_service.start(&listen_addr, bootstrap_nodes).await.unwrap();
        })
    });
    // Give the node some time to start
    thread::sleep(Duration::from_secs(2));
    // Perform any test or assertions here, such as checking if the node is reachable
    // Dropping the runtime will cause the node to shut down
    drop(rt);
    // Wait for the node to shut down gracefully
    node_handle.join().unwrap();
}

#[test]
fn test_start_stage_2() {
    let rt = Arc::new(Mutex::new(Runtime::new().unwrap()));
    let bootstrap_nodes = vec![];

    let server_config = create_test_server_config();
    println!("Server configurated successfully");

    let listen_addr = server_config.server_listen_addr.clone();
    println!("listen_addr: {:?}", listen_addr);

    let mut node_service = NodeService::new(server_config);
    println!("NodeServise created successfully");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let rt_clone = Arc::clone(&rt);
    let node_handle = thread::spawn(move || {
        let rt_guard = rt_clone.lock().unwrap();
        rt_guard.block_on(async {
            tokio::select! {
                _ = node_service.start(&listen_addr, bootstrap_nodes) => {},
                _ = shutdown_rx => {
                    println!("Received shutdown signal");
                },
            }
        });
    });

    // Give the node some time to start
    thread::sleep(Duration::from_secs(2));

    // Perform any test or assertions here, such as checking if the node is reachable

    // Send the shutdown signal
    shutdown_tx.send(()).unwrap();

    // Wait for the node to shut down gracefully
    node_handle.join().unwrap();
}

#[tokio::test]
async fn test_start_stage_3() {
    let rt = Arc::new(Mutex::new(Runtime::new().unwrap()));
    let bootstrap_nodes = vec![];
    let server_config = create_test_server_config();
    println!("Server configurated successfully");
    let listen_addr = server_config.server_listen_addr.clone();
    println!("listen_addr: {:?}", listen_addr);
    let mut node_service = NodeService::new(server_config);
    println!("NodeService created successfully");
    let rt_clone = Arc::clone(&rt);
    let listen_addr_clone = listen_addr.clone();
    let node_handle = thread::spawn(move || {
        let rt_guard = rt_clone.lock().unwrap();
        rt_guard.block_on(async {
            println!("Starting the NodeService");
            node_service.start(&listen_addr_clone, bootstrap_nodes).await.unwrap();
        })
    });
    // Give the node some time to start
    thread::sleep(Duration::from_secs(2));
    // Create a gRPC client
    let mut node_client = make_node_client(&listen_addr).await.unwrap();
    // Perform a handshake with the NodeService
    let version = Version {
        msg_version: "test-1".to_string(),
        msg_height: 0,
        msg_listen_address: listen_addr.to_string(),
        msg_peer_list: vec![],
    };
    let response = node_client.handshake(Request::new(version)).await.unwrap();
    // Check if the response is OK by comparing the received version with the sent version
    let received_version = response.into_inner();
    assert_eq!(received_version.msg_version, "test-1");
    assert_eq!(received_version.msg_height, 0);
    assert_eq!(received_version.msg_listen_address, "127.0.0.1:8080");
    assert_eq!(received_version.msg_peer_list, vec!["127.0.0.1:8080".to_string()]);
    // Perform any other test or assertions here
    // Dropping the runtime will cause the node to shut down
    drop(node_client);
    drop(rt);
    // Wait for the node to shut down gracefully
    node_handle.join().unwrap();
}

#[tokio::test]
async fn test_start_stage_4() {
    let rt = Arc::new(Mutex::new(Runtime::new().unwrap()));
    let bootstrap_nodes = vec![];
    let server_config = create_test_server_config();
    println!("Server configurated successfully");
    let listen_addr = server_config.server_listen_addr.clone();
    println!("listen_addr: {:?}", listen_addr);
    let mut node_service = NodeService::new(server_config);
    println!("NodeService created successfully");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let rt_clone = Arc::clone(&rt);
    let listen_addr_clone = listen_addr.clone();
    let node_handle = thread::spawn(move || {
        let rt_guard = rt_clone.lock().unwrap();
        rt_guard.block_on(async {
            println!("Starting the NodeService");
            let node_shutdown = async {
                tokio::select! {
                    _ = node_service.start(&listen_addr_clone, bootstrap_nodes) => {}
                    _ = shutdown_rx => {}
                }
            };
            node_shutdown.await;
        })
    });

    // Give the node some time to start
    thread::sleep(Duration::from_secs(2));

    // Create a gRPC client
    let mut node_client = make_node_client(&listen_addr).await.unwrap();

    // Perform a handshake with the NodeService
    let version = Version {
        msg_version: "test-1".to_string(),
        msg_height: 0,
        msg_listen_address: listen_addr.to_string(),
        msg_peer_list: vec![],
    };
    let response = node_client.handshake(Request::new(version)).await.unwrap();

    // Check if the response is OK by comparing the received version with the sent version
    let received_version = response.into_inner();
    assert_eq!(received_version.msg_version, "test-1");
    assert_eq!(received_version.msg_height, 0);
    assert_eq!(received_version.msg_listen_address, "127.0.0.1:8080");
    assert_eq!(received_version.msg_peer_list, vec!["127.0.0.1:8080".to_string()]);

    // Perform any other test or assertions here

    // Whenever you want to shut down the NodeService, call the shutdown function
    let shutdown_result = shutdown(shutdown_tx).await;
    assert!(shutdown_result.is_ok(), "Failed to shut down NodeService");

    // Dropping the runtime will cause the node to shut down
    drop(node_client);
    drop(rt);

    // Wait for the node to shut down gracefully
    node_handle.join().unwrap();
}


// start(), validator_tick(), broadcast(), add_peer(), delete_peer(), dial_remote_node(), and bootstrap_network()