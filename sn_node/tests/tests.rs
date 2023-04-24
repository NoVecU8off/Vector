use sn_node::node::*;
use std::sync::{Arc, Mutex};
use sn_proto::messages::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction};
use tokio::runtime::Runtime;
use std::thread;
use std::time::Duration;
use tonic::{Request};
use tokio::sync::{oneshot};

pub fn create_random_transaction() -> Transaction {
    let cfg_keypair = Keypair::generate_keypair();
    let input = TransactionInput {
        msg_previous_tx_hash: (0..64).map(|_| rand::random::<u8>()).collect(),
        msg_previous_out_index: rand::random::<u32>(),
        msg_public_key: cfg_keypair.public.to_bytes().to_vec(),
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

#[tokio::test]
async fn test_node_service_new() {
    let server_config = ServerConfig::new().await;
    let node_service = NodeService::new(server_config.clone());

    assert!(node_service.peer_lock.read().await.is_empty());
    assert_eq!(node_service.mempool.len().await, 0);
}

#[tokio::test]
async fn test_node_service_get_version() {
    let server_config = ServerConfig::new().await;
    let node_service = NodeService::new(server_config.clone());

    let cfg_version = node_service.get_version().await;

    assert_eq!(cfg_version.msg_version, "test-1");
    assert_eq!(cfg_version.msg_height, 0);
    assert_eq!(cfg_version.msg_listen_address, server_config.cfg_addr);
    assert!(cfg_version.msg_peer_list.is_empty());
}

#[tokio::test]
async fn test_node_service_can_connect_with() {
    let server_config = ServerConfig::new().await;
    let node_service = NodeService::new(server_config.clone());

    let same_addr = &server_config.cfg_addr;
    assert!(!node_service.can_connect_with(same_addr).await);

    let unconnected_addr = "127.0.0.1:8081";
    assert!(node_service.can_connect_with(unconnected_addr).await);
}

#[tokio::test]
async fn test_start_stage_3() {
    let rt = Arc::new(Mutex::new(Runtime::new().unwrap()));
    let bootstrap_nodes = vec![];
    let server_config = ServerConfig::new().await;
    let server_certificate = server_config.clone().cfg_certificate;
    println!("Server configurated successfully");
    let listen_addr = server_config.cfg_addr.clone();
    println!("listen_addr: {:?}", listen_addr);
    let mut node_service = NodeService::new(server_config);
    println!("NodeService created successfully");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let rt_clone = Arc::clone(&rt);
    let node_handle = thread::spawn(move || {
        let rt_guard = rt_clone.lock().unwrap();
        rt_guard.block_on(async {
            println!("Starting the NodeService");
            let node_shutdown = async {
                tokio::select! {
                    _ = node_service.start(bootstrap_nodes) => {}
                    _ = shutdown_rx => {}
                }
            };
            node_shutdown.await;
        })
    });
    let (client_cert_pem, client_key_pem) = generate_ssl_self_signed_cert_and_key().await.expect("Failed to create client certificate and key");
    let mut node_client = make_node_client(&listen_addr, &server_certificate, &client_cert_pem, &client_key_pem).await.expect("Failed to create NodeClient");
    let cfg_version = Version {
        msg_version: "test-1".to_string(),
        msg_height: 0,
        msg_listen_address: listen_addr.to_string(),
        msg_peer_list: vec![],
    };
    let response = node_client.handshake(Request::new(cfg_version)).await.unwrap();
    let received_version = response.into_inner();
    assert_eq!(received_version.msg_version, "test-1");
    assert_eq!(received_version.msg_height, 0);
    assert_eq!(received_version.msg_listen_address, "127.0.0.1:8080");
    assert_eq!(received_version.msg_peer_list, vec!["127.0.0.1:8080".to_string()]);
    let shutdown_result = shutdown(shutdown_tx).await;
    assert!(shutdown_result.is_ok(), "Failed to shut down NodeService");
    drop(node_client);
    drop(rt);
    node_handle.join().unwrap();
}

#[tokio::test]
async fn test_start_stage_4() {
    let rt = Arc::new(Mutex::new(Runtime::new().unwrap()));
    let bootstrap_nodes = vec![];
    let server_config = ServerConfig::new().await;
    let server_certificate = server_config.clone().cfg_certificate;
    let listen_addr = server_config.clone().cfg_addr;
    let mut node_service = NodeService::new(server_config);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let rt_clone = Arc::clone(&rt);
    let node_handle = thread::spawn(move || {
        let rt_guard = rt_clone.lock().unwrap();
        rt_guard.block_on(async {
            let node_shutdown = async {
                tokio::select! {
                    _ = node_service.start(bootstrap_nodes) => {}
                    _ = shutdown_rx => {}
                }
            };
            node_shutdown.await;
        })
    });
    thread::sleep(Duration::from_secs(2));
    let (client_certificate, client_key_pem) = generate_ssl_self_signed_cert_and_key().await.expect("Failed to create client certificate and key");
    let mut node_client = make_node_client(&listen_addr, &server_certificate, &client_certificate, &client_key_pem).await.expect("Failed to create NodeClient");
    let cfg_version = Version {
        msg_version: "test-1".to_string(),
        msg_height: 0,
        msg_listen_address: listen_addr.to_string(),
        msg_peer_list: vec![],
    };
    let response = node_client.handshake(Request::new(cfg_version)).await.unwrap();
    let received_version = response.into_inner();
    assert_eq!(received_version.msg_version, "test-1");
    assert_eq!(received_version.msg_height, 0);
    assert_eq!(received_version.msg_listen_address, listen_addr);
    assert_eq!(received_version.msg_peer_list, vec![listen_addr.to_string()]);
    let shutdown_result = shutdown(shutdown_tx).await;
    assert!(shutdown_result.is_ok(), "Failed to shut down NodeService");
    drop(node_client);
    drop(rt);
    node_handle.join().unwrap();
}


#[tokio::test]
async fn test_validator_tick() {
    let server_config = ServerConfig::new().await;
    let node_service = NodeService::new(server_config);
    let transaction1 = create_random_transaction();
    let transaction2 = create_random_transaction();
    node_service.mempool.add(transaction1).await;
    node_service.mempool.add(transaction2).await;
    node_service.validator_tick().await;
    let mempool_len = node_service.mempool.len().await;
    assert_eq!(mempool_len, 0, "Mempool is not empty after validator_tick");
}

#[tokio::test]
async fn test_add_delete_peer_async() {
    let mut server_config_1 = ServerConfig::new().await;
    server_config_1.cfg_addr = "168.0.0.2:8080".to_string();
    let server_config_2 = ServerConfig::new().await;
    let mut node_service_1 = NodeService::new(server_config_1);
    let mut node_service_2 = NodeService::new(server_config_2);
    node_service_1.self_ref = Some(Arc::new(node_service_1.clone()));
    node_service_2.self_ref = Some(Arc::new(node_service_2.clone()));
    let node_service_1_clone = node_service_1.clone();
    let node_service_2_clone = node_service_2.clone();
    tokio::spawn(async move {
        node_service_1_clone.clone().start(vec![]).await.unwrap();
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    tokio::spawn(async move {
        node_service_2_clone.clone().start(vec![]).await.unwrap();
    });
    let (client, cfg_version) = node_service_1
        .dial_remote_node(&node_service_2.server_config.cfg_addr)
        .await
        .unwrap();
    node_service_1.add_peer(client, cfg_version).await;
    let peer_list_before = node_service_1.get_peer_list().await;
    println!("Peer list before deletion: {:?}", peer_list_before);
    assert_eq!(peer_list_before.len(), 1);
    assert_eq!(peer_list_before[0], "127.0.0.1:8088");
    node_service_1.delete_peer(&node_service_2.server_config.cfg_addr).await;
    let peer_list_after = node_service_1.get_peer_list().await;
    println!("Peer list after deletion: {:?}", peer_list_after);
    assert_eq!(peer_list_after.len(), 0);
}

#[tokio::test]
async fn test_dial_remote_node() {
    let node_service_1 = NodeService::new(ServerConfig::new().await);
    let node_service_2 = NodeService::new(ServerConfig::new().await);
    let node_service_1_clone = node_service_1.clone();
    let node_service_2_clone = node_service_2.clone();
    tokio::spawn(async move {
        node_service_1
            .clone()
            .start(vec![])
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    tokio::spawn(async move {
        node_service_2
            .clone()
            .start(vec![])
            .await
            .unwrap();
    });
    let (_client, cfg_version) = node_service_1_clone
        .dial_remote_node(&node_service_2_clone.server_config.cfg_addr)
        .await
        .unwrap();
    assert_eq!(
        cfg_version.msg_listen_address,
        node_service_2_clone.server_config.cfg_addr,
        "Remote node cfg_version should have the correct listen address"
    );
    assert_eq!(
        cfg_version.msg_version,
        "test-1",
        "Remote node cfg_version should match the expected cfg_version"
    );
}

#[tokio::test]
async fn test_bootstrap_network() {
    let mut node1 = NodeService::new(ServerConfig::new().await);
    let node1_clone = node1.clone();
    let mut node2 = NodeService::new(ServerConfig::new().await);
    let (shutdown_tx1, shutdown_rx1) = oneshot::channel();
    let (shutdown_tx2, shutdown_rx2) = oneshot::channel();
    tokio::spawn(async move {
        node1.start(vec![]).await.unwrap();
        let _ = shutdown_rx1.await;
    });
    tokio::spawn(async move {
        node2.start(vec![]).await.unwrap();
        let _ = shutdown_rx2.await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    node1_clone.bootstrap_network(vec!["127.0.0.1:8088".to_string()]).await.unwrap();
    let peer_list = node1_clone.get_peer_list().await;
    assert_eq!(peer_list, vec!["127.0.0.1:8088"]);
    let _ = shutdown(shutdown_tx1).await;
    let _ = shutdown(shutdown_tx2).await;
}