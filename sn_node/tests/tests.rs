use sn_node::node::*;
use std::sync::{Arc};
use sn_proto::messages::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction};

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



// start(), validator_tick(), broadcast(), add_peer(), delete_peer(), dial_remote_node(), and bootstrap_network()