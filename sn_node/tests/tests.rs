use sn_node::node::*;
use sn_proto::messages::*;
use std::sync::{Arc};
use sn_cryptography::cryptography::Keypair;
use tokio::runtime::Runtime;

async fn create_test_config() -> ServerConfig {
    ServerConfig {
        version: "saturn-0.0.0.1".to_string(),
        listen_addr: get_available_port().await,
        keypair: Keypair::generate_keypair(),
    }
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
async fn test_create_operational_node() {
    let config = create_test_config().await;
    let operational_node = OperationalNode::new(config);
    assert_eq!(operational_node.peers.read().await.len(), 0);
}

#[test]
fn test_mempool() {
    let mut mempool = Mempool::new();
    assert_eq!(Runtime::new().unwrap().block_on(mempool.len()), 0);

    let tx = create_random_transaction();
    assert!(!Runtime::new().unwrap().block_on(mempool.has(&tx)));

    let added = Runtime::new().unwrap().block_on(mempool.add(&tx));
    assert!(added);
    assert!(Runtime::new().unwrap().block_on(mempool.has(&tx)));
    assert_eq!(Runtime::new().unwrap().block_on(mempool.len()), 1);

    let cleared_txs = Runtime::new().unwrap().block_on(mempool.clear());
    assert_eq!(cleared_txs.len(), 1);
    assert_eq!(Runtime::new().unwrap().block_on(mempool.len()), 0);
}

#[tokio::test]
async fn test_add_and_delete_peer() {
    let config = create_test_config().await;
    let operational_node = Arc::new(OperationalNode::new(config));

    let peer_config = create_test_config().await;
    let peer_node = Arc::new(OperationalNode::new(peer_config.clone()));
    let peer_node_client = make_node_client(peer_config.listen_addr).await.unwrap();
    let peer_version = peer_node.get_version().await;

    operational_node.clone().add_peer(peer_node_client.clone(), peer_version).await;
    assert_eq!(operational_node.peers.read().await.len(), 1);

    operational_node.delete_peer(&peer_node_client).await;
    assert_eq!(operational_node.peers.read().await.len(), 0);
}

#[tokio::test]
async fn test_broadcast_transaction() {
    let config = create_test_config().await;
    let operational_node = Arc::new(OperationalNode::new(config));

    let peer_config = create_test_config().await;
    let peer_node = Arc::new(OperationalNode::new(peer_config.clone()));
    let peer_node_url = format!("http://localhost:{}", peer_config.listen_addr);
    let peer_node_client = make_node_client(peer_node_url).await.unwrap();
    let peer_version = peer_node.get_version().await;

    operational_node.clone().add_peer(peer_node_client.clone(), peer_version).await;

    let tx = create_random_transaction();
    operational_node.broadcast(BroadcastMsg::Transaction(tx.clone())).await.unwrap();

    assert!(peer_node.mempool.lock().await.has(&tx).await);
}