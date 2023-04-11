use sn_node::node::*;
use sn_proto::messages::*;
use std::sync::{Arc};
use sn_cryptography::cryptography::Keypair;
use tokio::runtime::Runtime;
use tonic::{Request, Response, Status};
use std::time::Duration;

pub const BLOCK_TIME: Duration = Duration::from_secs(10);

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
    println!("Operational node listening on port: {}", config.listen_addr);
    let operational_node = OperationalNode::new(config);
    let peer_count = operational_node.peers.read().await.len();
    assert_eq!(peer_count, 0, "Unexpected peer count: {}", peer_count);
}

#[test]
fn test_mempool() {
    let mut mempool = Mempool::new();
    let initial_len = Runtime::new().unwrap().block_on(mempool.len());
    if initial_len != 0 {
        format!("Unexpected mempool initial length: {}", initial_len);
        assert_eq!(initial_len, 0, "Unexpected mempool initial length: {}", initial_len);
    }
    let tx = create_random_transaction();
    let has_tx = Runtime::new().unwrap().block_on(mempool.has(&tx));
    if has_tx {
        panic!("Transaction unexpectedly found in mempool");
    } 
    let added = Runtime::new().unwrap().block_on(mempool.add(&tx));
    if !added {
        panic!("Transaction not added to mempool");
    }  
    let has_tx_after_add = Runtime::new().unwrap().block_on(mempool.has(&tx));
    if !has_tx_after_add {
        panic!("Transaction not found in mempool after adding");
    }  
    let len_after_add = Runtime::new().unwrap().block_on(mempool.len());
    if len_after_add != 1 {
        format!("Unexpected mempool length after adding transaction: {}", len_after_add);
        assert_eq!(len_after_add, 1, "Unexpected mempool length after adding transaction: {}", len_after_add);
    } 
    let cleared_txs = Runtime::new().unwrap().block_on(mempool.clear());
    if cleared_txs.len() != 1 {
        format!("Unexpected cleared transactions count: {}", cleared_txs.len());
        assert_eq!(cleared_txs.len(), 1, "Unexpected cleared transactions count: {}", cleared_txs.len());
    }
    let len_after_clear = Runtime::new().unwrap().block_on(mempool.len());
    if len_after_clear != 0 {
        format!("Unexpected mempool length after clearing: {}", len_after_clear);
        assert_eq!(len_after_clear, 0, "Unexpected mempool length after clearing: {}", len_after_clear);
    }
}

#[tokio::test]
async fn test_add_and_delete_peer() {
    let config = create_test_config().await;
    println!("Operational node listening on port: {}", config.listen_addr);
    let operational_node = Arc::new(OperationalNode::new(config));
    let peer_config = create_test_config().await;
    let peer_node = Arc::new(OperationalNode::new(peer_config.clone()));
    println!("Peer node listening on port: {}", peer_config.listen_addr);
    let peer_node_client_result = make_node_client(peer_config.listen_addr).await;
    match peer_node_client_result {
        Ok(peer_node_client) => {
            let peer_version = peer_node.get_version().await;
            operational_node.clone().add_peer(peer_node_client.clone(), peer_version).await;
            let peer_count = operational_node.peers.read().await.len();
            if peer_count != 1 {
                format!("Unexpected peer count: {}", peer_count);
            }
            operational_node.delete_peer(&peer_node_client).await;
            let peer_count_after_delete = operational_node.peers.read().await.len();
            if peer_count_after_delete != 0 {
                format!("Unexpected peer count after delete: {}", peer_count_after_delete);
            }
        },
        Err(e) => {
            format!("Make node client error: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_broadcast_transaction() {
    let config = create_test_config().await;
    println!("Operational node listening on port: {}", config.listen_addr);
    let operational_node = Arc::new(OperationalNode::new(config));
    let peer_config = create_test_config().await;
    println!("Peer node listening on port: {}", peer_config.listen_addr);
    let peer_node = Arc::new(OperationalNode::new(peer_config.clone()));
    let peer_node_url = format!("http://localhost:{}", peer_config.listen_addr);
    let peer_node_client_result = make_node_client(peer_node_url).await;
    match peer_node_client_result {
        Ok(peer_node_client) => {
            let peer_version = peer_node.get_version().await;
            operational_node.clone().add_peer(peer_node_client.clone(), peer_version).await;
            let tx = create_random_transaction();
            let broadcast_result = operational_node.broadcast(BroadcastMsg::Transaction(tx.clone())).await;
            match broadcast_result {
                Ok(_) => {
                    assert!(peer_node.mempool.lock().await.has(&tx).await);
                },
                Err(e) => {
                    format!("Broadcast error: {:?}", e);
                }
            }
        },
        Err(e) => {
            format!("Make node client error: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_broadcast_transaction_with_urls() {
    let _ = tracing_subscriber::fmt::try_init();

    // Create and start the first node
    let mut config1 = create_test_config().await;
    let bootstrap_nodes1 = vec![];
    let node1_handle = tokio::spawn(async move {
        OperationalNode::start(config1, bootstrap_nodes1).await.unwrap();
    });

    // Create and start the second node
    let mut config2 = create_test_config().await;
    let bootstrap_nodes2 = vec![config1.listen_addr.clone()];
    let node2_handle = tokio::spawn(async move {
        OperationalNode::start(config2, bootstrap_nodes2).await.unwrap();
    });

    // Give the nodes time to start and establish connections
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Create NodeClient instances for both nodes
    let node1_client = make_node_client(config1.listen_addr.clone()).await.unwrap();
    let node2_client = make_node_client(config2.listen_addr.clone()).await.unwrap();

    // Create a transaction and broadcast it using the first node
    let tx = Transaction {
        msg_version: 1,
        msg_inputs: vec![],
        msg_outputs: vec![
            TransactionOutput {
                msg_amount: 1,
                msg_address: b"B".to_vec(),
            },
        ],
    };
    node1_client
        .handle_transaction(Request::new(tx.clone()))
        .await
        .unwrap();

    // Give the transaction some time to propagate
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Check if the transaction was received by the second node
    let mempool_tx = node2_client
        .mempool_state(Request::new(Empty {}))
        .await
        .unwrap()
        .into_inner()
        .transactions
        .into_iter()
        .find(|transaction| transaction == &tx);
    assert!(mempool_tx.is_some(), "Transaction not found in mempool");

    // Stop the nodes
    node1_handle.abort();
    node2_handle.abort();
}

// #[tokio::test]
// async fn test_broadcast_transaction_using_start() {
//     let mut config = create_test_config().await;
//     let mut peer_config = create_test_config().await;
    
//     let operational_node_handle = tokio::spawn(async move {
//         let _ = OperationalNode::start(config, vec![]).await;
//     });
    
//     let peer_node_handle = tokio::spawn(async move {
//         let _ = OperationalNode::start(peer_config, vec![]).await;
//     });

//     // Give nodes some time to start
//     tokio::time::sleep(Duration::from_secs(2)).await;

//     let operational_node_url = format!("http://localhost:{}", config.listen_addr);
//     let peer_node_url = format!("http://localhost:{}", peer_config.listen_addr);

//     let operational_node_client_result = make_node_client(operational_node_url).await;
//     let peer_node_client_result = make_node_client(peer_node_url).await;

//     if let (Ok(operational_node_client), Ok(peer_node_client)) = (operational_node_client_result, peer_node_client_result) {
//         let peer_version = peer_node_client.get_version(Request::new(())).await.unwrap().into_inner();
//         operational_node_client.add_peer(Request::new(peer_version)).await.unwrap();
        
//         let tx = create_random_transaction();
//         let broadcast_result = operational_node_client.broadcast(Request::new(tx.clone())).await;

//         match broadcast_result {
//             Ok(_) => {
//                 let peer_node_mempool = peer_node_client.get_mempool(Request::new(())).await.unwrap().into_inner();
//                 assert!(peer_node_mempool.transactions.contains(&tx));
//             },
//             Err(e) => {
//                 format!("Broadcast error: {:?}", e);
//             }
//         }
//     } else {
//         format!("Make node client error: failed to create node clients");
//     }

//     operational_node_handle.abort();
//     peer_node_handle.abort();
// }