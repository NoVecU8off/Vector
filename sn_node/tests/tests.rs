use sn_node::node::*;
use sn_proto::messages::*;
use std::sync::{Arc};
use sn_cryptography::cryptography::Keypair;
use tokio::time::{timeout, Instant};
use tokio::runtime::Runtime;
use std::time::Duration;

pub const BLOCK_TIME: Duration = Duration::from_secs(10);

async fn create_test_config() -> ServerConfig {
    let keypair = Keypair::generate_keypair();
    let listen_addr = get_available_port().await;
    ServerConfig {
        version: "saturn-0.0.0.1".to_string(),
        listen_addr,
        keypair,
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

#[test]
fn test_mempool_add_and_has() {
    let rt = Runtime::new().unwrap();
    let mut mempool = Mempool::new();
    let tx = create_random_transaction();

    // Check if the mempool initially does not have the transaction
    let has_tx = rt.block_on(mempool.has(&tx));
    assert_eq!(has_tx, false);

    // Add the transaction to the mempool
    let added = rt.block_on(mempool.add(&tx));
    assert_eq!(added, true);

    // Check if the mempool has the transaction now
    let has_tx = rt.block_on(mempool.has(&tx));
    assert_eq!(has_tx, true);
}

#[test]
fn test_mempool_len() {
    let rt = Runtime::new().unwrap();
    let mut mempool = Mempool::new();
    let tx = create_random_transaction();

    // Check the initial length of the mempool
    let len = rt.block_on(mempool.len());
    assert_eq!(len, 0);

    // Add the transaction to the mempool
    rt.block_on(mempool.add(&tx));

     // Check the length of the mempool after adding the transaction
     let len = rt.block_on(mempool.len());
    assert_eq!(len, 1);
}

#[test]
fn test_mempool_clear() {
    let rt = Runtime::new().unwrap();
    let mut mempool = Mempool::new();
    let tx = create_random_transaction();

    // Add the transaction to the mempool
    rt.block_on(mempool.add(&tx));

    // Clear the mempool
    let cleared_txs = rt.block_on(mempool.clear());
    assert_eq!(cleared_txs.len(), 1);
    assert_eq!(cleared_txs[0], tx);

    // Check if the mempool is empty now
    let len = rt.block_on(mempool.len());
    assert_eq!(len, 0);
}

#[tokio::test]
async fn test_create_operational_node() {
    let config = create_test_config().await;
    println!("Operational node listening on port: {}", config.listen_addr);
    
    let (server_status_sender, _) = tokio::sync::mpsc::channel::<bool>(1);
    
    let operational_node = OperationalNode::new(config, server_status_sender);
    
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
    let (server_status_sender, _) = tokio::sync::mpsc::channel(1);
    let operational_node = Arc::new(OperationalNode::new(config, server_status_sender));
    let peer_config = create_test_config().await;
    let (peer_server_status_sender, _) = tokio::sync::mpsc::channel(1);
    let peer_node = Arc::new(OperationalNode::new(peer_config.clone(), peer_server_status_sender));
    println!("Peer node listening on port: {}", peer_config.listen_addr);
    let peer_node_client_result = make_node_client(peer_config.listen_addr).await;
    match peer_node_client_result {
        Ok(peer_node_client) => {
            let peer_version = peer_node.get_version().await;
            operational_node.clone().add_peer(peer_node_client.clone(), peer_version).await;
            let peer_count = operational_node.peers.read().await.len();
            assert_eq!(peer_count, 1, "Unexpected peer count: {}", peer_count);
            operational_node.delete_peer(&peer_node_client).await;
            let peer_count_after_delete = operational_node.peers.read().await.len();
            assert_eq!(peer_count_after_delete, 0, "Unexpected peer count after delete: {}", peer_count_after_delete);
        },
        Err(e) => {
            panic!("Make node client error: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_broadcast_transaction() {
    let config = create_test_config().await;
    println!("Operational node listening on port: {}", config.listen_addr);
    let (server_status_sender, _) = tokio::sync::mpsc::channel(1);
    let operational_node = Arc::new(OperationalNode::new(config, server_status_sender));
    let peer_config = create_test_config().await;
    println!("Peer node listening on port: {}", peer_config.listen_addr);
    let (peer_server_status_sender, _) = tokio::sync::mpsc::channel(1);
    let peer_node = Arc::new(OperationalNode::new(peer_config.clone(), peer_server_status_sender));
    let peer_node_url = format!("http://localhost:{}", peer_config.listen_addr.split(':').last().unwrap());
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
                    panic!("Broadcast error: {:?}", e);
                }
            }
        },
        Err(e) => {
            panic!("Make node client error: {:?}", e);
        }
    }
}


#[tokio::test]
async fn test_start() {
    let config = create_test_config().await;
    println!("Operational node listening on port: {}", config.listen_addr);
    let (server_status_sender, mut server_status_receiver) = tokio::sync::mpsc::channel(1);
    let operational_node = Arc::new(OperationalNode::new(config, server_status_sender));
    let bootstrap_nodes = vec![];
    let operational_node_clone = operational_node.clone();
    let server_handle = tokio::spawn(async move {
        OperationalNode::start(operational_node_clone.config.clone(), bootstrap_nodes).await.unwrap();
    });

    let mut is_listening = false;
    let start_time = Instant::now();
    while !is_listening && start_time.elapsed() < Duration::from_secs(5) {
        is_listening = operational_node.is_listening(&mut server_status_receiver).await;
        println!("Is the server listening? {}", is_listening);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(is_listening, "Server should be in the listening state");
    
    let result = timeout(Duration::from_secs(5), server_handle).await;
    assert!(result.is_err(), "Server should still be running");
}


#[tokio::test]
async fn test_dial_remote_node_and_get_peer_list() {
    let config1 = create_test_config().await;
    println!("Operational node listening on port: {}", config1.listen_addr);
    let (server_status_sender1, mut server_status_receiver1) = tokio::sync::mpsc::channel(1);
    let operational_node1 = Arc::new(OperationalNode::new(config1, server_status_sender1));
    let config2 = create_test_config().await;
    println!("Operational node listening on port: {}", config2.listen_addr);
    let (server_status_sender2, mut server_status_receiver2) = tokio::sync::mpsc::channel(1);
    let operational_node2 = Arc::new(OperationalNode::new(config2, server_status_sender2));
    let addr2 = operational_node2.config.listen_addr.parse().unwrap();
    let bootstrap_nodes = Vec::new();
    let bootstrap_nodes_clone = bootstrap_nodes.clone();
    let node1_clone = operational_node1.clone();
    let node1_handle = tokio::spawn(async move {
        OperationalNode::start(node1_clone.config.clone(), bootstrap_nodes_clone).await.unwrap();
    });
    let node2_clone = operational_node2.clone();
    let node2_handle = tokio::spawn(async move {
        OperationalNode::start(node2_clone.config.clone(), bootstrap_nodes.clone()).await.unwrap();
    });
    while !operational_node1.is_listening(&mut server_status_receiver1).await || !operational_node2.is_listening(&mut server_status_receiver2).await {
        println!(
            "Node 1 listening: {}, Node 2 listening: {}",
            operational_node1.is_listening(&mut server_status_receiver1).await,
            operational_node2.is_listening(&mut server_status_receiver2).await
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert!(
        operational_node1.can_connect_with(&operational_node2.config.listen_addr).await,
        "Should be able to connect"
    );
    let (client, _) = operational_node1.dial_remote_node(&addr2).await.unwrap();
    operational_node1.clone().add_peer(client, operational_node2.get_version().await).await;
    let peer_list = operational_node1.get_peer_list().await;
    assert_eq!(peer_list.len(), 1, "There should be one connected peer");
    assert_eq!(
        peer_list[0], operational_node2.config.listen_addr,
        "Connected peer should be node2"
    );
    node1_handle.await.unwrap();
    node2_handle.await.unwrap();
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