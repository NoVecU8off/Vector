use std::sync::{Arc};
use std::time::Duration;
use tonic::Request;
use tokio::sync::{Mutex};
use tokio::runtime::Builder;
use sn_proto::messages::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction};
use sn_node::node::*;
use tokio::runtime::Runtime;
use tokio::time::{sleep};
use hex::encode;
use sn_transaction::transaction::*;


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
async fn test_mempool() {
    let mempool = Mempool::new();

    // Test the length of an empty mempool
    assert_eq!(mempool.len().await, 0);

    // Create a dummy transaction
    let tx = create_random_transaction();

    // Test adding the transaction to the mempool
    assert!(mempool.add(tx.clone()).await);

    // Test checking if the mempool contains the transaction
    assert!(mempool.has(&tx).await);

    // Test the length of the mempool after adding the transaction
    assert_eq!(mempool.len().await, 1);

    // Test clearing the mempool
    let cleared_transactions = mempool.clear().await;
    assert_eq!(cleared_transactions.len(), 1);
    assert_eq!(mempool.len().await, 0);
}

#[tokio::test]
async fn test_node_service() {
    let server_config = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12345".to_string(),
        keypair: None,
    };

    let node_service = NodeService::new(server_config.clone());

    // Test getting the initial peer list
    assert_eq!(node_service.get_peer_list().await.len(), 0);

    // Test the can_connect_with method
    assert!(!node_service.can_connect_with(&server_config.listen_addr).await);
    assert!(node_service.can_connect_with("127.0.0.1:12346").await);

    // Add more tests for methods such as start, validator_loop, etc.
}

#[test]
fn test_start() {
    let runtime = Builder::new_multi_thread()
        .worker_threads(4) // You can set the number of worker threads here
        .thread_stack_size(256 * 1024 * 1024) // Set the stack size to 4 MB (adjust as needed)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // let _ = env_logger::builder().is_test(true).try_init();
        let server_config = ServerConfig {
            version: "test_version".to_string(),
            listen_addr: "127.0.0.1:12345".to_string(),
            keypair: None,
        };
        let server_config_clone = server_config.clone();

        let mut node_service = NodeService::new(server_config.clone());
        let node_service_clone = node_service.clone();

        // Start the node in a separate task and give it a moment to start
        let start_node_task = tokio::spawn(async move {
            node_service.start(&server_config.listen_addr, vec![]).await.unwrap();
        });

        // Give the node a moment to start
        sleep(Duration::from_millis(500)).await;

        // Connect to the node
        let node_client_result = make_node_client(&server_config_clone.listen_addr).await;
        let mut node_client; // Declare the variable here
        match node_client_result {
            Ok(client) => {
                node_client = client;
            },
            Err(e) => {
                eprintln!("Error: {:?}", e);
                panic!("Failed to create node client");
            }
        }

        // Get the node's version using the handshake method
        let node_version_request = Request::new(node_service_clone.get_version().await);
        let node_version = node_client
            .handshake(node_version_request).await.unwrap().into_inner();
        assert_eq!(node_version.msg_version, server_config.version);

        // Shut down the node
        drop(node_client);
        start_node_task.abort();
    });
}


#[tokio::test]
async fn test_validator_loop() {
    let keypair = Arc::new(Keypair::generate_keypair());
    let server_config = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12345".to_string(),
        keypair: Some(keypair.clone()),
    };

    let node_service = NodeService::new(server_config.clone());

    // Clone node_service
    let node_service_clone = node_service.clone();

    // Start the validator loop in a separate task
    let validator_loop_task = tokio::spawn(async move {
        node_service.validator_loop().await;
    });

    // Create a dummy transaction
    let tx = create_random_transaction();

    // Add the transaction to the mempool
    node_service_clone.mempool.add(tx.clone()).await;

    // Sleep for a duration slightly longer than BLOCK_TIME
    sleep(BLOCK_TIME + Duration::from_millis(500)).await;

    // Check if the mempool is cleared
    assert_eq!(node_service_clone.mempool.len().await, 0);

    // Cancel the validator loop
    validator_loop_task.abort();
}


#[tokio::test]
async fn test_add_peer_and_delete_peer() {
    let server_config_1 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12345".to_string(),
        keypair: None,
    };

    let server_config_2 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12346".to_string(),
        keypair: None,
    };

    let node_service_1 = Arc::new(Mutex::new(NodeService::new(server_config_1.clone())));
    let node_service_2 = Arc::new(Mutex::new(NodeService::new(server_config_2.clone())));

    // Start both nodes
    let start_node_task_1 = tokio::spawn({
        let node_service_1 = node_service_1.clone();
        async move {
            node_service_1.lock().await.start(&server_config_1.listen_addr, vec![]).await.unwrap();
        }
    });

    let server_config_2_listen_addr = server_config_2.listen_addr.clone();
    let start_node_task_2 = tokio::spawn({
        let node_service_2 = node_service_2.clone();
        async move {
            node_service_2.lock().await.start(&server_config_2_listen_addr, vec![]).await.unwrap();
        }
    });

    // Give the nodes a moment to start
    sleep(Duration::from_millis(500)).await;

    // Connect node_service_1 to node_service_2
    let (node_client, version) = node_service_1.lock().await.dial_remote_node(&server_config_2.listen_addr).await.unwrap();

    // Add node_service_2 as a peer to node_service_1
    node_service_1.lock().await.add_peer(node_client.clone(), version.clone()).await;

    // Check if node_service_2 is a peer of node_service_1
    assert_eq!(node_service_1.lock().await.get_peer_list().await.len(), 1);
    assert!(node_service_1.lock().await.get_peer_list().await.contains(&server_config_2.listen_addr));

    // Delete the peer from node_service_1
    node_service_1.lock().await.delete_peer(&Arc::new(Mutex::new(node_client))).await;

    // Check if the peer is removed from node_service_1
    assert_eq!(node_service_1.lock().await.get_peer_list().await.len(), 0);

    // Shut down both nodes
    start_node_task_1.abort();
    start_node_task_2.abort();
}


#[tokio::test]
async fn test_get_peer_list() {
    let server_config_1 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12345".to_string(),
        keypair: None,
    };

    let server_config_2 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12346".to_string(),
        keypair: None,
    };

    let server_config_3 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12347".to_string(),
        keypair: None,
    };

    let node_service_1 = NodeService::new(server_config_1.clone());
    let mut node_service_2 = NodeService::new(server_config_2.clone());
    let mut node_service_3 = NodeService::new(server_config_3.clone());

    // Start all nodes
    let mut node_service_1_clone = node_service_1.clone();
    let start_node_task_1 = tokio::spawn(async move {
        node_service_1_clone.start(&server_config_1.listen_addr, vec![]).await.unwrap();
    });


    let server_config_2_listen_addr = server_config_2.listen_addr.clone();
    let start_node_task_2 = tokio::spawn(async move {
        node_service_2.start(&server_config_2_listen_addr, vec![]).await.unwrap();
    });

    let server_config_3_listen_addr = server_config_3.listen_addr.clone();
    let start_node_task_3 = tokio::spawn(async move {
        node_service_3.start(&server_config_3_listen_addr, vec![]).await.unwrap();
    });

    // Give the nodes a moment to start
    sleep(Duration::from_millis(500)).await;

    // Connect node_service_1 to node_service_2 and node_service_3
    let (node_client_2, version_2) = node_service_1.dial_remote_node(&server_config_2.listen_addr).await.unwrap();
    let (node_client_3, version_3) = node_service_1.dial_remote_node(&server_config_3.listen_addr).await.unwrap();

    // Add node_service_2 and node_service_3 as peers to node_service_1
    node_service_1.add_peer(node_client_2.clone(), version_2.clone()).await;
    node_service_1.add_peer(node_client_3.clone(), version_3.clone()).await;

    // Get the peer list for node_service_1
    let peer_list = node_service_1.get_peer_list().await;

    // Check if the peer list contains the expected addresses
    assert_eq!(peer_list.len(), 2);
    assert!(peer_list.contains(&server_config_2.listen_addr));
    assert!(peer_list.contains(&server_config_3.listen_addr));

    // Shut down all nodes
    start_node_task_1.abort();
    start_node_task_2.abort();
    start_node_task_3.abort();
}

#[tokio::test]
async fn test_broadcast() {
    let server_config_1 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12345".to_string(),
        keypair: None,
    };

    let server_config_2 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12346".to_string(),
        keypair: None,
    };

    let server_config_3 = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12347".to_string(),
        keypair: None,
    };

    let node_service_1 = Arc::new(Mutex::new(NodeService::new(server_config_1.clone())));
    let node_service_2 = Arc::new(Mutex::new(NodeService::new(server_config_2.clone())));
    let node_service_3 = Arc::new(Mutex::new(NodeService::new(server_config_3.clone())));

    let node_addr_1 = server_config_1.listen_addr.clone();
    let node_addr_1_clone = node_addr_1.clone();
    let start_node_task_1 = tokio::spawn({
        let node_service_1 = node_service_1.clone();
        async move {
            node_service_1.lock().await.start(&node_addr_1, vec![]).await.unwrap();
        }
    });

    let node_addr_2 = server_config_2.listen_addr.clone();
    let start_node_task_2 = tokio::spawn({
        let node_service_2 = node_service_2.clone();
        async move {
            node_service_2.lock().await.start(&node_addr_2, vec![node_addr_1_clone]).await.unwrap();
        }
    });

    let node_addr_3 = server_config_3.listen_addr.clone();
    let node_addr_1_clone = server_config_1.listen_addr.clone();
    let start_node_task_3 = tokio::spawn({
        let node_service_3 = node_service_3.clone();
        async move {
            node_service_3.lock().await.start(&node_addr_3, vec![node_addr_1_clone]).await.unwrap();
        }
    });

    // Give the nodes a moment to start
    sleep(Duration::from_millis(500)).await;

    // Connect node_service_1 to node_service_2
    let (node_client, version) = node_service_1.lock().await.dial_remote_node(&server_config_2.listen_addr).await.unwrap();
    node_service_1.lock().await.add_peer(node_client.clone(), version.clone()).await;

    // Connect node_service_1 to node_service_3
    let (node_client, version) = node_service_1.lock().await.dial_remote_node(&server_config_3.listen_addr).await.unwrap();
    node_service_1.lock().await.add_peer(node_client.clone(), version.clone()).await;

    // Create a test transaction
    let tx = create_random_transaction();

    // Broadcast the transaction from node_service_1
    node_service_1.lock().await.broadcast(Box::new(tx.clone())).await.unwrap();

    // Check if the transaction is received by node_service_2
    let received_tx_2 = node_service_2.lock().await.mempool.lock.read().await.get(&encode(hash_transaction(&tx))).cloned();
    assert_eq!(received_tx_2, Some(tx.clone()));

    // Check if the transaction is received by node_service_3
    let received_tx_3 = node_service_3.lock().await.mempool.lock.read().await.get(&encode(hash_transaction(&tx))).cloned();
    assert_eq!(received_tx_3, Some(tx.clone()));

    // Shut down all three nodes
    start_node_task_1.abort();
    start_node_task_2.abort();
    start_node_task_3.abort();
}


#[tokio::test]
async fn test_get_version() {
    let server_config = ServerConfig {
        version: "test_version".to_string(),
        listen_addr: "127.0.0.1:12345".to_string(),
        keypair: None,
    };

    let node_service = NodeService::new(server_config.clone());

    let version = node_service.get_version().await;

    assert_eq!(version.msg_version, "blocker-0.1");
    assert_eq!(version.msg_height, 0);
    assert_eq!(version.msg_listen_address, server_config.listen_addr);
    assert_eq!(version.msg_peer_list, vec![] as Vec<String>);
}

#[tokio::test]
async fn test_dial_remote_node() {
    let rt = Runtime::new().unwrap();

    // Start the first node
    rt.spawn(async move {
        let server_config1 = ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50051".to_string(),
            keypair: None,
        };
        let mut node_service1 = NodeService::new(server_config1);
        node_service1.start("127.0.0.1:50051", vec![]).await.unwrap();
    });

    // Start the second node
    rt.spawn(async move {
        let server_config2 = ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50052".to_string(),
            keypair: None,
        };
        let mut node_service2 = NodeService::new(server_config2);
        node_service2.start("127.0.0.1:50052", vec![]).await.unwrap();
    });

    // Give nodes some time to start
    std::thread::sleep(Duration::from_secs(2));

    // Test dial_remote_node
    rt.block_on(async {
        let node_service3 = NodeService::new(ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50053".to_string(),
            keypair: None,
        });

        let result = node_service3.dial_remote_node("http://127.0.0.1:50051").await;
        assert!(result.is_ok(), "Failed to dial remote node");

        let (_node_client, version) = result.unwrap();
        println!("Connected to remote node with version: {:?}", version);
    });

    // Keep the nodes running
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[tokio::test]
async fn test_can_connect_with() {
    let rt = Runtime::new().unwrap();

    // Start the first node
    rt.spawn(async move {
        let server_config1 = ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50051".to_string(),
            keypair: None,
        };
        let mut node_service1 = NodeService::new(server_config1);
        node_service1.start("127.0.0.1:50051", vec![]).await.unwrap();
    });

    // Give the node some time to start
    std::thread::sleep(Duration::from_secs(2));

    // Test can_connect_with
    rt.block_on(async {
        let node_service2 = NodeService::new(ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50052".to_string(),
            keypair: None,
        });

        // Test connecting to itself
        let can_connect1 = node_service2.can_connect_with("127.0.0.1:50052").await;
        assert_eq!(can_connect1, false, "The node should not be able to connect to itself");

        // Test connecting to another node
        let can_connect2 = node_service2.can_connect_with("127.0.0.1:50051").await;
        assert_eq!(can_connect2, true, "The node should be able to connect to another node");

        // Add the remote node to the peer list
        let (client, version) = node_service2.dial_remote_node("http://127.0.0.1:50051").await.unwrap();
        node_service2.add_peer(client, version).await;

        // Test connecting to an already connected node
        let can_connect3 = node_service2.can_connect_with("127.0.0.1:50051").await;
        assert_eq!(can_connect3, false, "The node should not be able to connect to an already connected node");
    });

    // Keep the node running
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[tokio::test]
async fn test_bootstrap_network() {
    let rt = Runtime::new().unwrap();

    // Start the first node
    rt.spawn(async move {
        let server_config1 = ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50051".to_string(),
            keypair: None,
        };
        let mut node_service1 = NodeService::new(server_config1);
        node_service1.start("127.0.0.1:50051", vec![]).await.unwrap();
    });

    // Start the second node
    rt.spawn(async move {
        let server_config2 = ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50052".to_string(),
            keypair: None,
        };
        let mut node_service2 = NodeService::new(server_config2);
        node_service2.start("127.0.0.1:50052", vec![]).await.unwrap();
    });

    // Give the nodes some time to start
    std::thread::sleep(Duration::from_secs(2));

    // Start the third node and bootstrap with the addresses of the first two nodes
    rt.spawn(async move {
        let server_config3 = ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50053".to_string(),
            keypair: None,
        };
        let mut node_service3 = NodeService::new(server_config3);
        node_service3.start("127.0.0.1:50053", vec!["127.0.0.1:50051".to_string(), "127.0.0.1:50052".to_string()]).await.unwrap();
    });

    // Give the third node some time to bootstrap
    std::thread::sleep(Duration::from_secs(2));

    // Check if the third node has two peers
    rt.block_on(async {
        let node_service3 = NodeService::new(ServerConfig {
            version: "blocker-0.1".to_string(),
            listen_addr: "127.0.0.1:50053".to_string(),
            keypair: None,
        });
        let peers = node_service3.get_peer_list().await;
        assert_eq!(peers.len(), 2, "The node should have 2 peers after bootstrapping");
    });

    // Keep the nodes running
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}


// use std::sync::atomic::{AtomicUsize, Ordering};
// use sn_proto::messages::{node_server::{Node}};

// pub struct TestNodeService {
//     node_service: NodeService,
//     received_transactions: Arc<AtomicUsize>,
// }

// #[tonic::async_trait]
// impl Node for TestNodeService {
//     async fn handshake(
//         &self,
//         request: Request<Version>,
//     ) -> Result<tonic::Response<Version>, Status> {
//         let v = request.into_inner();
//         let v_request = tonic::Request::new(v);
//         match self.handshake(v_request).await {
//             Ok(version) => Ok(version),
//             Err(err) => Err(Status::internal(err.to_string())),
//         }
//     }

//     async fn handle_transaction(
//         &self,
//         request: Request<Transaction>,
//     ) -> Result<tonic::Response<Confirmed>, Status> {
//         self.received_transactions.fetch_add(1, Ordering::Relaxed);
//         self.node_service.handle_transaction(request).await
//     }
// }

// #[tokio::test]
// async fn test_broadcast() {
//     let server_config_1 = ServerConfig {
//         version: "test_version".to_string(),
//         listen_addr: "127.0.0.1:12345".to_string(),
//         keypair: None,
//     };

//     let server_config_2 = ServerConfig {
//         version: "test_version".to_string(),
//         listen_addr: "127.0.0.1:12346".to_string(),
//         keypair: None,
//     };

//     let server_config_3 = ServerConfig {
//         version: "test_version".to_string(),
//         listen_addr: "127.0.0.1:12347".to_string(),
//         keypair: None,
//     };

//     let node_service_1 = NodeService::new(server_config_1.clone());
//     let node_service_2 = NodeService::new(server_config_2.clone());
//     let node_service_3 = NodeService::new(server_config_3.clone());

//     // Atomic counter to count received transactions
//     let received_transactions = Arc::new(AtomicUsize::new(0));

//     // Initialize the TestNodeService for node_service_2 and node_service_3
//     let test_node_service_2 = TestNodeService {
//         node_service: node_service_2,
//         received_transactions: received_transactions.clone(),
//     };

//     let test_node_service_3 = TestNodeService {
//         node_service: node_service_3,
//         received_transactions: received_transactions.clone(),
//     };

//     // Start all nodes
//     let start_node_task_1 = tokio::spawn(async move {
//         node_service_1.start(&server_config_1.listen_addr, vec![]).await.unwrap();
//     });

//     let start_node_task_2 = tokio::spawn(async move {
//         test_node_service_2.start(&server_config_2.listen_addr, vec![]).await.unwrap();
//     });

//     let start_node_task_3 = tokio::spawn(async move {
//         test_node_service_3.start(&server_config_3.listen_addr, vec![]).await.unwrap();
//     });

//     // Give the nodes a moment to start
//     sleep(Duration::from_millis(500)).await;

//     // Connect node_service_1 to node_service_2 and node_service_3
//     let (node_client_2, version_2) = node_service_1.dial_remote_node(&server_config_2.listen_addr).await.unwrap();
//     let (node_client_3, version_3) = node_service_1.dial_remote_node(&server_config_3.listen_addr).await.unwrap();

//     // Add node_service_2 and node_service_3 as peers to node_service_1
//     node_service_1.add_peer(node_client_2.clone(), version_2.clone()).await;
//     node_service_1.add_peer(node_client_3.clone(), version_3.clone()).await;

//     // Create a sample transaction
//     let keypair = Keypair::generate_keypair();
//     let tx = create_random_transaction();

//     // Broadcast the transaction from node_service_1
//     node_service_1.broadcast(Box::new(tx)).await.unwrap();

//     // Give the nodes a moment to process the broadcast
//     sleep(Duration::from_millis(500)).await;

//     // Check if both node_service_2 and node_service_3 received the transaction
//     assert_eq!(received_transactions.load(Ordering::Relaxed), 2);

//     // Stop all nodes
//     start_node_task_1.abort();
//     start_node_task_2.abort();
//     start_node_task_3.abort();

//     // Wait for nodes to stop
//     start_node_task_1.await.unwrap();
//     start_node_task_2.await.unwrap();
//     start_node_task_3.await.unwrap();
// }