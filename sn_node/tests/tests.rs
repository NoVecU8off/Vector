use sn_node::node::*;
use tokio::runtime::Runtime;
use tokio::time::{sleep, Duration};
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};
use tonic::codegen::Arc;

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


fn create_test_server_config_1() -> ServerConfig {
    let cfg_version = "2".to_string();
    let cfg_addr = "127.0.0.1:8080".to_string();
    let cfg_keypair = Keypair::generate_keypair();
    let (cfg_pem_certificate, cfg_pem_key, cfg_root_crt) = read_server_certs_and_keys().unwrap();
        ServerConfig {
            cfg_version,
            cfg_addr,
            cfg_keypair,
            cfg_pem_certificate,
            cfg_pem_key,
            cfg_root_crt,
        }
}

fn create_test_server_config_2() -> ServerConfig {
    let cfg_version = "1".to_string();
    let cfg_addr = "127.0.0.1:8088".to_string();
    let cfg_keypair = Keypair::generate_keypair();
    let (cfg_pem_certificate, cfg_pem_key, cfg_root_crt) = read_server_certs_and_keys().unwrap();
        ServerConfig {
            cfg_version,
            cfg_addr,
            cfg_keypair,
            cfg_pem_certificate,
            cfg_pem_key,
            cfg_root_crt,
        }
}

#[test]
fn test_make_node_client() {
    // Replace this with a valid address of a running NodeService instance.
    let addr = "192.168.0.120:8080";

    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async { make_node_client(addr).await });

    match result {
        Ok(_client) => {
            println!("Successfully created client for address: {}", addr);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client: {:?}", e);
            assert!(false);
        },
    }
}

#[test]
fn test_start_node_and_make_node_client() {
    // Create a new ServerConfig and NodeService.
    let rt = Runtime::new().unwrap();
    let server_config = rt.block_on(async { ServerConfig::default().await });
    let mut node_service = NodeService::new(server_config);
    let addr = &node_service.clone().server_config.cfg_addr;

    // Start the NodeService.
    rt.spawn(async move {
        node_service.start(Vec::new()).await.unwrap();
    });

    // Give the NodeService some time to start.
    rt.block_on(async { sleep(Duration::from_secs(2)).await });

    // Test make_node_client().
    let result = rt.block_on(async { make_node_client(&addr).await });

    match result {
        Ok(_client) => {
            println!("Successfully created client for address: {}", addr);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client: {:?}", e);
            assert!(false);
        },
    }
}

#[test]
fn test_start_node_and_make_node_client_stage_2() {
    // Create a new ServerConfig and NodeService.
    let rt = Runtime::new().unwrap();
    let server_config = rt.block_on(async { ServerConfig::default().await });
    let mut node_service = NodeService::new(server_config);
    let addr = &node_service.clone().server_config.cfg_addr;
    let node_service_clone = node_service.clone();

    // Start the NodeService.
    rt.spawn(async move {
        node_service.start(Vec::new()).await.unwrap();
    });

    // Give the NodeService some time to start.
    rt.block_on(async { sleep(Duration::from_secs(2)).await });

    let server_config_1 = rt.block_on(async { ServerConfig::default_b().await });
    let mut node_service_1 = NodeService::new(server_config_1);
    let addr_1 = &node_service_1.clone().server_config.cfg_addr;

    // Start the NodeService.
    rt.spawn(async move {
        node_service_1.start(Vec::new()).await.unwrap();
    });

    // Give the NodeService some time to start.
    rt.block_on(async { sleep(Duration::from_secs(2)).await });

    // Test make_node_client().
    let result = rt.block_on(async { node_service_clone.dial_remote_node(&addr_1).await });

    match result {
        Ok(_client) => {
            println!("Successfully created client for address: {}", addr);
        },
        Err(e) => {
            eprintln!("Error creating client: {:?}", e);
        },
    }
}

#[test]
fn test_two_servers_and_two_clients() {
    // Create new ServerConfig and NodeService instances for two nodes.
    let rt = Runtime::new().unwrap();
    let server_config1 = rt.block_on(async { ServerConfig::default().await });
    let server_config2 = rt.block_on(async { ServerConfig::default_b().await });
    let mut node_service1 = NodeService::new(server_config1);
    let mut node_service2 = NodeService::new(server_config2);
    let addr1 = &node_service1.clone().server_config.cfg_addr;
    let addr2 = &node_service2.clone().server_config.cfg_addr;

    // Start both NodeService instances.
    rt.spawn(async move {
        node_service1.start(Vec::new()).await.unwrap();
    });
    rt.spawn(async move {
        node_service2.start(Vec::new()).await.unwrap();
    });

    // Give both NodeService instances some time to start.
    rt.block_on(async { sleep(Duration::from_secs(2)).await });

    // Test make_node_client() for both server addresses.
    let result1 = rt.block_on(async { make_node_client(&addr1).await });
    let result2 = rt.block_on(async { make_node_client(&addr2).await });

    match result1 {
        Ok(_client) => {
            println!("Successfully created client1 for address: {}", addr1);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client1: {:?}", e);
            assert!(false);
        },
    }

    match result2 {
        Ok(_client) => {
            println!("Successfully created client2 for address: {}", addr2);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client2: {:?}", e);
            assert!(false);
        },
    }
}

#[test]
fn test_broadcast() {
    env_logger::init();
    let rt = Runtime::new().unwrap();
    let server_config_1 = rt.block_on(async { ServerConfig::default().await });
    let server_config_2 = rt.block_on(async { ServerConfig::default_b().await });
    let mut node_service_1 = NodeService::new(server_config_1);
    let mut node_service_2 = NodeService::new(server_config_2);
    node_service_1.self_ref = Some(Arc::new(node_service_1.clone()));
    node_service_2.self_ref = Some(Arc::new(node_service_2.clone()));
    let node_service_1_clone = node_service_1.clone();
    let node_service_2_clone = node_service_2.clone();
    let random_tx = create_random_transaction();
    rt.spawn(async move {
        node_service_1.start(vec![]).await.unwrap();
    });
    rt.spawn(async move {
        node_service_2.start(vec![]).await.unwrap();
        let (client, version) = node_service_2_clone
                .dial_remote_node(&node_service_1_clone.server_config.cfg_addr)
                .await
                .unwrap();
        println!("DAILED");
        node_service_2_clone
            .add_peer(client, version)
            .await;
        println!("PEERED");
        node_service_2_clone
            .broadcast(Box::new(random_tx))
            .await
            .unwrap();
        println!("BROADCASTED");
    });
}

#[tokio::test]
async fn test_broadcast_two() {
    env_logger::init();
    let server_config_1 = ServerConfig::default().await;
    let server_config_2 = ServerConfig::default_b().await;
    let mut node_service_1 = NodeService::new(server_config_1);
    let mut node_service_2 = NodeService::new(server_config_2);
    node_service_1.self_ref = Some(Arc::new(node_service_1.clone()));
    node_service_2.self_ref = Some(Arc::new(node_service_2.clone()));
    let node_service_1_clone = node_service_1.clone();
    let node_service_2_clone = node_service_2.clone();
    let random_tx = create_random_transaction();
    tokio::spawn(async move {
        node_service_1.start(vec![]).await.unwrap();
    });
    tokio::spawn(async move {
        node_service_2.start(vec![]).await.unwrap();
        let (client, version) = node_service_2_clone.dial_remote_node(&node_service_1_clone.server_config.cfg_addr).await.unwrap();
        node_service_2_clone.add_peer(client, version).await;
        node_service_2_clone.broadcast(Box::new(random_tx)).await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn test_dial_remote_node_works() {
    let node_service_1 = NodeService::new(ServerConfig::default().await);
    let node_service_2 = NodeService::new(ServerConfig::default_b().await);
    let node_service_1_clone = node_service_1.clone();
    tokio::spawn(async move {
        node_service_1
            .clone()
            .start(vec![])
            .await
            .unwrap();
    });
    tokio::spawn(async move {
        node_service_2
            .clone()
            .start(vec![])
            .await
            .unwrap();
        let (_client, version) = node_service_2
        .dial_remote_node(&node_service_1_clone.server_config.cfg_addr)
        .await
        .unwrap();
    assert_eq!(
        version.msg_listen_address,
        node_service_2.server_config.cfg_addr,
        "Remote node version should have the correct listen address"
    );
    assert_eq!(
        version.msg_version,
        "1",
        "Remote node version should match the expected version"
    );
    }).await.unwrap();
}

#[test]
fn test_dial_remote_node_works_runtime() {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let node_service_1 = NodeService::new(ServerConfig::default().await);
        let node_service_2 = NodeService::new(ServerConfig::default_b().await);
        let node_service_1_clone = node_service_1.clone();
        tokio::spawn(async move {
            node_service_1.clone().start(vec![]).await.unwrap();
        });
        tokio::spawn(async move {
            node_service_2.clone().start(vec![]).await.unwrap();
            let (_client, version) = node_service_2
                .dial_remote_node(&node_service_1_clone.server_config.cfg_addr)
                .await
                .unwrap();
            println!("{} dialed to {}", node_service_2.server_config.cfg_addr, node_service_1_clone.server_config.cfg_addr);
            assert_eq!(
                version.msg_listen_address,
                node_service_2.server_config.cfg_addr,
                "Remote node version should have the correct listen address"
            );
            assert_eq!(
                version.msg_version,
                "1",
                "Remote node version should match the expected version"
            );
        });
    });
}

#[tokio::test]
async fn test_dial_remote_node_fail() {
    let node_service_1 = NodeService::new(ServerConfig::default().await);
    let node_service_2 = NodeService::new(ServerConfig::default_b().await);
    let node_service_1_clone = node_service_1.clone();
    let node_service_2_clone = node_service_2.clone();
    tokio::spawn(async move {
        node_service_1
            .clone()
            .start(vec![])
            .await
            .unwrap();
    });
    sleep(Duration::from_secs(5)).await;
    tokio::spawn(async move {
        node_service_2
            .clone()
            .start(vec![])
            .await
            .unwrap();
        
    }).await.unwrap();
    sleep(Duration::from_secs(5)).await;
    let (_client, version) = node_service_2_clone
        .dial_remote_node(&node_service_1_clone.server_config.cfg_addr)
        .await
        .unwrap();
    assert_eq!(
        version.msg_listen_address,
        node_service_2_clone.server_config.cfg_addr,
        "Remote node version should have the correct listen address"
    );
    assert_eq!(
        version.msg_version,
        "test-1",
        "Remote node version should match the expected version"
    );
}

#[tokio::test]
async fn test_dial_remote_node_fail_two() {
    let node_service_1 = NodeService::new(ServerConfig::default().await);
    let node_service_2 = NodeService::new(ServerConfig::default_b().await);

    let node_service_1_clone = node_service_1.clone();
    let node_service_2_clone = node_service_2.clone();

    let node1_handle = tokio::spawn(async move {
        node_service_1.clone().start(vec![]).await.unwrap();
    });

    let node2_handle = tokio::spawn(async move {
        node_service_2.clone().start(vec![]).await.unwrap();
        node_service_2_clone.dial_remote_node(&node_service_1_clone.server_config.cfg_addr).await.unwrap();
    });

    node1_handle.await.unwrap();
    node2_handle.await.unwrap();
}

#[test]
fn test_broadcast_https() {
    let rt = Runtime::new().unwrap();
    let server_config_1 = create_test_server_config_1();
    let server_config_2 = create_test_server_config_2();
    let mut node_service_1 = NodeService::new(server_config_1);
    let mut node_service_2 = NodeService::new(server_config_2);
    node_service_1.self_ref = Some(Arc::new(node_service_1.clone()));
    node_service_2.self_ref = Some(Arc::new(node_service_2.clone()));
    let node_service_1_clone_2 = node_service_1.clone();
    let node_service_1_clone_3 = node_service_1.clone();
    let node_service_2_clone_2 = node_service_2.clone();
    rt.spawn(async move {
        node_service_1.start(vec![]).await.unwrap();
    });
    rt.spawn(async move {
        node_service_2.start(vec![]).await.unwrap();
    });
    rt.block_on(async move {
        let (client, version) = node_service_1_clone_2
                .dial_remote_node(&node_service_2_clone_2.server_config.cfg_addr)
                .await
                .unwrap();
        node_service_1_clone_2.add_peer(client, version).await;
    });
    let random_tx = create_random_transaction();
    rt.block_on(async move {
        node_service_1_clone_3.broadcast(Box::new(random_tx)).await.unwrap();
    });
    rt.shutdown_background();
}

#[test]
fn test_start_node_and_make_node_client_and_broadcast() {
    let rt = Runtime::new().unwrap();
    let server_config = rt.block_on(async { ServerConfig::default().await });
    let mut node_service = NodeService::new(server_config);
    let addr_node_1 = &node_service.clone().server_config.cfg_addr;

    let server_config_2 = rt.block_on(async { ServerConfig::default_b().await });
    let mut node_service_2 = NodeService::new(server_config_2);
    let node_service_2_clone = node_service_2.clone();

    // Start the NodeService.
    rt.spawn(async move {
        node_service.start(Vec::new()).await.unwrap();
        node_service_2.start(Vec::new()).await.unwrap();
    });

    // Test make_node_client().
    let result = rt.block_on(async { make_node_client(&addr_node_1).await });

    match result {
        Ok(_client) => {
            println!("Successfully created client for address: {}", addr_node_1);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client: {:?}", e);
            assert!(false);
        },
    }

    let result_2 = rt.block_on(async { node_service_2_clone.dial_remote_node(&addr_node_1).await});

    match result_2 {
        Ok(_client) => {
            println!("Successfully created client for address: {}", addr_node_1);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client: {:?}", e);
            assert!(false);
        },
    }
}