use sn_node::node::*;
use tokio::runtime::Runtime;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};
use tonic::codegen::Arc;
use sn_server::server::*;

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
        msg_relative_timestamp: 5638,
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
fn test_start_node_and_make_node_client_pass() {
    // Create a new ServerConfig and NodeService.
    let rt = Runtime::new().unwrap();
    let server_config = rt.block_on(async { ServerConfig::default().await });
    let mut node_service = NodeService::new(server_config);
    let addr = &node_service.clone().server_config.cfg_addr;

    // Start the NodeService.
    rt.spawn(async move {
        node_service.start(Vec::new()).await.unwrap();
    });

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
fn test_start_node_and_make_node_client_stage_2_pass() {
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

    let server_config_1 = rt.block_on(async { ServerConfig::default_b().await });
    let mut node_service_1 = NodeService::new(server_config_1);
    let addr_1 = &node_service_1.clone().server_config.cfg_addr;

    // Start the NodeService.
    rt.spawn(async move {
        node_service_1.start(Vec::new()).await.unwrap();
    });

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
fn test_two_servers_and_two_clients_pass() {
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

#[tokio::test]
async fn test_two_servers_and_two_clients_pass_async() {
    // Create new ServerConfig and NodeService instances for two nodes.
    let server_config1 = ServerConfig::default().await;
    let server_config2 = ServerConfig::default_b().await;
    let mut node_service1 = NodeService::new(server_config1);
    let mut node_service2 = NodeService::new(server_config2);
    let addr1 = &node_service1.clone().server_config.cfg_addr;
    let addr2 = &node_service2.clone().server_config.cfg_addr;

    // Start both NodeService instances.
    tokio::spawn(async move {
        node_service1.start(Vec::new()).await.unwrap();
    });
    tokio::spawn(async move {
        node_service2.start(Vec::new()).await.unwrap();
    });

    let result1 = make_node_client(&addr1).await;
    let result2 = make_node_client(&addr2).await;

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
fn test_broadcast_pass() {
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
        let is_validator = version.msg_validator;
        node_service_1_clone_2.add_peer(client, version, is_validator).await;
    });
    let random_tx1 = create_random_transaction();
    let random_tx2: Transaction = create_random_transaction();
    rt.block_on(async move {
        node_service_1_clone_3
            .collect_and_broadcast_transactions(vec![random_tx1, random_tx2])
            .await
            .unwrap();
    });
    rt.shutdown_background();
}

#[test]
fn test_start_node_and_make_node_client_and_broadcast_fail() {
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