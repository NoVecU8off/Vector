use sn_node::node::*;
use sn_server::server::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};
use tokio::runtime::Runtime;
use tonic::Request;
use tokio_test::{assert_ok};
use sn_node::validator::Validator;

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
        msg_to: (0..32).map(|_| rand::random::<u8>()).collect(),
    };
    Transaction {
        msg_version: rand::random::<i32>(),
        msg_inputs: vec![input],
        msg_outputs: vec![output],
        msg_relative_timestamp: 5638,
    }
}

#[test]
fn test_server_client() {
    let rt = Runtime::new().unwrap();
    let sc = rt.block_on(async {ServerConfig::default_v().await });
    let mut ns = rt.block_on(async {NodeService::new(sc).await});
    let ad = &ns.clone().server_config.cfg_addr;
    rt.spawn(async move {
        ns.start(Vec::new()).await.unwrap();
    });
    let res = rt.block_on(async{make_node_client(ad).await});
    match res {
        Ok(_) => {
            println!("Successfully created client for address: {}", ad);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client: {:?}", e);
            assert!(false);
        },
    }
}

#[test]
fn test_servers_clients() {
    let rt = Runtime::new().unwrap();
    let sc1 = rt.block_on(async {ServerConfig::default_v().await });
    let mut ns1 = rt.block_on(async {NodeService::new(sc1).await});
    let ad1 = &ns1.clone().server_config.cfg_addr;
    rt.spawn(async move {
        ns1.start(Vec::new()).await.unwrap();
    });
    let sc2 = rt.block_on(async {ServerConfig::default_v2().await });
    let mut ns2 = rt.block_on(async {NodeService::new(sc2).await});
    let ad2 = &ns2.clone().server_config.cfg_addr;
    rt.spawn(async move {
        ns2.start(Vec::new()).await.unwrap();
    });

    // Test make_node_client() for both server addresses.
    let r1 = rt.block_on(async{make_node_client(ad1).await});
    let r2 = rt.block_on(async{make_node_client(ad2).await});

    match r1 {
        Ok(_) => {
            println!("Successfully created client for address: {}", ad1);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client1: {:?}", e);
            assert!(false);
        },
    }

    match r2 {
        Ok(_) => {
            println!("Successfully created client for address: {}", ad2);
            assert!(true);
        },
        Err(e) => {
            eprintln!("Error creating client2: {:?}", e);
            assert!(false);
        },
    }
}

#[test]
fn test_dial_broadcast() {
    let rt = Runtime::new().unwrap();
    let sc1 = rt.block_on(async {ServerConfig::default_v().await });
    let ns1 = rt.block_on(async {NodeService::new(sc1).await});
    let mut ns1_clone = ns1.clone(); // Clone ns1
    rt.spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = rt.block_on(async {ServerConfig::default_v2().await });
    let mut ns2 = rt.block_on(async {NodeService::new(sc2).await});
    let ad2 = &ns2.clone().server_config.cfg_addr;
    rt.spawn(async move {
        ns2.start(Vec::new()).await.unwrap();
    });
    let (_, _) = rt.block_on(async {
        ns1
            .dial_remote_node(&ad2)
            .await
            .unwrap()
    });
    let tx1 = create_random_transaction();
    rt.block_on(async {
        ns1
            .broadcast_transaction(tx1)
            .await
            .unwrap()
    });
}


#[test]
fn servers_broadcast_sync() {
    let rt = Runtime::new().unwrap();
    let sc1 = rt.block_on(async {ServerConfig::default_v().await });
    let ns1 = rt.block_on(async {NodeService::new(sc1).await});
    let mut ns1_clone = ns1.clone(); // Clone ns1
    rt.spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = rt.block_on(async {ServerConfig::default_v2().await });
    let mut ns2 = rt.block_on(async {NodeService::new(sc2).await});
    rt.spawn(async move {
        ns2.start(Vec::new()).await.unwrap();
    });
    let tx = create_random_transaction();
    rt.block_on( async { ns1.broadcast_transaction(tx).await.unwrap() });
}

#[tokio::test]
async fn servers_broadcast_async() {
    let sc1 = ServerConfig::default_v().await;
    let ns1 = NodeService::new(sc1).await;
    let mut ns1_clone = ns1.clone();
    tokio::spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = ServerConfig::default_v2().await;
    let mut ns2 = NodeService::new(sc2).await;
    tokio::spawn(async move {
        ns2.start(Vec::new()).await.unwrap();
    });
    let tx = create_random_transaction();
    let rs = ns1.broadcast_transaction(tx).await;
    assert_ok!(&rs);
}

#[tokio::test]
async fn test_handle_transaction() {
    let sc1 = ServerConfig::default_v().await;
    let ns1 = NodeService::new(sc1).await;
    let mut ns1_clone = ns1.clone();
    tokio::spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let tx = create_random_transaction();
    let rq = Request::new(tx.clone());
    let validator_service = ns1.validator.as_ref().unwrap();
    let rs = validator_service.handle_transaction(rq).await;
    assert_ok!(&rs);
    assert!(validator_service.mempool.contains_transaction(&tx).await);
}

#[tokio::test]
async fn test_validators_broadcast_handle() {
    let sc1 = ServerConfig::default_v().await;
    let ns1 = NodeService::new(sc1).await;
    let mut ns1_clone = ns1.clone();
    let ad1 = ns1.server_config.cfg_addr.clone();
    tokio::spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = ServerConfig::default_v2().await;
    let ns2 = NodeService::new(sc2).await;
    let mut ns2_clone = ns2.clone();
    tokio::spawn(async move {
        ns2_clone.start(vec![ad1]).await.unwrap();
    });
    let tx = create_random_transaction();
    let validator2 = ns2.validator.as_ref().expect("NO VALIDATOR");
    let r1 = validator2.broadcast_transaction(tx.clone()).await;
    assert_ok!(r1);
    let validator1 = ns1.validator.as_ref().expect("NO VALIDATOR");
    let r2 = validator1.handle_transaction(Request::new(tx.clone())).await;
    assert_ok!(r2);
    assert!(validator1.mempool.contains_transaction(&tx).await);
}

#[tokio::test]
async fn test_validator_consensus() {
    let sc1 = ServerConfig::default_v().await;
    let ns1 = NodeService::new(sc1).await;
    let ad1 = ns1.server_config.cfg_addr.clone();
    let mut ns1_clone = ns1.clone();
    let ns1_task = tokio::spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });

    let sc2 = ServerConfig::default_v2().await;
    let ns2 = NodeService::new(sc2).await;
    let mut ns2_clone = ns2.clone();
    let ns2_task = tokio::spawn(async move {
        ns2_clone.start(vec![ad1]).await.unwrap();
    });

    let tx = create_random_transaction();
    let validator1 = ns1.validator.clone().expect("NO VALIDATOR");  // Cloning the Arc
    let validator2 = ns2.validator.clone().expect("NO VALIDATOR");

    validator1.mempool.add(tx.clone()).await;
    validator2.mempool.add(tx.clone()).await;

    let v1_task = tokio::spawn(async move {
        validator1.initialize_consensus().await;
    });

    let v2_task = tokio::spawn(async move {
        validator2.initialize_consensus().await;
    });

    v1_task.await.unwrap();
    v2_task.await.unwrap();
    ns1_task.await.unwrap();
    ns2_task.await.unwrap();
}

