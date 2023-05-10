use sn_node::node::*;
use sn_server::server::*;
use sn_cryptography::cryptography::Keypair;
use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};
use tokio::runtime::Runtime;

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

#[test]
fn test_server_client() {
    let rt = Runtime::new().unwrap();
    let sc = rt.block_on(async {ServerConfig::default().await });
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
    let sc1 = rt.block_on(async {ServerConfig::default().await });
    let mut ns1 = rt.block_on(async {NodeService::new(sc1).await});
    let ad1 = &ns1.clone().server_config.cfg_addr;
    rt.spawn(async move {
        ns1.start(Vec::new()).await.unwrap();
    });
    let sc2 = rt.block_on(async {ServerConfig::default_b().await });
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
    let sc1 = rt.block_on(async {ServerConfig::default().await });
    let ns1 = rt.block_on(async {NodeService::new(sc1).await});
    let mut ns1_clone = ns1.clone(); // Clone ns1
    rt.spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = rt.block_on(async {ServerConfig::default_b().await });
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
    let sc1 = rt.block_on(async {ServerConfig::default().await });
    let ns1 = rt.block_on(async {NodeService::new(sc1).await});
    let mut ns1_clone = ns1.clone(); // Clone ns1
    rt.spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = rt.block_on(async {ServerConfig::default_b().await });
    let mut ns2 = rt.block_on(async {NodeService::new(sc2).await});
    rt.spawn(async move {
        ns2.start(Vec::new()).await.unwrap();
    });
    let tx = create_random_transaction();
    rt.block_on( async { ns1.broadcast_transaction(tx).await.unwrap() });
}

#[tokio::test]
async fn servers_broadcast_async() {
    let sc1 = ServerConfig::default().await;
    let ns1 = NodeService::new(sc1).await;
    let mut ns1_clone = ns1.clone(); // Clone ns1
    tokio::spawn(async move {
        ns1_clone.start(Vec::new()).await.unwrap();
    });
    let sc2 = ServerConfig::default_b().await;
    let mut ns2 = NodeService::new(sc2).await;
    tokio::spawn(async move {
        ns2.start(Vec::new()).await.unwrap();
    });
    let tx = create_random_transaction();
    ns1.broadcast_transaction(tx).await.unwrap();
}