use sn_node::node::*;
use tokio::runtime::Runtime;
use tokio::time::{sleep, Duration};

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