// pub fn get_available_port<A: ToSocketAddrs>(addr: A) -> Result<String> {
//     for address in addr.to_socket_addrs()? {
//         if let Ok(listener) = TcpListener::bind(address) {
//             return Ok(format!("{}", listener.local_addr()?));
//         }
//     }
//     Err(anyhow!("No available port found"))
// }
// #[test]
// fn test_add_and_delete_peer() {
//     let rt = Runtime::new().unwrap();
//     let server_config_1 = create_test_server_config_1();
//     let server_config_2 = create_test_server_config_2();

//     let mut node_service_1 = NodeService::new(server_config_1);
//     let mut node_service_2 = NodeService::new(server_config_2);

//     let node_service_1_clone_1 = node_service_1.clone();
//     let node_service_1_clone_2 = node_service_1.clone();
//     let node_service_2_clone_1 = node_service_2.clone();
//     let node_service_2_clone_2 = node_service_2.clone();

//     node_service_1.self_ref = Some(Arc::new(node_service_1.clone()));
//     node_service_2.self_ref = Some(Arc::new(node_service_2.clone()));

//     rt.spawn(async move {
//         node_service_1.start(&node_service_1_clone_1.server_config.server_listen_addr, vec![]).await.unwrap();
//     });
//     rt.spawn(async move {
//         node_service_2.start(&node_service_2_clone_1.server_config.server_listen_addr, vec![]).await.unwrap();
//     });

//     rt.block_on(async {
//         let (client, version) = node_service_1_clone_2
//             .dial_remote_node(&format!("http://{}", node_service_2_clone_2.server_config.server_listen_addr))
//             .await
//             .unwrap();
//         let client_arc = Arc::new(tokioMutex::new(client));
//         node_service_1_clone_2.add_peer(client_arc.clone(), version).await;

//         let peer_list_before = node_service_1_clone_2.get_peer_list().await;
//         assert_eq!(peer_list_before.len(), 1);
//         assert_eq!(peer_list_before[0], "127.0.0.1:8088");

//         node_service_1_clone_2.delete_peer(&client_arc).await;
//         let peer_list_after = node_service_1_clone_2.get_peer_list().await;
//         assert_eq!(peer_list_after.len(), 0);
//     });
// }