// use clap::{App, Arg, SubCommand};
// use sn_node::node::{NodeService, ServerConfig};
// use sn_proto::messages::{Transaction, TransactionInput, TransactionOutput};
// use std::sync::{Arc};
// use sn_proto::messages::node_server::Node;
// use sn_cryptography::cryptography::Keypair;
fn main(){}
// #[tokio::main]
// async fn main() {
//     let server_config = ServerConfig {
//         version: "1.0".to_string(),
//         server_listen_addr: "127.0.0.1:3000".to_string(),
//         keypair: Some(Keypair::generate_keypair()),
//     };

//     let mut node_service = NodeService::new(server_config);
//     let _ = node_service.start(vec![]);

//     let node_service_arc = Arc::new(node_service);

//     let matches = App::new("sn_cli")
//         .version("test cli-0.1")
//         .author("Andrew Novikoff <andrewnovikoff@outlook.com>")
//         .about("Simple command-line interface for the Rust blockchain project")
//         .subcommand(
//             SubCommand::with_name("make_transaction")
//                 .about("Creates a new transaction")
//                 .arg(
//                     Arg::with_name("to")
//                         .help("Recipient address")
//                         .required(true)
//                         .index(1),
//                 )
//                 .arg(
//                     Arg::with_name("amount")
//                         .help("Amount to send")
//                         .required(true)
//                         .index(2),
//                 ),
//         )
//         .subcommand(SubCommand::with_name("get_balance").about("Displays your balance"))
//         .get_matches();

//     if let Some(ref matches) = matches.subcommand_matches("make_transaction") {
//         let to = matches.value_of("to").unwrap();
//         let amount = matches.value_of("amount").unwrap().parse::<u64>().unwrap();

//         let transaction_input = TransactionInput {
//             msg_previous_tx_hash: Vec::new(), // Replace with the actual previous transaction hash
//             msg_previous_out_index: 0,        // Replace with the actual previous output index
//             msg_public_key: Vec::new(),       // Replace with the actual public key
//             msg_signature: Vec::new(),        // Replace with the actual signature
//         };
        
//         let transaction_output = TransactionOutput {
//             msg_amount: amount as i64,
//             msg_address: to.as_bytes().to_vec(),
//         };
        
//         let transaction = Transaction {
//             msg_version: 1,
//             msg_inputs: vec![transaction_input],
//             msg_outputs: vec![transaction_output],
//         };
        
        
//         let confirmed = node_service_arc.handle_transaction(tonic::Request::new(transaction)).await.unwrap();
//         println!("Transaction confirmed: {:?}", confirmed);

//     } else if let Some(_) = matches.subcommand_matches("get_balance") {
//         // Call your balance query function here
//         // Currently, there's no balance query function in the provided sn_node module
//         println!("Your current balance: (balance function not implemented)");
//     }
// }