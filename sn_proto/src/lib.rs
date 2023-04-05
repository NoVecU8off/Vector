pub mod messages {
    include!(concat!(env!("OUT_DIR"), "/messages.rs"));
}

// Use the generated code in your application:
// use messages::{Version, Transaction, Confirmed, node_server::Node, node_client::NodeClient};