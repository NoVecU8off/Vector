use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use vec_node::{node::*};
use vec_server::server::*;

enum Command {
    SendTransaction { address: String, amount: u64 },
    GetBalance,
    Genesis,
    ConnectTo { ip: String },
    GetAddress,
    GetHeight,
}

#[tokio::main]
async fn main() {
    let mut rl = DefaultEditor::new().unwrap();
    let mut nodes_to_bootstrap = Vec::new();
    loop {
        let readline = rl.readline("Type in ip address to pre-connect (or 'done' to proceed): ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line == "done" {
                    break;
                } else {
                    nodes_to_bootstrap.push(line.to_string());
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                return;
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                return;
            },
            Err(err) => {
                println!("Error: {:?}", err);
                return;
            },
        }
    }
    let scv = ServerConfig::default_v().await;
    let nsv = NodeService::new(scv).await.unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let mut nsv_clone = nsv.clone();
    tokio::spawn(async move {
        nsv_clone.start(nodes_to_bootstrap).await
    });

    let server_future = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(Command::SendTransaction { address, amount}) => {
                    match nsv.make_transaction(&address, amount as u64).await {
                        Ok(_) => println!("Transaction broadcasted successfully"),
                        Err(e) => eprintln!("Failed to broadcast transaction: {}", e),
                    }
                },
                Some(Command::GetBalance) => {
                    let balance = nsv.get_balance().await;
                    println!("Balance: {}", balance);
                },
                Some(Command::GetHeight) => {
                    let height = nsv.get_height().await.unwrap();
                    println!("Height: {}", height);
                },
                Some(Command::Genesis) => {
                    match nsv.make_genesis_block().await {
                        Ok(_) => println!("Genesis block created successfully"),
                        Err(e) => eprintln!("Failed to create genesis block: {}", e),
                    }
                },
                Some(Command::ConnectTo { ip }) => {
                    match nsv.connect_to(&ip).await {
                        Ok(_) => println!("Successfully connected to {}", ip),
                        Err(e) => eprintln!("Failed to connect: {}", e),
                    }
                },
                Some(Command::GetAddress) => {
                    match nsv.get_address().await {
                        Ok(address) => println!("Address: {}", address),
                        Err(e) => eprintln!("Failed to get address: {}", e),
                    }
                },
                None => {
                    break;
                },
            }
        }
    });

    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                let command = line.trim();
                match command {
                    cmd if cmd.starts_with("send") => {
                        let parts: Vec<&str> = cmd.split_whitespace().collect();
                        if parts.len() == 5 {
                            let address = parts[1].to_string();
                            let amount = parts[3].parse::<u64>().unwrap_or(0);
                            let _ = tx.send(Command::SendTransaction { address, amount }).await;
                        } else {
                            println!("Invalid 'send' command format. It should be 'send <pvk> <psk> amount <amount>'");
                        }
                    },
                    cmd if cmd.starts_with("connect to") => {
                        let parts: Vec<&str> = cmd.split_whitespace().collect();
                        if parts.len() == 3 {
                            let ip = parts[2].to_string();
                            let _ = tx.send(Command::ConnectTo { ip }).await;
                        } else {
                            println!("Invalid 'connect to' command format. It should be 'connect to <ip>'");
                        }
                    },
                    "balance" => {
                        let _ = tx.send(Command::GetBalance).await;
                    },
                    "height" => {
                        let _ = tx.send(Command::GetHeight).await;
                    },
                    "genesis" => {
                        let _ = tx.send(Command::Genesis).await;
                    },
                    "address" => {
                        let _ = tx.send(Command::GetAddress).await;
                    },
                    _ => {
                        println!("Invalid command");
                    },
                }
            },
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            },
        }
    }    
    server_future.await.unwrap();
}
