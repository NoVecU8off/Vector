use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use vec_cryptography::cryptography::Wallet;
use vec_node::node::*;
use vec_server::server::*;

enum Command {
    SendTransaction { address: String, amount: u64 },
    GetBalance,
    Genesis,
    ConnectTo { ip: String },
    GetAddress,
    GetIndex,
    MakeBlock,
}

#[tokio::main]
async fn main() {
    let mut rl = DefaultEditor::new().unwrap();

    let readline = rl.readline("Please enter port <xxxx>: ");
    let port = match readline {
        Ok(line) => line.trim().to_string(),
        Err(_) => {
            eprintln!("Failed to read port");
            return;
        }
    };

    let readline = rl.readline("Do you have a secret key? (yes/no): ");
    let has_secret_key = match readline {
        Ok(line) => line.trim().eq_ignore_ascii_case("yes"),
        Err(_) => {
            eprintln!("Failed to read response");
            return;
        }
    };

    let secret_key: String;
    if has_secret_key {
        let readline = rl.readline("Please enter your secret key: ");
        secret_key = match readline {
            Ok(line) => line.trim().to_string(),
            Err(_) => {
                eprintln!("Failed to read secret key");
                return;
            }
        };
    } else {
        let wallet = Wallet::generate();
        secret_key = bs58::encode(wallet.secret_spend_key_to_vec()).into_string();
        println!("Your new wallet has been generated.");
        println!("Please, save your secret key: {}", secret_key);
    }

    let scv = ServerConfig::local(secret_key, port).await;
    let nsv = NodeService::new(scv).await.unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let mut nsv_clone = nsv.clone();
    tokio::spawn(async move { nsv_clone.start().await });

    let server_future = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(Command::SendTransaction { address, amount }) => {
                    match nsv.make_transaction(&address, amount as u64).await {
                        Ok(_) => println!("Transaction broadcasted successfully"),
                        Err(e) => eprintln!("Failed to broadcast transaction: {}", e),
                    }
                }
                Some(Command::MakeBlock) => match nsv.make_block().await {
                    Ok(_) => println!("Block created successfully"),
                    Err(e) => eprintln!("Failed to create block: {}", e),
                },
                Some(Command::GetBalance) => {
                    let balance = nsv.get_balance().await;
                    println!("Your balance: {}", balance);
                }
                Some(Command::GetIndex) => {
                    let height = nsv.get_last_index().await.unwrap();
                    println!("Current Block's index: {}", height);
                }
                Some(Command::Genesis) => match nsv.make_genesis_block().await {
                    Ok(_) => println!("Genesis block created successfully"),
                    Err(e) => eprintln!("Failed to create genesis block: {}", e),
                },
                Some(Command::ConnectTo { ip }) => match nsv.connect_to(&ip).await {
                    Ok(_) => println!("Successfully connected to {}", ip),
                    Err(e) => eprintln!("Failed to connect: {}", e),
                },
                Some(Command::GetAddress) => match nsv.get_address().await {
                    Ok(address) => println!("Address: {}", address),
                    Err(e) => eprintln!("Failed to get address: {}", e),
                },
                None => {
                    break;
                }
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
                        if parts.len() == 4 {
                            let address = parts[1].to_string();
                            let amount = parts[3].parse::<u64>().unwrap_or(0);
                            let _ = tx.send(Command::SendTransaction { address, amount }).await;
                        } else {
                            println!("Invalid 'send' command format. It should be 'send <address> amount <amount>'");
                        }
                    }
                    cmd if cmd.starts_with("connect to") => {
                        let parts: Vec<&str> = cmd.split_whitespace().collect();
                        if parts.len() == 3 {
                            let ip = parts[2].to_string();
                            let _ = tx.send(Command::ConnectTo { ip }).await;
                        } else {
                            println!("Invalid 'connect to' command format. It should be 'connect to <ip>'");
                        }
                    }
                    "balance" => {
                        let _ = tx.send(Command::GetBalance).await;
                    }
                    "block" => {
                        let _ = tx.send(Command::MakeBlock).await;
                    }
                    "index" => {
                        let _ = tx.send(Command::GetIndex).await;
                    }
                    "genesis" => {
                        let _ = tx.send(Command::Genesis).await;
                    }
                    "address" => {
                        let _ = tx.send(Command::GetAddress).await;
                    }
                    _ => {
                        println!("Invalid command");
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    server_future.await.unwrap();
}
