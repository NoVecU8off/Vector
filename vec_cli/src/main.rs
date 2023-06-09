use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::sync::Arc;
use vec_crypto::crypto::Wallet;
use vec_errors::errors::*;
use vec_node::node::*;

enum Command {
    SendTransaction {
        address: String,
        amount: u64,
        contract_path: Option<String>,
    },
    GetBalance,
    Genesis,
    ConnectTo {
        ip: String,
    },
    GetAddress,
    GetIndex,
    MakeBlock,
}

#[tokio::main]
async fn main() {
    let mut rl = DefaultEditor::new().unwrap();

    let readline = rl.readline("Do you want to run locally? (yes/no): ");
    let run_local = match readline {
        Ok(line) => line.trim().eq_ignore_ascii_case("yes"),
        Err(_) => {
            eprintln!("Failed to read response");
            return;
        }
    };

    let readline = rl.readline("Please enter port: ");
    let port = match readline {
        Ok(line) => line.trim().to_string(),
        Err(_) => {
            eprintln!("Failed to read port");
            return;
        }
    };

    let ip: String = if run_local {
        "192.168.0.120".to_string()
    } else {
        match get_ip().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Failed to get IP: {}", e);
                return;
            }
        }
    };

    let address = format!("{}:{}", ip, port);

    let readline = rl.readline("Do you have a secret key? (yes/no): ");
    let has_secret_key = match readline {
        Ok(line) => line.trim().eq_ignore_ascii_case("yes"),
        Err(_) => {
            eprintln!("Failed to read response");
            return;
        }
    };

    let secret_spend_key: String;
    if has_secret_key {
        let readline = rl.readline("Please enter your secret key: ");
        secret_spend_key = match readline {
            Ok(line) => line.trim().to_string(),
            Err(_) => {
                eprintln!("Failed to read secret key");
                return;
            }
        };
    } else {
        let wallet = Wallet::generate().unwrap();
        secret_spend_key = bs58::encode(wallet.secret_spend_key_to_vec()).into_string();
        println!("Your new wallet has been generated.");
        println!("Please, save your secret key: {}", secret_spend_key);
    }

    let ans = match new(secret_spend_key, address).await {
        Ok(ans) => ans,
        Err(e) => {
            eprintln!("Failed to create NodeService: {}", e);
            return;
        }
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    let arc_ns = Arc::clone(&ans.ns);
    tokio::spawn(async move { start(&arc_ns).await });

    let server_future = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(Command::SendTransaction {
                    address,
                    amount,
                    contract_path,
                }) => {
                    match ans
                        .ns
                        .make_transaction(&address, amount, contract_path.as_deref())
                        .await
                    {
                        Ok(_) => println!("Transaction broadcasted successfully"),
                        Err(e) => eprintln!("Failed to broadcast transaction: {}", e),
                    }
                }
                Some(Command::MakeBlock) => match ans.ns.make_block().await {
                    Ok(_) => println!("Block created successfully"),
                    Err(e) => eprintln!("Failed to create block: {}", e),
                },
                Some(Command::GetBalance) => {
                    let balance = ans.ns.get_balance().await;
                    println!("Your balance: {}", balance);
                }
                Some(Command::GetIndex) => {
                    let height = match ans.ns.get_last_index().await {
                        Ok(height) => height,
                        Err(e) => {
                            eprintln!("Failed to get last index: {}", e);
                            return;
                        }
                    };
                    println!("Current Block's index: {}", height);
                }
                Some(Command::Genesis) => match ans.ns.make_genesis_block().await {
                    Ok(_) => println!("Genesis block created successfully"),
                    Err(e) => eprintln!("Failed to create genesis block: {}", e),
                },
                Some(Command::ConnectTo { ip }) => match ans.ns.connect_to(ip.clone()).await {
                    Ok(_) => println!("Successfully connected to {}", ip),
                    Err(e) => eprintln!("Failed to connect: {}", e),
                },
                Some(Command::GetAddress) => match ans.ns.get_address().await {
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
                    cmd if cmd.starts_with("tx") => {
                        let parts: Vec<&str> = cmd.split_whitespace().collect();
                        if parts.len() == 3 || parts.len() == 4 {
                            let address = parts[1].to_string();
                            let amount = match parts[2].parse::<u64>() {
                                Ok(amount) => amount,
                                Err(_) => {
                                    println!("Invalid amount: {}", parts[2]);
                                    continue;
                                }
                            };
                            let contract_path = if parts.len() == 4 {
                                Some(parts[3].to_string())
                            } else {
                                None
                            };
                            let _ = tx
                                .send(Command::SendTransaction {
                                    address,
                                    amount,
                                    contract_path,
                                })
                                .await;
                        } else {
                            println!("Invalid 'tx' command format. It should be 'tx <address> <amount>' or 'tx <address> <amount> <contract_path>'");
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
    match server_future.await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Server future error: {}", e);
        }
    }
}

pub async fn get_ip() -> Result<String, ServerConfigError> {
    let response = reqwest::get("https://api.ipify.org").await?;
    let ip = response.text().await?;
    let ip_port = format!("{}:8080", ip);
    Ok(ip_port)
}
