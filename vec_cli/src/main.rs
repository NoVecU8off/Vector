use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use vec_node::{node::*};
use vec_server::server::*;

#[derive(Debug)]
enum UserType {
    Validator,
    User,
}

enum Command {
    SendTransaction { to: Vec<u8>, amount: i64 },
    GetBalance,
    Stop,
}

#[tokio::main]
async fn main() {
    let mut rl = DefaultEditor::new().unwrap();
    let user_type: UserType = loop {
        let readline = rl.readline("Choose your role  ('user'/'validator'): ");
        match readline {
            Ok(line) => {
                match line.trim() {
                    "validator" => break UserType::Validator,
                    "user" => break UserType::User,
                    _ => println!("This role doesn't exist, choose 'validator' or 'user'."),
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
    };

    match user_type {
        UserType::Validator => {
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

            let server_future = tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Some(Command::SendTransaction { to, amount}) => {
                            match nsv.make_tx(&to, amount as u64).await {
                                Ok(_) => {
                                    println!("Error broadcasting transaction");
                                }
                                Err(e) => {
                                    println!("Error creating and broadcasting transaction: {:?}", e);
                                }
                            }
                        },
                        Some(Command::GetBalance) => {
                            // handle balance command
                        },
                        Some(Command::Stop) => {
                            // handle stop command
                            break;
                        },
                        None => {
                            // channel closed
                            break;
                        },
                    }
                }
            });

            loop {
                let readline = rl.readline("validator> ");
                match readline {
                    Ok(line) => {
                        let command = line.trim();
                        match command {
                            cmd if cmd.starts_with("send") => {
                                let parts: Vec<&str> = cmd.split_whitespace().collect();
                                if parts.len() == 4 {
                                    let recipient = parts[1].as_bytes().to_vec();
                                    let amount = parts[3].parse::<i64>().unwrap_or(0);
                                    let _ = tx.send(Command::SendTransaction { to: recipient, amount }).await;
                                } else {
                                    println!("Invalid 'send' command format. It should be 'send <recipient> to <amount>'");
                                }
                            },
                            "get balance" => {
                                let _ = tx.send(Command::GetBalance).await;
                            },
                            "stop" => {
                                let _ = tx.send(Command::Stop).await;
                                break;
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
        },
        UserType::User => {
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
            let scn = ServerConfig::default_v().await;
            let nsn_result = NodeService::new(scn).await;
            match nsn_result {
                Ok(mut nsn) => {
                    tokio::spawn(async move {
                        nsn.start(Vec::new()).await.unwrap();
                    });
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
            loop {
                let readline = rl.readline("user> ");
                match readline {
                    Ok(line) => {
                        let command = line.trim();
                        // process user commands
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
        },
    }
}
