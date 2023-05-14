use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use vec_node::{node::*};
use vec_server::server::*;

enum UserType {
    Validator,
    User,
}

enum OperationType {
    Transaction,
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
                    _ => println!("This role doesen't exist, choose 'validator' or 'user'."),
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
            let mut nsv = NodeService::new(scv).await;
            tokio::spawn(async move {
                nsv.start(Vec::new()).await.unwrap();
            });
            let operation_type: OperationType = loop {
                let readline = rl.readline("validator> (available: tx)");
                match readline {
                    Ok(line) => {
                        match line.trim() {
                            "tx" => break OperationType::Transaction,
                            _ => println!("This operation doesen't exist, choose 'tx'."),
                        }
                    },
                    Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                        return;
                    },
                    Err(err) => {
                        println!("Error: {:?}", err);
                        return;
                    },
                }
            };
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
            let scn = ServerConfig::default_n().await;
            let mut nsn = NodeService::new(scn).await;
            tokio::spawn(async move {
                nsn.start(Vec::new()).await.unwrap();
            });
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
