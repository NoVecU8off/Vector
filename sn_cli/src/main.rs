use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use sn_node::{node::*};
use sn_server::server::*;

enum UserType {
    Validator,
    User,
}

#[tokio::main]
async fn main() {
    let mut rl = DefaultEditor::new().unwrap();
    let user_type: UserType = loop {
        let readline = rl.readline("Какой ты сегодня смешарик? (крош/чмо): ");
        match readline {
            Ok(line) => {
                match line.trim() {
                    "крош" => break UserType::Validator,
                    "чмо" => break UserType::User,
                    _ => println!("Такого смешарика не существует, выбери 'крош' или 'чмо'."),
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
                let readline = rl.readline("Вводи адресс гниды (или 'пошел нахуй' чтобы продолжить): ");
                match readline {
                    Ok(line) => {
                        let line = line.trim();
                        if line == "пошел нахуй" {
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
            loop {
                let readline = rl.readline("validator> ");
                match readline {
                    Ok(line) => {
                        let command = line.trim();
                        // process validator commands
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
        UserType::User => {
            let mut rl = DefaultEditor::new().unwrap();
            let mut nodes_to_bootstrap = Vec::new();
            loop {
                let readline = rl.readline("Вводи адресс гниды (или 'иди нахуй' чтобы продолжить): ");
                match readline {
                    Ok(line) => {
                        let line = line.trim();
                        if line == "пошел нахуй" {
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
