use clap::{App, Arg, SubCommand};

fn main() {
    let matches = App::new("My Blockchain CLI")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("A CLI for the My Blockchain project")
        .subcommand(
            SubCommand::with_name("send")
                .about("make transaction")
                .arg(
                    Arg::with_name("to")
                        .short("t")
                        .long("to")
                        .value_name("TO_ADDRESS")
                        .help("Recipient's address")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("amount")
                        .short("a")
                        .long("amount")
                        .value_name("AMOUNT")
                        .help("Amount to be sent")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("get balance")
                .about("Get the balance of an address")
                .arg(
                    Arg::with_name("address")
                        .short("a")
                        .long("address")
                        .value_name("ADDRESS")
                        .help("Address to check balance for")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .get_matches();

    // Handle subcommands
    match matches.subcommand() {
        ("send", Some(send_matches)) => {
            // Call the send transaction function
            let to_address = send_matches.value_of("to").unwrap();
            let amount = send_matches.value_of("amount").unwrap().parse::<u64>().expect("Invalid amount");

            // Call your send transaction function here
            // e.g., sn_transaction::send_transaction(from_address, to_address, amount);
        }
        ("balance", Some(balance_matches)) => {
            // Call the get balance function
            let address = balance_matches.value_of("address").unwrap();

            // Call your get balance function here
            // e.g., let balance = sn_transaction::get_balance(address);
            // println!("Balance: {}", balance);
        }
        _ => {
            // If no subcommand was used or it was not recognized, print the help message
            println!("{}", matches.usage());
        }
    }
}
