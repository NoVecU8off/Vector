# Vector

Welcome to Vector, my blockchain solution designed in pure Rust. This project leverages the efficiency and concurrency of Rust alongside gRPC (protobuf) for network communication, and a custom PBFT-like consensus mechanism to ensure data integrity across the network.
(UPD: the consensus mechanism was considered useless due to its inefficiency + unscalability and was permanetly removed, currently using simple Proof of Work CM (Simple and Straightforward).

Among its core privacy features, Vector adopts the bLSAG signature scheme and utilizes stealth (one-time) addresses, similar to Monero. It integrates these privacy-ensuring mechanisms into a custom Unspent Transaction Output (UTXO) model to create a highly secure environment for transactions. Vector's design caters to the evolving needs of developers and businesses, providing a scalable, efficient, and secure network.

## Key Features And Goals

- **Complete Anonymity**: Vector incorporates the bLSAG signature scheme and stealth (one-time) addresses to ensure complete anonymity in all transactions, making it an ideal choice for privacy-focused applications.
- **Pure Rust**: The project is crafted entirely in Rust, offering memory safety without the need for garbage collection and providing concurrent execution for optimal performance.
- **gRPC (Protobuf) Communication**: Vector employs Google's high-performance, open-source universal RPC framework, gRPC (protobuf), for efficient and reliable network communication.
- **UTXO Model**: The Unspent Transaction Output (UTXO) model is used for transaction management, ensuring high levels of security and privacy.
- **PoW Consensus Mechanism**: Currently Vector works on PoW CM, but i think that I'll try to develop something like DPoS-kind consensus mechanism, we'll see. (DEV IN PROCESS)
- **Scalability**: Designed to scale seamlessly, Vector should handle a growing number of transactions without compromising on speed or security.

## Modules and explanations:

1. **vec_utils**: There are hashing and mining functions for Block (protobuf message declared in .proto).
2. **vec_chain**: There are validation and processing functions for the Blocks and Transactions (in other words, these are operations that locally display global changes in the state of the network).
3. **vec_cli**: Сommand-line interface for interaction.
4. **vec_crypto**: Here the most important cryptographic operations take place (mathematical operations on the Edwards elliptic curve, calculation of user keys, creation of signatures and proofs).
5. **vec_errors**: Just custom errors.
6. **vec_mempool**: Mempool ops, nothing special.
7. **vec_merkle**: My Merkle Tree implementation, simplistic and works fine.
8. **vec_node**: Here the most interesting p2p operations take place (organizing client-server, gRPC communication methods, user-synchronization and pull-no-push system implementation).
9. **vec_proto**: The heart of the code. All general types that I am working on declared here.
11. **vec_storage**: Data bases for blocks, key images, ip_db (at the moment it is not used, I think about whether it is needed at all).
12. **vec_utils**: Environment operations (hashing) for the Transaction (there used to be a lot of code here, but it has moved, need to abolish this Workspace later).

## Current tasks and problems

1. **Bottlenecks**: At present, asynchronous methods are not fully parallelised, there are potential threats in the process of "avalanche" gRPC communications (e.g. situation with simultaneous incoming transactions from N-th number of participants, where N >> 10). More in-depth investigation into the processes is required.
2. **Contracts**: At the moment, the contract code can be absolutely anything (within the WebAssembly code). A general contract schema designation is required, which will further avoid increasing the weight of the blockchain by adding invalid (unexecutable) contracts.
3. **Consensus**: Curretly, the consensus (Proof of Work) can be considered unrealised. There are no methods for dealing with fork situations in the protocol. Block complexity is constant (plan to make this parameter dynamic).

## License

This project is licensed under the Apache-2.0 License - see the LICENSE file for details.

## Contact

For any queries, please raise an issue in our GitHub repository, or contact me at andrewnovikoff@outlook.com.
