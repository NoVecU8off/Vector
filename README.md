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

## License
This project is licensed under the Apache-2.0 License - see the LICENSE file for details.

## Acknowledgments
I am grateful to the Rust and gRPC communities for their comprehensive documentation and libraries, which have contributed significantly to the development of Vector.

## Contact
For any queries, please raise an issue in our GitHub repository, or contact me at andrewnovikoff@outlook.com.

Welcome to Vector, and thank you for being part of my journey!