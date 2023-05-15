use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Block header is missing")]
    MissingHeader,
    #[error(transparent)]
    MerkleTreeError(#[from] MerkleTreeError),
}

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Invalid public key in block")]
    InvalidPublicKey,
    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,
    #[error("Index too high")]
    IndexTooHigh,
    #[error("Failed to create genesis block: {0}")]
    GenesisBlockCreationFailed(#[from] Box<dyn std::error::Error>),
    #[error("Block with hash {0} not found")]
    BlockNotFound(String),
    #[error("Chain is empty")]
    ChainIsEmpty,
    #[error("Given height ({0}) too high - height ({1})")]
    HeightTooHigh(usize, usize),
    #[error("Invalid previous block hash: expected ({0}), got ({1})")]
    InvalidPreviousBlockHash(String, String),
    #[error("Block header is missing")]
    BlockHeaderMissing,
    #[error("Invalid public key in transaction input")]
    InvalidPublicKeyInTransactionInput,
    #[error("Missing block header")]
    MissingBlockHeader,
}

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Failed to compute hashes")]
    HashingError,
}

#[derive(Debug, Error)]
pub enum NodeServiceError {
    #[error("Failed to create chain: {0}")]
    ChainCreationError(String),
    #[error("Failed to setup server: {0}")]
    ServerSetupError(#[from] tonic::transport::Error),
    #[error("Failed to bootstrap node: {0}")]
    NodeBootstrapError(String),
    #[error("Address parsing error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error("Failed to broadcast transaction: {0}")]
    BroadcastTransactionError(String),
    #[error("Failed to bootstrap: {0}")]
    BootstrapError(String),
    #[error("Failed to make node client: {0}")]
    MakeNodeClientError(#[from] tonic::transport::Error),
    #[error("Failed to perform handshake: {0}")]
    HandshakeError(#[from] tonic::Status),
    #[error("Error encountered in bootstrap_network: {0}")]
    BootstrapNetworkError(String),
    #[error("Failed to create transaction: {0}")]
    CreateTransactionError(String),
    #[error("Failed to parse URI: {0}")]
    UriParseError(#[from] http::uri::InvalidUri),
    #[error("Failed to send shutdown signal")]
    ShutdownError,
}