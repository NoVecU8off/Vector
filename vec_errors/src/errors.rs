use thiserror::Error;

pub enum VectorError {
    UTXOStore(UTXOStorageError),
    BlockStore(BlockStorageError),
    BlockOps(BlockOpsError),
    MerkleTree(MerkleTreeError),
    Chain(ChainOpsError),
    NodeService(NodeServiceError),
    ValidatorService(ValidatorServiceError),
    ServerConfig(ServerConfigError),
}

#[derive(Debug, Error)]
pub enum UTXOStorageError {
    #[error("The specified UTXO was not found")]
    UtxoNotFound,
    #[error("No UTXOs were found for the specified criteria")]
    UtxosNotFound,
    #[error("Unable to acquire write lock")]
    WriteLockError,
    #[error("Unable to acquire read lock")]
    ReadLockError,
    #[error("Insufficient UTXOs to fulfill the amount needed")]
    InsufficientUtxos,
    #[error("Unexpected error")]
    UnexpectedError,
    #[error("Unable to serialize UTXO")]
    SerializationError,
    #[error("Unable to deserialize UTXO")]
    DeserializationError,
    #[error("Unable to write to DB")]
    WriteError,
    #[error("Unable to read from DB")]
    ReadError,

}

#[derive(Debug, Error)]
pub enum BlockStorageError {
    #[error("Unable to acquire write lock")]
    WriteLockError,
    #[error("Unable to acquire read lock")]
    ReadLockError,
    #[error(transparent)]
    SledError(sled::Error),
    #[error(transparent)]
    TaskPanic(tokio::task::JoinError),
    #[error(transparent)]
    BlockOpsError(#[from] BlockOpsError),
    #[error("Unable to serialize block")]
    SerializationError,
    #[error("Unable to write to DB")]
    WriteError,
    #[error("Unable to deserialize block")]
    DeserializationError,
    #[error("Unable to read from DB")]
    ReadError,
}

#[derive(Debug, Error)]
pub enum StakePoolStorageError {
    #[error("Unable to serialize SP")]
    SerializationError,
    #[error("Unable to deserialize SP")]
    DeserializationError,
    #[error("Unable to write to DB")]
    WriteError,
    #[error("Unable to read from DB")]
    ReadError,
    #[error("Pool doesen't exist")]
    NonexistentPool,
    #[error(transparent)]
    SledError(sled::Error),
    #[error(transparent)]
    SledTransactionError(#[from] sled::transaction::ConflictableTransactionError<Box<StakePoolStorageError>>),
}

#[derive(Debug, Error)]
pub enum BlockOpsError {
    #[error("Block header is missing")]
    MissingHeader,
    #[error("Merkle tree is empty")]
    EmptyTree,
    #[error(transparent)]
    MerkleTreeError(#[from] MerkleTreeError),
}

#[derive(Debug, Error)]
pub enum MerkleTreeError {
    #[error("Failed to compute hashes")]
    HashingError,
    #[error("Transaction not found in Merkle Tree")]
    TransactionNotFound,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Doublespend detected")]
    DoubleSpend,
    #[error("Transaction has invalid signature")]
    InvalidSignature,
    #[error("Transaction has insufficientInput")]
    InsufficientInput,
    #[error("Transaction check error")]
    TransactionCheckError,
    #[error("Transaction is missing input")]
    MissingInput,
    #[error("Mismatched pk key")]
    PublicKeyMismatch,
    #[error("Provided range proofs are incorrect")]
    IncorrectRangeProofs,
}

#[derive(Debug, Error)]
pub enum ChainOpsError {
    #[error("Given index is too high")]
    IndexTooHigh,
    #[error("Missing block's header")]
    MissingBlockHeader,
    #[error(transparent)]
    BlockStorageError(#[from] BlockStorageError),
    #[error("Couldn't find block with hash: {0}")]
    BlockNotFound(String),
    #[error("Chain is empty")]
    ChainIsEmpty,
    #[error("Given height {height} is out of bounds, max height is: {max_height}")]
    HeightTooHigh {
        height: usize,
        max_height: usize
    },
    #[error(transparent)]
    BlockOpsError(#[from] BlockOpsError),
    #[error("Invalid pk key in the block")]
    InvalidPublicKey,
    #[error("Invalid previous block's hash, expected: {expected}, got: {got}")]
    InvalidPreviousBlockHash {
        expected: String,
        got: String
    },
    #[error("Invalid pk key in the transaction's input")]
    InvalidPublicKeyInTransactionInput,
    #[error("Invalid transaction's signature")]
    InvalidTransactionSignature,
    #[error("Invalid transaction's input signature")]
    InvalidInputSignature,
    #[error(transparent)]
    Ed25519DalekError(#[from] ed25519_dalek::ed25519::Error),
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    #[error(transparent)]
    TaskPanic(tokio::task::JoinError),
    #[error(transparent)]
    UTXOStorageError(#[from] UTXOStorageError),
}

#[derive(Debug, Error)]
pub enum NodeServiceError {
    #[error("Failed to create chain: {0}")]
    ChainCreationError(String),
    #[error("Failed to setup server: {0}")]
    TonicTransportError(#[from] tonic::transport::Error),
    #[error("Failed to bootstrap node: {0}")]
    NodeBootstrapError(String),
    #[error("Address parsing error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
    #[error("Failed to broadcast transaction: {0}")]
    BroadcastTransactionError(String),
    #[error("Failed to bootstrap: {0}")]
    BootstrapError(String),
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
    #[error("Failed make node client")]
    MakeNodeClientError,
    #[error("Peer not found")]
    PeerNotFound,
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Can not pull from non-validator node")]
    PullFromNonValidatorNode,
    #[error("Pull from the leader failed")]
    PullStateError,
    #[error(transparent)]
    UTXOStorageError(#[from] UTXOStorageError),
    #[error("Failed to read certificates")]
    FailedToReadCertificates,
    #[error(transparent)]
    ServerConfigError(#[from] ServerConfigError),
    #[error(transparent)]
    ValidatorServiceError(#[from] ValidatorServiceError),
    #[error(transparent)]
    MissingBlockHeader(#[from] ChainOpsError),
    #[error(transparent)]
    MissingHeader(#[from] BlockOpsError),
    #[error(transparent)]
    TaskPanic(#[from] tokio::task::JoinError), 
    #[error("Unable to open Sled DB")]
    SledOpenError,
}

#[derive(Debug, Error)]
pub enum ValidatorServiceError {
    #[error(transparent)]
    MerkleTreeError(#[from] MerkleTreeError),
    #[error("Failed to join broadcast transaction")]
    TransactionBroadcastFailed,
    #[error("Failed to join broadcast hash")]
    HashBroadcastFailed,
    #[error("Failed to join peer broadcast")]
    PeerBroadcastFailed,
    #[error("Failed to join broadcast leader block")]
    LeaderBlockBroadcastFailed,
    #[error("Failed to join broadcast vote")]
    VoteBroadcastFailed,
    #[error("No created block found")]
    NoCreatedBlockFound,
    #[error(transparent)]
    ChainOpsError(#[from] ChainOpsError),
    #[error(transparent)]
    BlockOpsError(#[from] BlockOpsError),
    #[error(transparent)]
    BlockStorageError(#[from] BlockStorageError),
    #[error("Broadcast error: {0}")]
    BroadcastError(#[from] tokio::sync::broadcast::error::RecvError),
}

#[derive(Debug, Error)]
pub enum ServerConfigError {
    #[error("Failed to read server certificate and key: {0}")]
    FailedToReadServerCertAndKey(std::io::Error),
    #[error("Failed to read server cetificate: {0}")]
    FailedToReadServerCert(std::io::Error),
    #[error("Failed to read server key: {0}")]
    FailedToReadServerKey(std::io::Error),
    #[error("Failed to read server root certificate: {0}")]
    FailedToReadServerRootCert(std::io::Error),
    #[error("Failed to read client cetificate: {0}")]
    FailedToReadClientCert(std::io::Error),
    #[error("Failed to read client key: {0}")]
    FailedToReadClientKey(std::io::Error),
    #[error("Failed to read client root certificate: {0}")]
    FailedToReadClientRootCert(std::io::Error),
    #[error("Failed to serialize config: {0}")]
    FailedToSerializeConfig(bincode::Error),
    #[error("Failed to create config file: {0}")]
    FailedToCreateConfigFile(std::io::Error),
    #[error("Failed to write to config file: {0}")]
    FailedToWriteToConfigFile(std::io::Error),
    #[error("Failed to open config file: {0}")]
    FailedToOpenConfigFile(std::io::Error),
    #[error("Failed to read from config file: {0}")]
    FailedToReadFromConfigFile(std::io::Error),
    #[error("Failed to deserialize config: {0}")]
    FailedToDeserializeConfig(bincode::Error),
    #[error("HTTP request failed: {0}")]
    HttpRequestFailed(reqwest::Error),
}

impl From<reqwest::Error> for ServerConfigError {
    fn from(err: reqwest::Error) -> ServerConfigError {
        ServerConfigError::HttpRequestFailed(err)
    }
}