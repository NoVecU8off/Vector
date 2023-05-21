use vec_chain::chain::Chain;
use vec_store::block_store::BlockStorer;
use vec_store::block_store::MemoryBlockStore;
use vec_store::utxo_store::UTXOSetStorer;
use vec_store::utxo_store::MemoryUTXOSet;

#[tokio::test]
async fn test_genesis_chain_creation() {
    let block_storer: Box<dyn BlockStorer> = Box::new(MemoryBlockStore::new());
    let utxo_set_storer: Box<dyn UTXOSetStorer> = Box::new(MemoryUTXOSet::new());
    let chain = Chain::genesis_chain(block_storer, utxo_set_storer).await;
    assert!(chain.is_ok())
}

#[tokio::test]
async fn test_new_chain_creation() {
    let block_storer: Box<dyn BlockStorer> = Box::new(MemoryBlockStore::new());
    let utxo_set_storer: Box<dyn UTXOSetStorer> = Box::new(MemoryUTXOSet::new());
    let chain = Chain::new(block_storer, utxo_set_storer).await;
    assert!(chain.is_ok())
}



