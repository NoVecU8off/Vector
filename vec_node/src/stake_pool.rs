use tokio::sync::{RwLock};
use std::collections::HashMap;
use tonic::codegen::Arc;

#[derive(Clone)]
pub struct StakePool {
    pool: Arc<RwLock<HashMap<String, u64>>>,
}

impl StakePool {
    pub async fn new() -> Self {
        StakePool {
            pool: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    // A delegator can stake a certain amount of cryptocurrency.
    pub async fn stake(&self, delegator: String, amount: u64) {
        let mut stakes = self.pool.write().await;
        let current_stake = stakes.entry(delegator).or_insert(0);
        *current_stake += amount;
    }

    // A delegator can unstake a certain amount of cryptocurrency.
    pub async fn unstake(&self, delegator: String, amount: u64) {
        let mut stakes = self.pool.write().await;
        if let Some(current_stake) = stakes.get_mut(&delegator) {
            *current_stake = current_stake.saturating_sub(amount);
        }
    }

    // Returns the total stake.
    pub async fn total_stake(&self) -> u64 {
        let stakes = self.pool.read().await;
        stakes.values().sum()
    }
}