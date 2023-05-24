use dashmap::DashMap;
use tonic::codegen::Arc;

#[derive(Clone)]
pub struct StakePool {
    pool: Arc<DashMap<String, u64>>,
}

impl StakePool {
    pub async fn new() -> Self {
        StakePool {
            pool: Arc::new(DashMap::new()),
        }
    }
    
    pub async fn stake(&self, delegator: String, amount: u64) {
        let mut current_stake = self.pool.entry(delegator).or_insert(0);
        *current_stake += amount;
    }

    pub async fn unstake(&self, delegator: String, amount: u64) {
        if let Some(mut current_stake) = self.pool.get_mut(&delegator) {
            *current_stake = current_stake.saturating_sub(amount);
        }
    }

    pub async fn total_stake(&self) -> u64 {
        self.pool.iter().map(|entry| *entry.value()).sum()
    }
}