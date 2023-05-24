use tonic::codegen::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

#[derive(Clone)]
pub struct Clock {
    time: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
    era: Arc<AtomicU64>,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            time: Arc::new(AtomicU64::new(0)),
            epoch: Arc::new(AtomicU64::new(0)),
            era: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn start(&self) {
        let time = Arc::clone(&self.time);
        let epoch = Arc::clone(&self.epoch);
        let era = Arc::clone(&self.era);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_nanos(100)).await;
                let prev_time = time.fetch_add(1, Ordering::SeqCst);
                if prev_time == u64::MAX {
                    time.compare_exchange(u64::MAX, 0, Ordering::SeqCst, Ordering::SeqCst).unwrap();
                    let prev_epoch = epoch.fetch_add(1, Ordering::SeqCst);
                    if prev_epoch == u64::MAX {
                        epoch.compare_exchange(u64::MAX, 0, Ordering::SeqCst, Ordering::SeqCst).unwrap();
                        era.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });
    }

    pub fn get_time(&self) -> u64 {
        self.time.load(Ordering::SeqCst)
    }

    pub fn add_to_time(&self, offset: u64) {
        self.time.fetch_add(offset, Ordering::SeqCst);
        let prev_time = self.time.load(Ordering::SeqCst);
        if prev_time == u64::MAX {
            self.time.store(0, Ordering::SeqCst);
            let prev_epoch = self.epoch.fetch_add(1, Ordering::SeqCst);
            if prev_epoch == u64::MAX {
                self.epoch.store(0, Ordering::SeqCst);
                self.era.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}
