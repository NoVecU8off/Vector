use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use tonic::codegen::Arc;

#[derive(Clone)]
pub struct Clock {
    millis: Arc<AtomicU64>,
    sec: Arc<AtomicU64>,
    epoch: Arc<AtomicU64>,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            millis: Arc::new(AtomicU64::new(0)),
            sec: Arc::new(AtomicU64::new(0)),
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn start(&self) {
        let millis = Arc::clone(&self.millis);
        let sec = Arc::clone(&self.sec);
        let epoch = Arc::clone(&self.epoch);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                let prev_millis = millis.fetch_add(1, Ordering::SeqCst);
                if prev_millis + 1 >= 1000 {
                    millis.store(0, Ordering::SeqCst);
                    let prev_sec = sec.fetch_add(1, Ordering::SeqCst);
                    if prev_sec + 1 >= 86400 * 2 {
                        sec.store(0, Ordering::SeqCst);
                        epoch.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });
    }

    pub fn get_time(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }

    pub fn add_to_time(&self, offset: u64) {
        self.millis.fetch_add(offset, Ordering::SeqCst);
    }
}
