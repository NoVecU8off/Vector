#[macro_export]
macro_rules! hash {
    ($($arg:expr),*) => {{
        let mut hasher = Keccak256::new();
        $( hasher.update($arg); )*
        hasher.finalize()
    }};
}
