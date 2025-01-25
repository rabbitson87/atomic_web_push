#[macro_export]
macro_rules! log_debug {
    ($($rest:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($rest)*)
        }
    };
}
