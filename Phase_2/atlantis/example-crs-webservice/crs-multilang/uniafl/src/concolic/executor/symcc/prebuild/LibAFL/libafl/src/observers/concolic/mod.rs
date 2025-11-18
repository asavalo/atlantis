include!("./sym_expr.rs");

/// The environment name used to identify the hitmap for the concolic runtime.
pub const HITMAP_ENV_NAME: &str = "LIBAFL_CONCOLIC_HITMAP";

/// The name of the environment variable that contains the byte offsets to be symbolized.
pub const SELECTIVE_SYMBOLICATION_ENV_NAME: &str = "LIBAFL_SELECTIVE_SYMBOLICATION";

/// The name of the environment variable that signals the runtime to concretize floating point operations.
pub const NO_FLOAT_ENV_NAME: &str = "LIBAFL_CONCOLIC_NO_FLOAT";

/// The name of the environment variable that signals the runtime to perform expression pruning.
pub const EXPRESSION_PRUNING: &str = "LIBAFL_CONCOLIC_EXPRESSION_PRUNING";

pub mod serialization_format;
mod metadata;
pub use metadata::ConcolicMetadata;

mod observer;
pub use observer::ConcolicObserver;
