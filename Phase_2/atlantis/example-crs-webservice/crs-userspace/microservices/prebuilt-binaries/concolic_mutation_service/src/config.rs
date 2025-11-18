use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub type HarnessId = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarnessInfo {
    pub executor_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConcolicMutatorServiceConfig {
    pub harnesses: HashMap<HarnessId, HarnessInfo>,
    pub grpc_addr: String,
    pub log_path: Option<String>,
    pub use_llm: bool,
    pub use_smt: bool,
}
