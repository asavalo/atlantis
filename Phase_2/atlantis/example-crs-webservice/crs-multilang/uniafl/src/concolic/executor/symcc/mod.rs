use super::{ConcolicExecutor, ExecutorProfileData, SingleStepResult};
use crate::common::errors::Error;
#[allow(unused)]
pub use symcc::{SymCCExecutor, SymCCSingleStepSession};
#[allow(unused)]
pub use symqemu::{SymQEMUExecutor, SymQEMUSingleStepSession};

mod mmap_shmem;
mod resource_control;
mod symcc;
mod symqemu;
mod symqemu_helpers;

#[allow(unused)]
pub const SYMCC_TRACE_ENV_KEY: &str = "SYMCC_TRACE_FILE";
#[allow(unused)]
pub const SYMCC_ENABLE_FULL_TRACE_KEY: &str = "SYMCC_ENABLE_FULL_TRACE";
#[allow(unused)]
pub const SYMCC_INJECTION_FILE_ENV_KEY: &str = "SYMCC_INJECTION_FILE";
#[allow(unused)]
pub const SYMCC_SYMBOLIZE_DATA_LENGTH: &str = "SYMCC_SYMBOLIZE_DATA_LENGTH";
#[allow(unused)]
pub const SYMCC_SEM_KEY_ENV_KEY: &str = "SYMCC_SEM_KEY";
#[allow(unused)]
pub const SYMCC_FUNCTION_CALL_HOOK_ENV_KEY: &str = "SYMCC_FUNCTION_CALL_HOOK";
#[allow(unused)]
pub const SYMCC_MEMORY_LIMIT: i64= 1 * 1024 * 1024 * 1024;
#[allow(unused)]
pub const SYMQEMU_MEMORY_LIMIT: i64= 1 * 1024 * 1024 * 1024;
#[allow(unused)]
pub const SYMCC_CPU_PERIOD: u64= 10_000; 
#[allow(unused)]
pub const SYMCC_CPU_QUOTA: i64= 5_000; 
#[allow(unused)]
pub const SYMQEMU_CPU_PERIOD: u64= 10_000; 
#[allow(unused)]
pub const SYMQEMU_CPU_QUOTA: i64= 5_000; 

pub fn out_dir() -> String {
    std::env::vars()
        .find(|(k, _)| k == "OUT")
        .map(|(_, v)| v)
        .unwrap_or("/out".to_string())
}

pub type SymCCHook = String;

#[allow(unused)]
pub trait SymCCInstallFunctionCallHook {
    fn install_function_call_hook(
        &mut self,
        hook: SymCCHook,
    ) -> Result<Option<SymCCHook>, Error>;
    fn remove_function_call_hook(&mut self) -> Result<(), Error>;
    fn get_function_call_hook(&self) -> Result<Option<SymCCHook>, Error>;
}

#[allow(unused)]
pub trait SymCCEnableDataLengthSymbolization {
    fn enable_data_length_symbolization(&mut self);
    fn disable_data_length_symbolization(&mut self);
}
