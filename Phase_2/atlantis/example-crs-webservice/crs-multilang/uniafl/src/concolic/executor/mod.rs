use crate::common::{Error, InputID};
use crate::concolic::ExecutorProfileData;
mod symcc;

#[allow(unused)]
pub use symcc::{
    SymCCEnableDataLengthSymbolization, SymCCExecutor, SymCCHook,
    SymCCInstallFunctionCallHook, SymCCSingleStepSession, SymQEMUExecutor,
    SymQEMUSingleStepSession, SYMCC_MEMORY_LIMIT, SYMQEMU_MEMORY_LIMIT,
};

pub enum SingleStepResult<T> {
    Continued(T),
    Finished(T),
}

#[allow(unused)]
impl<T> SingleStepResult<T> {
    pub fn get_trace(self) -> T {
        match self {
            SingleStepResult::Continued(trace) => trace,
            SingleStepResult::Finished(trace) => trace,
        }
    }
}

pub trait SingleStepSession {
    fn kill(&mut self) -> Result<(), Error>;
}

pub trait ConcolicExecutor<T, S>
where
    S: SingleStepSession,
{
    fn execute(&mut self, input_id: InputID, input: &[u8]) -> Result<T, Error>;

    fn execute_single_step(&mut self, input_id: InputID, input: &[u8]) -> Result<S, Error>;

    // The executor returns a trace for every path constraint
    fn single_step(&mut self, session: &mut S) -> Result<SingleStepResult<T>, Error>;

    fn profile_data(&self) -> &ExecutorProfileData;
}
