use std::path::PathBuf;

use crate::concolic::ConcolicExecutor;

pub struct ConcolicLLM {}

impl ConcolicExecutor for ConcolicLLM {
    fn execute(&mut self, _testcase: &PathBuf) -> PathBuf {
        todo!("ConcolicLLM.execute")
    }
}
