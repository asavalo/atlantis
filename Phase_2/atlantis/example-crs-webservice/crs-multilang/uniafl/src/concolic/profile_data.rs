#[allow(unused)]
#[cfg(feature = "concolic_profiling")]
mod profile_data {
    use crate::common::Error;
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};

    pub trait ConcolicProfileData: Serialize + Deserialize<'static> {
        fn name() -> &'static str;
        fn write(&self, out_dir: &PathBuf) -> Result<(), Error> {
            let file_path = out_dir.join(format!("{}.json", Self::name()));
            let file = std::fs::File::create(file_path)?;
            serde_json::to_writer(file, self)?;
            Ok(())
        }
    }

    #[derive(Serialize, Clone, Deserialize, Default)]
    pub struct ExecutorProfileData {
        pub spawn_failure_cnt: usize,
        pub other_failure_cnt: usize,
        pub nonzero_exits_cnt: usize,
        pub timeouts_cnt: usize,
        pub missing_traces_cnt: usize,
        pub successful_execs_cnt: usize,
        pub total_exec_time_ms: u64,
    }

    #[derive(Serialize, Clone, Deserialize, Default)]
    pub struct SymStateProfileData {
        pub unsat_path_constraint_count: usize,
        pub sat_path_constraint_count: usize,
        pub total_crossover_count: usize,
        pub total_solving_time_ms: u64,
        pub solver_invocation_count: usize,
    }

    #[derive(Serialize, Clone, Deserialize, Default)]
    pub struct LlmQueryProfileData {
        pub total_query_count: usize,
        pub total_query_time_ms: u64,
        pub total_new_seed_count: usize,
    }

    impl ConcolicProfileData for ExecutorProfileData {
        fn name() -> &'static str {
            "executor_profile_data"
        }
    }

    impl ConcolicProfileData for SymStateProfileData {
        fn name() -> &'static str {
            "symstate_profile_data"
        }
    }

    impl ConcolicProfileData for LlmQueryProfileData {
        fn name() -> &'static str {
            "llm_query_profile_data"
        }
    }
}

#[cfg(feature = "concolic_profiling")]
pub use profile_data::*;
