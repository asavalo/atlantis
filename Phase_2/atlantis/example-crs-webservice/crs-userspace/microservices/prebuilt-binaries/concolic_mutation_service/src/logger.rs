use libafl::inputs::{BytesInput, HasMutatorBytes};
use libafl::observers::concolic::{SymExpr, SymExprRef};
use libafl::stages::concolic::{SatQuery, StringReplacement, UnsatQuery};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub enum OtherLogs {
    ConcolicMutationRequest {
        timestamp: Duration,
        harness_id: String,
        input_bytes: Vec<u8>,
    },

    ConcolicMutationTraceResult {
        timestamp: Duration,
        harness_id: String,
        trace: Vec<(SymExprRef, SymExpr)>,
    },
    ConcolicMutationNewInput {
        timestamp: Duration,
        harness_id: String,
        new_input: Vec<u8>,
    },
    ConcolicMutationUnsatOutcome {
        timestamp: Duration,
        harness_id: String,
        site_id: usize,
        assertions: Vec<String>,
    },
    ConcolicMutationSatOutcome {
        timestamp: Duration,
        harness_id: String,
        site_id: usize,
        taken: bool,
        assertions: Vec<String>,
        solution_index: usize,
    },
}

pub struct ConciseConcolicMutationLogger {
    log_path: String,
}

impl ConciseConcolicMutationLogger {
    pub fn new(log_path: &str) -> Self {
        Self {
            log_path: log_path.to_string(),
        }
    }

    fn append_to_log<L: Serialize>(&self, e: L) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        writeln!(file, "{}", &serde_json::to_string(&e)?)?;
        Ok(())
    }

    pub fn record_request(
        &self,
        timestamp: Duration,
        harness_id: &str,
        input_bytes: &[u8],
    ) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        writeln!(
            file,
            "{}",
            &serde_json::to_string(&OtherLogs::ConcolicMutationRequest {
                timestamp,
                harness_id: harness_id.to_string(),
                input_bytes: input_bytes.to_vec()
            })?
        )?;
        Ok(())
    }

    pub fn record_trace(
        &self,
        timestamp: Duration,
        harness_id: &str,
        trace: Vec<(SymExprRef, SymExpr)>,
    ) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        writeln!(
            file,
            "{}",
            &serde_json::to_string(&OtherLogs::ConcolicMutationTraceResult {
                timestamp,
                harness_id: harness_id.to_string(),
                trace,
            })?
        )?;
        Ok(())
    }

    pub fn record_query_outcomes(
        &self,
        timestamp: Duration,
        harness_id: &str,
        sat_queries: Vec<SatQuery>,
        unsat_queries: Vec<UnsatQuery>,
    ) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        for sat_query in sat_queries {
            self.append_to_log(&OtherLogs::ConcolicMutationSatOutcome {
                timestamp,
                harness_id: harness_id.to_string(),
                site_id: sat_query.site_id,
                taken: sat_query.taken,
                assertions: sat_query.assertions,
                solution_index: sat_query.solution_index,
            })?;
        }

        for unsat_query in unsat_queries {
            self.append_to_log(&OtherLogs::ConcolicMutationUnsatOutcome {
                timestamp,
                harness_id: harness_id.to_string(),
                site_id: unsat_query.site_id,
                assertions: unsat_query.assertions,
            })?;
        }
        Ok(())
    }

    pub fn record_new_inputs(
        &self,
        timestamp: Duration,
        harness_id: &str,
        new_inputs: &[BytesInput],
    ) -> Result<(), anyhow::Error> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.log_path)?;
        for new_input in new_inputs {
            writeln!(
                file,
                "{}",
                &serde_json::to_string(&OtherLogs::ConcolicMutationNewInput {
                    timestamp,
                    harness_id: harness_id.to_string(),
                    new_input: new_input.bytes().to_vec()
                })?
            )?;
        }
        Ok(())
    }

    pub fn current_time() -> Duration {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
    }
}
