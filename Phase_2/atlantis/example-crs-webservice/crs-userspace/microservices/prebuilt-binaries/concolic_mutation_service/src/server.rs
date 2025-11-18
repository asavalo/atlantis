use libafl::inputs::{BytesInput, HasMutatorBytes};
use libafl::observers::concolic::serialization_format::{
    MessageFileReader, DEFAULT_ENV_NAME, DEFAULT_SIZE,
};
use libafl::stages::concolic::{create_new_inputs, generate_mutations};
use libafl_bolts::{
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    AsSlice,
};
use mutation_service::mutation_service_server::MutationServiceServer;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{env, fs};
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;
use tonic::{transport::Server, Request, Response, Status};

use crate::config::ConcolicMutatorServiceConfig;
use crate::logger::ConciseConcolicMutationLogger;
use crate::mutation_service::mutation_service_server::MutationService;
use crate::mutation_service::{MutateRequest, MutateResponse};

mod config;
mod logger;

mod mutation_service {
    tonic::include_proto!("mutation_service");
}

struct ConcolicMutatorImpl {
    config: Arc<ConcolicMutatorServiceConfig>,
    logger: Arc<Mutex<Option<ConciseConcolicMutationLogger>>>,
}

/// Mutation result obtained via SMT solver
struct SmtMutationResult {
    /// Execution result of the mutated input. This is not present in LLM mutation results
    exit_code: i32,
    new_inputs: Vec<Vec<u8>>,
}

/// Mutation result obtained via LLM
struct LlmMutationResult {
    new_inputs: Vec<Vec<u8>>,
}

#[tonic::async_trait]
impl MutationService for ConcolicMutatorImpl {
    async fn mutate(
        &self,
        request: Request<MutateRequest>,
    ) -> Result<Response<MutateResponse>, Status> {
        let request = request.into_inner();
        let harness_id = request.harness_id;
        let input = request.input;

        let (new_inputs, exit_code) = self
            .mutate_impl(harness_id, &input)
            .map_err(|e| Status::internal(format!("Failed to mutate: {}", e.to_string())))?;
        let response = MutateResponse {
            new_inputs,
            exit_code,
        };
        Ok(Response::new(response))
    }
}

impl ConcolicMutatorImpl {
    fn new(config: ConcolicMutatorServiceConfig) -> Self {
        let logger = if let Some(log_path) = config.log_path.as_ref() {
            Some(ConciseConcolicMutationLogger::new(log_path))
        } else {
            None
        };
        Self {
            config: Arc::new(config),
            logger: Arc::new(Mutex::new(logger)),
        }
    }

    fn mutate_with_llm(&self, harness_id: &str, input: &[u8]) -> anyhow::Result<LlmMutationResult> {
        todo!()
    }

    fn mutate_with_smt(&self, harness_id: &str, input: &[u8]) -> anyhow::Result<SmtMutationResult> {
        let concolic_shmem = StdShMemProvider::new().unwrap().new_shmem(DEFAULT_SIZE)?;
        let request_ts = ConciseConcolicMutationLogger::current_time();
        // This is okay, because the environment is shared with the parent process
        concolic_shmem.write_to_env(DEFAULT_ENV_NAME)?;

        let mut input_file = NamedTempFile::new()?;
        input_file.write_all(input)?;

        // NOTE: these paths don't necessarily need to be absolute, thanks to the profile writer
        // sharing the cwd with the parent
        let input_file_path = input_file.path().to_path_buf();
        let profile_file_path = PathBuf::from_str("/dev/null")?;
        let executor_path = self.config.harnesses[harness_id]
            .executor_path
            .clone();

        // no need to write input to file because logger is responsible for managing inputs
        let mut added_envs = vec![];
        added_envs.push((
            "LLVM_PROFILE_FILE",
            profile_file_path.to_str().unwrap().to_string(),
        ));
        let mut child = Command::new(executor_path)
            .envs(added_envs.into_iter())
            .arg(input_file_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let exit_status = child.wait()?;
        let mut reader = MessageFileReader::from_length_prefixed_buffer(concolic_shmem.as_slice())?;
        let mut constraints = vec![];
        while let Some(maybe_msg) = reader.next_message() {
            if let Ok((expr_ref, expr)) = maybe_msg {
                constraints.push((expr_ref, expr));
            } else {
                panic!("Serialization error");
            }
        }
        let trace_ts = ConciseConcolicMutationLogger::current_time();

        let out = generate_mutations(constraints.clone().into_iter());
        let new_inputs: Vec<BytesInput> = create_new_inputs(BytesInput::new(input.to_vec()), out.mutations);
        let solve_ts = ConciseConcolicMutationLogger::current_time();

        if let Some(logger) = self.logger.lock().unwrap().as_ref() {
            // write atomically
            logger.record_request(request_ts, harness_id, input)?;
            logger.record_trace(trace_ts, harness_id, constraints)?;
            logger.record_query_outcomes(solve_ts, harness_id, out.sat_queries, out.unsat_queries)?;
            logger.record_new_inputs(solve_ts, harness_id, new_inputs.as_slice())?;
        }
        Ok(SmtMutationResult {
            new_inputs: new_inputs.into_iter().map(|x| x.bytes().to_vec()).collect(),
            exit_code: exit_status.code().unwrap_or(-1),
        })
    }

    fn mutate_impl(&self, harness_id: String, input: &[u8]) -> anyhow::Result<(Vec<Vec<u8>>, i32)> {
        let mut new_inputs = vec![];
        let mut exit_code = 0;

        if self.config.use_llm {
            let res = self.mutate_with_llm(&harness_id, input)?;
            new_inputs.extend(res.new_inputs);
        }

        if self.config.use_smt {
            let res = self.mutate_with_smt(&harness_id, input)?;
            new_inputs.extend(res.new_inputs);
            exit_code = res.exit_code;
        }

        Ok((new_inputs, exit_code))
    }
}

async fn execute_service(config_path: &str) -> anyhow::Result<()> {
    // read config from args.config_path
    let config_str = fs::read_to_string(&config_path)?;
    let config: ConcolicMutatorServiceConfig = serde_json::from_str(&config_str)?;

    if !config.use_llm && !config.use_smt {
        return Err(anyhow::format_err!(
            "At least one of use_llm and use_smt must be true"
        ));
    }

    let svc = MutationServiceServer::new(ConcolicMutatorImpl::new(config.clone()));
    Server::builder()
        .add_service(svc)
        .serve(config.grpc_addr.parse()?)
        .await?;
    Ok(())
}

pub fn main() {
    let config_path = env::var("CONCOLIC_CONFIG_PATH").expect("CONCOLIC_CONFIG_PATH not set");
    let rt = Runtime::new().expect("Failed to create runtime");
    rt.block_on(execute_service(&config_path))
        .expect("Failed to execute service");
}
