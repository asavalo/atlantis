use crate::common::errors::Error as UniaflError;
use crate::common::InputID;
use crate::concolic::{
    new_symcc_symstate, new_symqemu_symstate, ConcolicExecutor, ConcolicProfileData, Solver,
    SymCCAux, SymCCPathConstraintMetadata, SymCCSolutionCache, SymCCSymState, SymCCSymStateConfig,
    SymQEMUSymState, SymQEMUSymStateConfig, SymState, SymStateProcessResult,
};
use crate::input_gen::server::{InputGenPool, InputGenWorker, Output, Outputs};
use crate::msa::manager::MsaSeed;
use file_lock::{FileLock, FileOptions};
use serde::{Deserialize, Serialize};
use std::boxed::Box;
use std::fs::File;
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{fs::read_to_string, io::Write, path::PathBuf, str::FromStr};
use wait_timeout::ChildExt;

macro_rules! concolic_log {
    ($outputs:expr, $($arg:tt)*) => {
        #[cfg(feature = "log")]
        $outputs.log("concolic", format!($($arg)*))
    };
}

pub struct ConcolicPool<'ctxs> {
    symcc_config: Option<SymCCSymStateConfig>,
    symqemu_config: SymQEMUSymStateConfig,
    workdir: PathBuf,
    solution_cache: Arc<RwLock<SymCCSolutionCache<'ctxs>>>,
    max_worker_cnt: usize,
    worker_counter: usize,
    #[allow(unused)]
    z3_ctx_shared: Box<z3::Context>,
}

#[derive(Deserialize)]
struct ConcolicConfigInner {
    harness: String,
    symqemu: String,
    symqemu_harness: String,
    workdir: String,
    executor_timeout_ms: Option<u64>,
    utilization: Option<f64>,
    llvm_symbolizer: String,
    python: String,
    resolve_script: String,
}

#[derive(Deserialize)]
struct ConcolicConfig {
    max_len: usize,
    core_ids: Vec<usize>,
    concolic: ConcolicConfigInner,
}

impl<'ctxs> ConcolicPool<'ctxs> {
    /// Will return a true if the SymCC instrumented harness exists
    fn get_symcc_cp(config: &ConcolicConfig) -> Result<bool, UniaflError> {
        let mut child = Command::new("get_symcc_cp").spawn()?;
        match child.wait_timeout(Duration::new(60 * 60, 0))? {
            Some(_) => {
                let harness = PathBuf::from(&config.concolic.harness);
                Ok(harness.exists())
            }
            None => {
                child.kill()?;
                Ok(false)
            }
        }
    }
}

/// ctxs: lifetime of z3} context used by solution cache.
/// ctxp: lifetime of z3 context used by symstate in each worker.
/// Technically, the lifetimes of z3 contexts for each workers are different.
/// However, we can safely assume that the lifetime of ctxp is 'static because they are never
/// deallocated.
impl<'ctxs> InputGenPool for ConcolicPool<'ctxs> {
    // The lifetime of ctx private (ctxp) is equal to 'static because it is never deallocated
    type Worker = ConcolicWorker<'static, 'ctxs>;
    fn name() -> &'static str {
        "concolic_input_gen"
    }
    fn has_generator() -> bool {
        false
    }

    fn has_mutator() -> bool {
        true
    }

    fn new(config_path: &PathBuf) -> Self {
        let config: ConcolicConfig = serde_json::from_str(
            &read_to_string(config_path).expect("Failed to read concolic_input_gen config"),
        )
        .expect("Failed to parse concolic_input_gen config");

        let time_begin = std::time::Instant::now();
        eprintln!("Waiting for get_symcc_cp...");
        let symcc_harness_exists = Self::get_symcc_cp(&config)
            .expect("Failed to wait for SymCC instrumented harnesses to build");
        eprintln!("get_symcc_cp done in {:?}", time_begin.elapsed());

        let z3_ctx = Box::leak(Box::new(Solver::new_ctx()));
        let solution_cache = Arc::new(RwLock::new(SymCCSolutionCache::new(z3_ctx)));
        let symcc_config = if symcc_harness_exists {
            let harness = PathBuf::from_str(&config.concolic.harness).unwrap();
            Some(SymCCSymStateConfig {
                harness,
                python: config.concolic.python.clone().into(),
                resolve_script: config.concolic.resolve_script.clone().into(),
                executor_timeout_ms: config.concolic.executor_timeout_ms,
                max_len: config.max_len,
            })
        } else {
            None
        };
        let qemu = PathBuf::from_str(&config.concolic.symqemu).unwrap();
        let harness = PathBuf::from_str(&config.concolic.symqemu_harness).unwrap();
        let llvm_symbolizer = PathBuf::from_str(&config.concolic.llvm_symbolizer).unwrap();
        let symqemu_config = SymQEMUSymStateConfig {
            harness,
            qemu,
            llvm_symbolizer,
            executor_timeout_ms: config.concolic.executor_timeout_ms,
            max_len: config.max_len,
            python: config.concolic.python.into(),
            resolve_script: config.concolic.resolve_script.into(),
        };

        let max_worker_cnt = if let Some(util) = config.concolic.utilization {
            (config.core_ids.len() as f64 * util) as usize
        } else {
            config.core_ids.len()
        };

        Self {
            symcc_config,
            symqemu_config,
            workdir: PathBuf::from_str(&config.concolic.workdir).unwrap(),
            solution_cache,
            max_worker_cnt,
            worker_counter: 0,
            z3_ctx_shared: unsafe {
                Box::from_raw(z3_ctx as *const z3::Context as *mut z3::Context)
            },
        }
    }

    fn new_worker(&self, worker_idx: usize) -> Self::Worker {
        if self.worker_counter >= self.max_worker_cnt {
            ConcolicWorker::idle()
        } else {
            let workdir = self.workdir.join(format!("worker-{}", worker_idx));
            let z3_ctx = Box::leak(Box::new(Solver::new_ctx()));
            ConcolicWorker::new(
                z3_ctx,
                self.symcc_config.clone(),
                self.symqemu_config.clone(),
                &workdir,
                self.solution_cache.clone(),
                worker_idx,
            )
        }
    }
}

enum WorkerMode<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    SymCCMode {
        consecutive_failures: usize,
        sym_state: SymCCSymState<'ctxp, 'ctxs>,
        workdir: PathBuf,
    },
    SymQEMUMode {
        consecutive_failures: usize,
        sym_state: SymQEMUSymState<'ctxp, 'ctxs>,
        workdir: PathBuf,
    },
    IdleMode,
}

impl<'ctxp, 'ctxs> WorkerMode<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    fn name(&self) -> &'static str {
        match self {
            WorkerMode::SymCCMode { .. } => "SymCC",
            WorkerMode::SymQEMUMode { .. } => "SymQEMU",
            WorkerMode::IdleMode => "Idle",
        }
    }

    #[allow(unused_variables)]
    fn process<M: Clone>(
        &mut self,
        input_id: InputID,
        input: &[u8],
        outputs: &mut Outputs<M>,
    ) -> Result<
        SymStateProcessResult<'ctxp, SymCCAux<'ctxp>, SymCCPathConstraintMetadata>,
        UniaflError,
    > {
        let (result, consecutive_failures) = match self {
            WorkerMode::SymCCMode {
                sym_state,
                consecutive_failures,
                workdir,
                ..
            } => {
                let process_result = sym_state.process(input_id, input);

                sym_state.profile_data().write(workdir)?;
                sym_state.executor().profile_data().write(workdir)?;
                (process_result, consecutive_failures)
            }
            WorkerMode::SymQEMUMode {
                sym_state,
                consecutive_failures,
                workdir,
                ..
            } => {
                let process_result = sym_state.process(input_id, input);
                sym_state.profile_data().write(workdir)?;
                sym_state.executor().profile_data().write(workdir)?;
                (process_result, consecutive_failures)
            }
            WorkerMode::IdleMode => unreachable!(),
        };
        match result {
            Err(e) => {
                concolic_log!(outputs, "SymState::process raised error: {}", e);
                *consecutive_failures += 1;
                Err(e)
            }
            Ok(result) => {
                // Don't reset consecutive failures if the input is not new. The flag
                // `is_new_input` is set to true if the given input ID was not previously solved
                // (not in the solution cache).
                if *consecutive_failures > 0 && result.is_new_input {
                    concolic_log!(outputs, "SymState success, resetting consecutive failures");
                    *consecutive_failures = 0;
                }
                Ok(result)
            }
        }
    }
}

pub struct ConcolicWorker<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    #[allow(unused)]
    symcc_config: Option<SymCCSymStateConfig>,
    symqemu_config: SymQEMUSymStateConfig,
    worker_mode: WorkerMode<'ctxp, 'ctxs>,
    workdir: PathBuf,
    worker_idx: usize,
    /// The sole purpose of this field is for it to be drop-ed, preventing memory leaks
    #[allow(unused)]
    z3_ctx_private: Option<Box<z3::Context>>,
}

impl<'ctxp, 'ctxs> ConcolicWorker<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    fn idle() -> Self {
        ConcolicWorker {
            symcc_config: None,
            symqemu_config: SymQEMUSymStateConfig::default(),
            worker_mode: WorkerMode::IdleMode,
            workdir: PathBuf::new(),
            worker_idx: 0,
            z3_ctx_private: None,
        }
    }

    fn new(
        z3_ctx_ref: &'ctxp z3::Context,
        symcc_config: Option<SymCCSymStateConfig>,
        symqemu_config: SymQEMUSymStateConfig,
        workdir: &PathBuf,
        solution_cache: Arc<RwLock<SymCCSolutionCache<'ctxs>>>,
        worker_idx: usize,
    ) -> Self {
        let z3_ctx_box =
            unsafe { Box::from_raw(z3_ctx_ref as *const z3::Context as *mut z3::Context) };
        if let Some(symcc_config) = symcc_config {
            let worker_mode = {
                let sym_state =
                    match new_symcc_symstate(&symcc_config, &workdir, z3_ctx_ref, solution_cache) {
                        Ok(sym_state) => sym_state,
                        Err(e) => {
                            eprintln!("Failed to create SymCCSymState: {}", e);
                            return ConcolicWorker::idle();
                        }
                    };
                WorkerMode::SymCCMode {
                    consecutive_failures: 0,
                    sym_state,
                    workdir: workdir.clone(),
                }
            };
            ConcolicWorker {
                symcc_config: Some(symcc_config),
                symqemu_config,
                worker_mode,
                workdir: workdir.clone(),
                worker_idx,
                z3_ctx_private: Some(z3_ctx_box),
            }
        } else {
            let worker_mode = {
                let sym_state = match new_symqemu_symstate(
                    &symqemu_config,
                    worker_idx,
                    &workdir,
                    z3_ctx_ref,
                    solution_cache,
                    false,
                ) {
                    Ok(sym_state) => sym_state,
                    Err(e) => {
                        eprintln!("Failed to create SymQEMUSymState: {}", e);
                        return ConcolicWorker::idle();
                    }
                };
                WorkerMode::SymQEMUMode {
                    consecutive_failures: 0,
                    sym_state,
                    workdir: workdir.clone(),
                }
            };
            ConcolicWorker {
                symcc_config: None,
                symqemu_config,
                workdir: workdir.clone(),
                worker_mode,
                worker_idx,
                z3_ctx_private: Some(z3_ctx_box),
            }
        }
    }

    fn check_transition(&mut self) -> Result<bool, UniaflError> {
        match &self.worker_mode {
            WorkerMode::SymCCMode {
                consecutive_failures,
                sym_state,
                ..
            } => {
                if *consecutive_failures >= CONSECUTIVE_FAILURES_THRESH {
                    let z3_ctx_ref = Box::leak(Box::new(Solver::new_ctx()));
                    let solution_cache = sym_state.solution_cache();
                    let sym_state = new_symqemu_symstate(
                        &self.symqemu_config,
                        self.worker_idx,
                        &self.workdir,
                        z3_ctx_ref,
                        solution_cache,
                        false,
                    )?;
                    self.worker_mode = WorkerMode::SymQEMUMode {
                        consecutive_failures: 0,
                        sym_state,
                        workdir: self.workdir.clone(),
                    };
                    return Ok(true);
                }
            }
            WorkerMode::SymQEMUMode {
                consecutive_failures,
                ..
            } => {
                if *consecutive_failures >= CONSECUTIVE_FAILURES_THRESH {
                    self.worker_mode = WorkerMode::IdleMode;
                    return Ok(true);
                }
            }
            WorkerMode::IdleMode => {}
        }
        Ok(false)
    }
}

const CONSECUTIVE_FAILURES_THRESH: usize = 5;

impl<'ctxp, 'ctxs> InputGenWorker for ConcolicWorker<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    type Metadata = ();
    fn generate(&mut self, _outputs: &mut Outputs<Self::Metadata>) -> Result<bool, UniaflError> {
        unreachable!()
    }

    fn mutate(
        &mut self,
        seed: &MsaSeed,
        outputs: &mut Outputs<Self::Metadata>,
    ) -> Result<bool, UniaflError> {
        match self.check_transition() {
            Ok(true) => {
                let _new_mode_name = self.worker_mode.name();
                concolic_log!(
                    outputs,
                    "Transitioned to mode {} due to consecutive execution failures",
                    _new_mode_name
                );
            }
            Err(_e) => {
                concolic_log!(
                    outputs,
                    "Failed to check transition: {}, transitioing to IDLE",
                    _e
                );
                self.worker_mode = WorkerMode::IdleMode;
            }
            Ok(false) => {}
        }
        // Early exit
        if let WorkerMode::IdleMode = self.worker_mode {
            concolic_log!(outputs, "Worker is idle, returning immediately");
            return Ok(false);
        }
        let input_id: u128 = seed.id.try_into().expect("Failed to convert seed id");
        let input_dir = self.workdir.join(format!("{}", input_id));
        if !input_dir.exists() {
            std::fs::create_dir_all(&input_dir)?;
        }
        let seed_fname_file = input_dir.join("fname.txt");
        let mut file = File::create(&seed_fname_file)?;
        file.write_all(seed.fname.as_bytes())?;
        let symstate_result = self.worker_mode.process(input_id, &seed.bytes, outputs)?;
        match self.write_symstate_result(input_id, &symstate_result) {
            Ok(_) => {}
            Err(_e) => {
                concolic_log!(outputs, "Failed to write symstate result: {}", _e);
            }
        }
        concolic_log!(
            outputs,
            "Get {} inputs by solving",
            symstate_result.new_inputs.len()
        );

        if symstate_result.new_inputs.is_empty() {
            return Ok(false);
        }
        outputs.bump_blobs(symstate_result.new_inputs);
        Ok(true)
    }

    fn has_cb_if_added_into_corpus() -> bool {
        true
    }

    fn cb_if_added_into_corpus(
        &mut self,
        _output: &Output<Self::Metadata>,
        _corpus_id: usize,
    ) -> Result<(), UniaflError> {
        // for now, let's just leave it as it is
        Ok(())
    }
}

impl ConcolicWorker<'_, '_> {
    fn write_symstate_result<T: Serialize>(
        &self,
        input_id: InputID,
        symstate_result: &SymStateProcessResult<T, SymCCPathConstraintMetadata>,
    ) -> Result<(), UniaflError> {
        if !symstate_result.is_new_input {
            // don't overwrite the result if the current mutation is splicing based,
            // meaning concolic execution was not performed
            return Ok(());
        }
        let input_dir = self.workdir.join(format!("{}", input_id));
        let mut lock = FileLock::lock(
            input_dir.join("result.json"),
            true,
            FileOptions::new().write(true).create(true).truncate(true),
        )?;
        let json_str = serde_json::to_string(symstate_result)?;
        lock.file.write(json_str.as_bytes())?;
        Ok(())
    }
}
