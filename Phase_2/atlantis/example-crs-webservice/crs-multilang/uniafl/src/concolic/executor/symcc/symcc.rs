use super::resource_control::{apply_cgroup, new_cgroup};
use super::{
    out_dir, ConcolicExecutor, ExecutorProfileData, SingleStepResult,
    SymCCEnableDataLengthSymbolization, SymCCHook, SymCCInstallFunctionCallHook, SYMCC_CPU_PERIOD,
    SYMCC_CPU_QUOTA, SYMCC_ENABLE_FULL_TRACE_KEY, SYMCC_FUNCTION_CALL_HOOK_ENV_KEY,
    SYMCC_MEMORY_LIMIT, SYMCC_SEM_KEY_ENV_KEY, SYMCC_SYMBOLIZE_DATA_LENGTH, SYMCC_TRACE_ENV_KEY,
};
use crate::common::errors::ErrorKind;
use crate::common::sem_lock::{SemLock, SingleSem};
use crate::common::{Error, ExecutableType, InputID};
use crate::concolic::{SingleStepSession, SymCCTR};
use cgroups_rs::Cgroup;
use std::collections::HashMap;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

pub struct SymCCSingleStepSession {
    spawned_harness: SymCCSpawnedHarness,
    sem_lock: SemLock,
    exited_sem: SingleSem,
}

impl SingleStepSession for SymCCSingleStepSession {
    fn kill(&mut self) -> Result<(), Error> {
        self.spawned_harness.process.kill()?;
        self.spawned_harness.process.wait()?;
        Ok(())
    }
}

fn wait_end_with_timeout(
    sem_lock: &mut SemLock,
    timeout_ms: u64,
    harness: &PathBuf,
) -> Result<(), Error> {
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed().as_millis();
        if !sem_lock.end_consumed() {
            // this is guaranteed to return unless any other processes race it
            sem_lock.wait_end();
            return Ok(());
        }
        if elapsed >= timeout_ms.into() {
            return Err(Error::timeout_error(
                &format!("{}", harness.to_str().unwrap()),
                Duration::from_millis(timeout_ms),
            ));
        }
    }
}

impl Drop for SymCCSingleStepSession {
    fn drop(&mut self) {
        self.sem_lock.destroy();
        self.exited_sem.destroy();
    }
}

pub struct SymCCExecutor {
    pub harness: PathBuf,
    workdir: PathBuf,
    timeout_ms: Option<u64>,

    #[cfg(feature = "concolic_profiling")]
    profile_data: ExecutorProfileData,

    ignore_nonzero_exits: bool,
    interactive: bool,

    random_name: String,

    nonce: usize,
    function_call_hook: Option<PathBuf>,
    symbolize_data_length: bool,
}

pub struct SymCCExecutorConfig {
    additional_environment_vars: HashMap<String, String>,
}

impl SymCCExecutorConfig {
    pub fn new() -> Self {
        Self {
            additional_environment_vars: HashMap::new(),
        }
    }

    pub fn set_sem_key(&mut self, value: &str) -> &mut Self {
        self.additional_environment_vars
            .insert(SYMCC_SEM_KEY_ENV_KEY.to_string(), value.to_string());
        self
    }

    pub fn set_full_trace(&mut self, enable: bool) -> &mut Self {
        if enable {
            self.additional_environment_vars
                .insert(SYMCC_ENABLE_FULL_TRACE_KEY.to_string(), "1".to_string());
        } else {
            self.additional_environment_vars
                .remove(SYMCC_ENABLE_FULL_TRACE_KEY);
        }
        self
    }

    pub fn set_data_length_symbolization(&mut self, enable: bool) -> &mut Self {
        if enable {
            self.additional_environment_vars
                .insert(SYMCC_SYMBOLIZE_DATA_LENGTH.to_string(), "1".to_string());
        } else {
            self.additional_environment_vars
                .remove(SYMCC_SYMBOLIZE_DATA_LENGTH);
        }
        self
    }

    pub fn set_function_call_hook(&mut self, hook: &PathBuf) -> &mut Self {
        self.additional_environment_vars.insert(
            SYMCC_FUNCTION_CALL_HOOK_ENV_KEY.to_string(),
            hook.to_str().unwrap().to_string(),
        );
        self
    }
}

#[allow(unused)]
struct SymCCSpawnedHarness {
    process: Child,
    input_file: PathBuf,
    trace_file: PathBuf,
    time_begin: Instant,
    cgroup: Cgroup,
}

#[allow(unused)]
impl SymCCExecutor {
    pub fn new(
        harness: &PathBuf,
        workdir: &PathBuf,
        timeout_ms: Option<u64>,
    ) -> Result<Self, Error> {
        if !harness.exists() {
            return Err(Error::executable_does_not_exist(
                harness,
                ExecutableType::SymCCHarness,
            ));
        }
        if !workdir.exists() {
            std::fs::create_dir_all(&workdir)?;
        }
        Ok(Self {
            harness: harness.canonicalize()?,
            workdir: workdir.canonicalize()?,
            timeout_ms,
            profile_data: ExecutorProfileData::default(),
            random_name: format!("symcc-cgroup-{}", rand::random::<u64>()),
            ignore_nonzero_exits: false,
            interactive: true,
            nonce: 0,
            function_call_hook: None,
            symbolize_data_length: false,
        })
    }

    pub fn set_interactive(&mut self, interactive: bool) {
        self.interactive = interactive;
    }

    pub fn set_ignore_nonzero_exits(&mut self, ignore: bool) {
        self.ignore_nonzero_exits = ignore;
    }

    fn increase_nonce(&mut self) -> usize {
        self.nonce += 1;
        self.nonce - 1
    }

    fn spawn_harness(
        &mut self,
        input_id: InputID,
        input: &[u8],
        config: &SymCCExecutorConfig,
    ) -> Result<SymCCSpawnedHarness, Error> {
        if !self.harness.exists() {
            return Err(Error::executable_does_not_exist(
                &self.harness,
                ExecutableType::SymCCHarness,
            ));
        }
        let time_begin = Instant::now();
        let input_dir = self.workdir.join(format!("{}", input_id));
        if !input_dir.exists() {
            std::fs::create_dir_all(&input_dir)?;
        }
        let input_file = input_dir.join("input.txt");
        let trace_file = input_dir.join("trace.bin");
        let out_dir = out_dir();
        std::fs::write(&input_file, input)?;
        let mut cmd = Command::new(&self.harness);
        cmd.arg(&input_file)
            .env(SYMCC_TRACE_ENV_KEY, trace_file.to_str().unwrap())
            .current_dir(out_dir);
        let cgroup = new_cgroup(
            &self.random_name,
            SYMCC_MEMORY_LIMIT,
            SYMCC_CPU_PERIOD,
            SYMCC_CPU_QUOTA,
        )?;
        unsafe {
            let cgroup = cgroup.clone();
            cmd.pre_exec(move || {
                apply_cgroup(&cgroup, std::process::id() as u64).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to apply cgroup: {}", e),
                    )
                })?;
                Ok(())
            });
        }
        if !self.interactive {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        for (key, value) in &config.additional_environment_vars {
            cmd.env(key, value);
        }
        let mut process = cmd.spawn()?;
        Ok(SymCCSpawnedHarness {
            process,
            input_file,
            trace_file,
            time_begin,
            cgroup,
        })
    }

    fn wait_spanwed_harness(
        &mut self,
        mut spawned_harness: SymCCSpawnedHarness,
    ) -> Result<SymCCTR, Error> {
        let status = if let Some(timeout_ms) = self.timeout_ms {
            let timeout_duration = Duration::from_millis(timeout_ms);
            match spawned_harness.process.wait_timeout(timeout_duration)? {
                Some(status) => status,
                None => return Err(Error::timeout_error("", timeout_duration)),
            }
        } else {
            spawned_harness.process.wait()?
        };
        if !status.success() {
            self.profile_data.nonzero_exits_cnt += 1;
            self.profile_data.total_exec_time_ms +=
                spawned_harness.time_begin.elapsed().as_millis() as u64;
            if !self.ignore_nonzero_exits {
                if let Some(code) = status.code() {
                    return Err(Error::execution_failed(
                        &self.harness.to_str().unwrap(),
                        code,
                    ));
                } else {
                    if let Some(signal) = status.signal() {
                        return Err(Error::execution_failed(
                            &self.harness.to_str().unwrap(),
                            -signal,
                        ));
                    } else {
                        // TODO: handle this case
                        return Err(Error::execution_failed(&self.harness.to_str().unwrap(), -1));
                    }
                }
            }
        } else {
            self.profile_data.total_exec_time_ms +=
                spawned_harness.time_begin.elapsed().as_millis() as u64;
        }
        let trace_file = spawned_harness.trace_file;
        if !trace_file.exists() {
            return Err(Error::missing_trace(
                &self.harness,
                ExecutableType::SymCCHarness,
            ));
        }
        let trace = std::fs::read(&trace_file)?;
        // delete the trace file
        std::fs::remove_file(&trace_file)?;
        spawned_harness.cgroup.delete()?;
        Ok((trace, HashMap::new()))
    }

    fn update_profile_data(&mut self, error: &Result<SymCCTR, Error>) {
        match error {
            Ok(_) => {
                self.profile_data.successful_execs_cnt += 1;
            }
            Err(e) => match e.kind {
                ErrorKind::ExecutionFailed { .. } => {
                    self.profile_data.nonzero_exits_cnt += 1;
                }
                ErrorKind::TimeoutError { .. } => {
                    self.profile_data.timeouts_cnt += 1;
                }
                ErrorKind::MissingTrace { .. } => {
                    self.profile_data.missing_traces_cnt += 1;
                }
                _ => {
                    self.profile_data.other_failure_cnt += 1;
                }
            },
        }
    }
}

impl ConcolicExecutor<SymCCTR, SymCCSingleStepSession> for SymCCExecutor {
    fn execute(&mut self, input_id: InputID, input: &[u8]) -> Result<SymCCTR, Error> {
        let mut config = SymCCExecutorConfig::new();
        if let Some(hook) = &self.function_call_hook {
            config.set_function_call_hook(hook);
        }
        config.set_data_length_symbolization(self.symbolize_data_length);
        let spawned_harness = match self.spawn_harness(input_id, input, &config) {
            Ok(spawned_harness) => spawned_harness,
            Err(e) => {
                self.profile_data.spawn_failure_cnt += 1;
                return Err(e);
            }
        };
        let result = self.wait_spanwed_harness(spawned_harness);
        self.update_profile_data(&result);
        Ok(result?)
    }

    fn profile_data(&self) -> &ExecutorProfileData {
        &self.profile_data
    }

    fn execute_single_step(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<SymCCSingleStepSession, Error> {
        self.interactive = true;
        let mut config = SymCCExecutorConfig::new();
        config.set_full_trace(true);
        config.set_data_length_symbolization(self.symbolize_data_length);
        if let Some(hook) = &self.function_call_hook {
            config.set_function_call_hook(hook);
        }
        let sem_key = format!(
            "{}-{}-{}",
            self.harness
                .to_path_buf()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            input_id,
            self.increase_nonce()
        );
        config.set_sem_key(&sem_key);
        let exited_sem = SingleSem::new2(&sem_key, "exited", true)?;
        let mut sem_lock = SemLock::new2(sem_key, true)?;
        let spawned_harness = self.spawn_harness(input_id, input, &config)?;

        // Wait for the initial post-end call. This should occur promptly and serves as confirmation
        // that the child process has successfully opened all the required semaphores.
        sem_lock.post_start();
        wait_end_with_timeout(&mut sem_lock, 1000, &self.harness)?;

        Ok(SymCCSingleStepSession {
            spawned_harness,
            sem_lock,
            exited_sem,
        })
    }

    fn single_step(
        &mut self,
        session: &mut SymCCSingleStepSession,
    ) -> Result<SingleStepResult<SymCCTR>, Error> {
        session.sem_lock.post_start();
        if let Some(timeout_ms) = self.timeout_ms {
            wait_end_with_timeout(&mut session.sem_lock, timeout_ms, &self.harness)?;
        } else {
            session.sem_lock.wait_end();
        }
        let trace_file = &session.spawned_harness.trace_file;
        if !trace_file.exists() {
            return Err(Error::missing_trace(
                &self.harness,
                ExecutableType::SymCCHarness,
            ));
        }
        let trace_inner = std::fs::read(trace_file)?;
        // delete the trace file
        std::fs::remove_file(trace_file)?;
        let trace = (trace_inner, HashMap::new());
        if session.exited_sem.get_consumed() {
            Ok(SingleStepResult::Continued(trace))
        } else {
            Ok(SingleStepResult::Finished(trace))
        }
    }
}

impl SymCCInstallFunctionCallHook for SymCCExecutor {
    fn install_function_call_hook(&mut self, hook: SymCCHook) -> Result<Option<SymCCHook>, Error> {
        let hook_path = self.workdir.join("hook.py");
        let previous_hook = match self.function_call_hook {
            Some(ref path) => {
                let contents = std::fs::read_to_string(path)?;
                Some(contents)
            }
            None => None,
        };
        std::fs::write(&hook_path, &hook)?;
        self.function_call_hook = Some(hook_path);
        Ok(previous_hook)
    }

    fn remove_function_call_hook(&mut self) -> Result<(), Error> {
        self.function_call_hook = None;
        Ok(())
    }

    fn get_function_call_hook(&self) -> Result<Option<SymCCHook>, Error> {
        if let Some(ref path) = self.function_call_hook {
            let contents = std::fs::read_to_string(path)?;
            Ok(Some(contents))
        } else {
            Ok(None)
        }
    }
}

impl SymCCEnableDataLengthSymbolization for SymCCExecutor {
    fn enable_data_length_symbolization(&mut self) {
        self.symbolize_data_length = true;
    }

    fn disable_data_length_symbolization(&mut self) {
        self.symbolize_data_length = false;
    }
}
