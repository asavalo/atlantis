use super::mmap_shmem::MmapShm;
use super::resource_control::{apply_cgroup, new_cgroup};
use super::{
    out_dir, SymCCEnableDataLengthSymbolization, SymCCHook,
    SymCCInstallFunctionCallHook, SYMQEMU_CPU_PERIOD, SYMQEMU_CPU_QUOTA, SYMQEMU_MEMORY_LIMIT,
};
use super::{
    symqemu_helpers::get_libfuzzer_symbols_string, ConcolicExecutor, ExecutorProfileData,
    SingleStepResult, SYMCC_FUNCTION_CALL_HOOK_ENV_KEY, SYMCC_TRACE_ENV_KEY,
};
use crate::common::errors::ErrorKind;
use crate::common::{sem_lock::SemLock, Error, ExecutableType, InputID};
use crate::concolic::{SingleStepSession, SymCCTR};
use bytes::BufMut;
use cgroups_rs::Cgroup;
use proc_maps::get_process_maps;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[allow(unused)]
pub const SYMQEMU_HOME_ENV_KEY: &str = "SYMQEMU_HOME";
#[allow(unused)]
pub const SYMQEMU_SHM_ENV_KEY: &str = "SYMQEMU_SHM";
#[allow(unused)]
pub const SYMQEMU_LIBFUZZER_SERVER_ENV_KEY: &str = "LIBFUZZER_SERVER";
#[allow(unused)]
pub const SYMQEMU_WORKER_IDX_ENV_KEY: &str = "SYMQEMU_WORKER_IDX";
#[allow(unused)]
pub const SYMQEMU_MAX_INPUT_SIZE: usize = 0x100 * 0x1000 - 8;
#[allow(unused)]
pub const LIBFUZZER_SYMBOL_TBL_ENV_KEY: &str = "LIBFUZZER_SYMBOL_TBL";
#[allow(unused)]
pub const QEMU_LOG_FILENAME_ENV_KEY: &str = "QEMU_LOG_FILENAME";
#[allow(unused)]
pub const QEMU_LOG_ENV_KEY: &str = "QEMU_LOG";

pub struct SymQEMUSingleStepSession {}

impl SingleStepSession for SymQEMUSingleStepSession {
    fn kill(&mut self) -> Result<(), Error> {
        todo!()
    }
}

enum SymQEMUExecutorState {
    Running,
    Killed,
}

pub struct SymQEMUExecutor {
    qemu: PathBuf,
    qemu_process: Child,
    harness: PathBuf,
    workdir: PathBuf,
    #[allow(unused)]
    worker_idx: usize,
    trace_path: PathBuf,
    sem_lock: SemLock,
    input_shmem: MmapShm,
    timeout_ms: Option<u64>,

    stderr_thread: PipeThread,
    stdout_thread: PipeThread,

    image_mem_range: (usize, usize),
    status: SymQEMUExecutorState,

    profile_data: ExecutorProfileData,

    interactive: bool,
    log: bool,
    cgroup: Cgroup,

    #[allow(unused)]
    hook: PathBuf,
    hook_contents: String,
}

#[allow(unused)]
fn create_symbol_tables(harness: &PathBuf, workdir: &PathBuf) -> Result<PathBuf, Error> {
    let libfuzzer_symbol_table_contents = get_libfuzzer_symbols_string(harness)?;
    let libfuzzer_symbol_table_path = workdir.join("libfuzzer_symbol_address_tbl.txt");
    std::fs::write(
        &libfuzzer_symbol_table_path,
        libfuzzer_symbol_table_contents,
    )?;
    Ok(libfuzzer_symbol_table_path)
}

const SYMQEMU_PROMT_STR: &str = "[LIBFUZZER] libfuzzer_shm_recv";

fn get_image_mem_range(qemu_process_id: i32, harness: &PathBuf) -> Result<(usize, usize), Error> {
    let proc_maps = get_process_maps(qemu_process_id)?;
    let mut start = usize::MAX;
    let mut end = 0;
    // this should already be canonicalized, but just in case
    let canonical_harness = harness.canonicalize()?;
    for map in proc_maps {
        if let Some(filename) = map.filename() {
            if let Ok(filename) = filename.canonicalize() {
                if filename == canonical_harness {
                    start = std::cmp::min(map.start(), start);
                    end = std::cmp::max(map.start() + map.size(), end);
                    break;
                }
            }
        }
    }
    if start == usize::MAX || end == 0 {
        return Err(Error::invalid_data("Could not find image memory range"));
    }
    Ok((start, end))
}

fn wait_symqemu_ready(stderr_thread: &PipeThread) -> Result<(), Error> {
    let symqemu_ready_wait_time = Duration::from_secs(10);
    let start = Instant::now();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= symqemu_ready_wait_time {
            return Err(Error::timeout_error(
                "SymQEMU process did not start in time",
                symqemu_ready_wait_time,
            ));
        }
        if stderr_thread.output_contains(SYMQEMU_PROMT_STR) {
            break;
        }
    }
    Ok(())
}

struct PipeThread {
    handle: Option<thread::JoinHandle<Result<(), Error>>>,
    buf: Arc<Mutex<Vec<String>>>,
}

impl PipeThread {
    fn new<R: Read + Send + 'static>(pipe: R) -> Self {
        let buf = Arc::new(Mutex::new(vec![]));
        let handle = {
            let buf = buf.clone();
            thread::spawn(move || {
                let reader = BufReader::new(pipe);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        buf.lock().unwrap().push(line);
                    }
                }
                Ok(())
            })
        };
        Self {
            handle: Some(handle),
            buf,
        }
    }

    fn output_contains(&self, needle: &str) -> bool {
        let buf = self.buf.lock().unwrap();
        buf.iter().any(|line| line.contains(needle))
    }

    fn dump(&self) -> String {
        let buf = self.buf.lock().unwrap();
        buf.join("\n")
    }
}

#[allow(unused)]
impl SymQEMUExecutor {
    pub fn respawn(&mut self) -> Result<Self, Error> {
        self.shutdown()?;
        Self::new(
            &self.qemu,
            &self.harness,
            &self.workdir,
            self.worker_idx,
            self.timeout_ms,
            self.interactive,
            self.log,
            &self.hook_contents,
        )
    }

    pub fn new(
        qemu: &PathBuf,
        harness: &PathBuf,
        workdir: &PathBuf,
        worker_idx: usize,
        timeout_ms: Option<u64>,
        interactive: bool,
        log: bool,
        hook_contents: &str,
    ) -> Result<Self, Error> {
        if !qemu.exists() {
            return Err(Error::executable_does_not_exist(
                qemu,
                ExecutableType::SymQEMU,
            ));
        }
        if !harness.exists() {
            return Err(Error::executable_does_not_exist(
                &harness,
                ExecutableType::SymQEMUHarness,
            ));
        }
        if !workdir.exists() {
            std::fs::create_dir_all(&workdir)?;
        }
        // we must canonicalize the paths because we force the current directory to be the output
        // directory
        let workdir = workdir.canonicalize()?;
        let harness = harness.canonicalize()?;
        let libfuzzer_symbol_table_path =
            create_symbol_tables(&harness, &workdir)?.canonicalize()?;
        let qemu = qemu.canonicalize()?;
        let trace_path = workdir.join(format!("trace.bin"));
        let hook = workdir.join(format!("hook.py"));
        std::fs::write(&hook, hook_contents)?;
        let symqemu_home = qemu.parent().unwrap().canonicalize()?;
        let common_name = format!("symqemu-{}", worker_idx);
        let input_shmem = MmapShm::new(&common_name, SYMQEMU_MAX_INPUT_SIZE + 8)?;
        let sem_lock = SemLock::new(common_name, true);
        let mut cmd = Command::new(&qemu);
        let out_dir = out_dir();
        cmd.arg(&harness)
            .env(SYMCC_TRACE_ENV_KEY, trace_path.to_str().unwrap())
            .env(SYMQEMU_HOME_ENV_KEY, symqemu_home.to_str().unwrap())
            .env(SYMQEMU_LIBFUZZER_SERVER_ENV_KEY, "1")
            .env(SYMQEMU_WORKER_IDX_ENV_KEY, worker_idx.to_string())
            .env(SYMQEMU_SHM_ENV_KEY, input_shmem.name())
            .env(
                LIBFUZZER_SYMBOL_TBL_ENV_KEY,
                libfuzzer_symbol_table_path.to_str().unwrap(),
            )
            .env(SYMCC_FUNCTION_CALL_HOOK_ENV_KEY, hook.display().to_string())
            .current_dir(&out_dir);
        if !interactive {
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let cgroup = new_cgroup(
            &format!("symqemu-cgroup-{}", rand::random::<u64>()),
            SYMQEMU_MEMORY_LIMIT,
            SYMQEMU_CPU_PERIOD,
            SYMQEMU_CPU_QUOTA,
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
        if log {
            let datetime_str = chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S").to_string();
            let qemu_log_path = workdir.join(format!("symqemu-log-{}.txt", datetime_str));
            cmd.env(QEMU_LOG_FILENAME_ENV_KEY, qemu_log_path);
            cmd.env(QEMU_LOG_ENV_KEY, "op,in_asm,out_asm");
        }
        let mut child = cmd.spawn()?;
        let stderr_thread = PipeThread::new(child.stderr.take().unwrap());
        let stdout_thread = PipeThread::new(child.stdout.take().unwrap());
        let qemu_process_id = child.id() as i32;
        match wait_symqemu_ready(&stderr_thread) {
            Ok(_) => {}
            Err(e) => match &e.kind {
                ErrorKind::TimeoutError { .. } => {
                    // Drop is not called in this case, so we need to manually shut it down
                    child.kill()?;
                    child.wait()?;
                    eprintln!("Killed SymQEMU child {}", qemu_process_id);
                    return Err(e);
                }
                _ => {
                    return Err(e);
                }
            },
        }
        let image_mem_range = get_image_mem_range(qemu_process_id, &harness)?;
        Ok(Self {
            qemu: qemu.clone(),
            qemu_process: child,
            harness: harness.clone(),
            workdir: workdir.clone(),
            worker_idx,
            trace_path,
            sem_lock,
            input_shmem,
            timeout_ms,

            stderr_thread,
            stdout_thread,

            profile_data: ExecutorProfileData::default(),
            image_mem_range,
            status: SymQEMUExecutorState::Running,
            interactive,
            cgroup,
            log,

            hook,
            hook_contents: hook_contents.to_string(),
        })
    }

    fn dump_qemu_output(&mut self) -> Result<(), Error> {
        let mut stdout_string = self.stdout_thread.dump();
        let mut stderr_string = self.stderr_thread.dump();
        let datetime_str = chrono::Utc::now().format("%Y-%m-%d-%H-%M-%S").to_string();
        let stdout_file = self
            .workdir
            .join(format!("symqemu-stdout-{}.txt", datetime_str));
        let stderr_file = self
            .workdir
            .join(format!("symqemu-stderr-{}.txt", datetime_str));
        std::fs::write(&stdout_file, stdout_string)?;
        std::fs::write(&stderr_file, stderr_string)?;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        if let SymQEMUExecutorState::Killed = self.status {
            return Ok(());
        }
        eprintln!("Shutting down SymQEMU process...");
        self.dump_qemu_output()?;
        let status = self.qemu_process.try_wait()?;
        // QEMU process is still running
        if status.is_none() {
            self.qemu_process.kill()?;
            let exit_status = self.qemu_process.wait()?;
            eprintln!(
                "Killed SymQEMU process (pid={}), exit status: {}",
                self.qemu_process.id(),
                exit_status
            );
        } else {
            eprintln!(
                "SymQEMU process (pid={}) has already exited, exit status: {}",
                self.qemu_process.id(),
                status.unwrap()
            );
        }
        self.sem_lock.destroy();
        self.status = SymQEMUExecutorState::Killed;
        // now that the process is killed and its stdout/stderr are closed, we can join the threads
        self.stdout_thread.handle.take().unwrap().join().unwrap()?;
        self.stderr_thread.handle.take().unwrap().join().unwrap()?;
        self.cgroup.delete()?;
        Ok(())
    }

    pub fn get_image_mem_range(&self) -> Result<(usize, usize), Error> {
        Ok(self.image_mem_range)
    }

    fn execute_inner(&mut self, input_id: InputID, input: &[u8]) -> Result<SymCCTR, Error> {
        if self.trace_path.exists() {
            std::fs::remove_file(&self.trace_path)?;
        }
        let mut data = vec![];
        data.put_u64_le(input.len() as u64);
        data.put_slice(input);
        self.input_shmem.write_all(&data)?;
        let start = Instant::now();
        self.sem_lock.post_start();
        if let Some(timeout_ms) = self.timeout_ms {
            let maybe_error = loop {
                let elapsed = start.elapsed().as_millis();
                if !self.sem_lock.end_consumed() {
                    self.sem_lock.wait_end();
                    break Ok(());
                }
                if elapsed >= timeout_ms.into() {
                    break Err(Error::timeout_error(
                        &format!(
                            "{} {}",
                            self.qemu.to_str().unwrap(),
                            self.harness.to_str().unwrap()
                        ),
                        Duration::from_millis(timeout_ms),
                    ));
                }
            };
            maybe_error?;
        } else {
            // if QEMU is killed via cgroups, this will wait indefinitely
            self.sem_lock.wait_end();
        }
        if !self.trace_path.exists() {
            return Err(Error::missing_trace(
                &self.harness,
                ExecutableType::SymQEMUHarness,
            ));
        } // move trace file to {}/trace.bin
        let input_dir = self.workdir.join(format!("{}", input_id));
        if !input_dir.exists() {
            std::fs::create_dir_all(&input_dir)?;
        }
        let dst_trace_path = input_dir.join("trace.bin");
        let dst_input_path = input_dir.join("input.txt");
        std::fs::rename(&self.trace_path, &dst_trace_path)?;
        std::fs::write(&dst_input_path, input)?;
        let trace = std::fs::read(&dst_trace_path)?;
        // delete the trace file
        std::fs::remove_file(&dst_trace_path)?;
        Ok((trace, HashMap::new()))
    }

    fn update_profile_data(
        &mut self,
        result: &Result<SymCCTR, Error>,
        time_begin: Instant,
    ) -> Result<(), Error> {
        self.profile_data.total_exec_time_ms += time_begin.elapsed().as_millis() as u64;
        match result {
            Ok(_) => {
                self.profile_data.successful_execs_cnt += 1;
            }
            Err(e) => match e.kind {
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
        Ok(())
    }
}

impl Drop for SymQEMUExecutor {
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            eprintln!("Failed to shutdown SymQEMU process: {:?}", e);
        }
    }
}

impl ConcolicExecutor<SymCCTR, SymQEMUSingleStepSession> for SymQEMUExecutor {
    fn execute(&mut self, input_id: InputID, input: &[u8]) -> Result<SymCCTR, Error> {
        let time_begin = Instant::now();
        let result = self.execute_inner(input_id, input);
        self.update_profile_data(&result, time_begin)?;
        result
    }

    fn profile_data(&self) -> &ExecutorProfileData {
        &self.profile_data
    }

    fn execute_single_step(
        &mut self,
        _input_id: InputID,
        _input: &[u8],
    ) -> Result<SymQEMUSingleStepSession, Error> {
        todo!()
    }

    fn single_step(
        &mut self,
        _session: &mut SymQEMUSingleStepSession,
    ) -> Result<SingleStepResult<SymCCTR>, Error> {
        todo!()
    }
}

impl SymCCInstallFunctionCallHook for SymQEMUExecutor {
    fn install_function_call_hook(
        &mut self,
        _hook: SymCCHook,
    ) -> Result<Option<SymCCHook>, Error> {
        Ok(None)
    }

    fn remove_function_call_hook(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_function_call_hook(&self) -> Result<Option<SymCCHook>, Error> {
        Ok(None)
    }
}

impl SymCCEnableDataLengthSymbolization for SymQEMUExecutor {
    fn enable_data_length_symbolization(&mut self) {
        unreachable!()
    }

    fn disable_data_length_symbolization(&mut self) {
        unreachable!()
    }
}
