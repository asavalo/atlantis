mod common;
mod concolic;
use crate::common::{Error, InputID};
use crate::concolic::{
    new_symcc_symstate, new_symqemu_symstate, parse_symcc_map, ConcolicProfileData,
    SelfCorrectingSymState, SrcLocation, SymCCSolutionCache, SymCCSymStateConfig, SymState,
};
use clap::{Parser, Subcommand};
use concolic::{ConcolicExecutor, IsSymCCAux, SymQEMUSymStateConfig};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Parser)]
#[command(name = "Concolic Utils")]
#[command(about = "A CLI tool for SymCC map parsing and concolic execution.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    ParseMap {
        #[arg(short = 'e', long = "harness")]
        harness: String,
        #[arg(short = 'o', long = "output")]
        output: String,
    },
    Run {
        #[arg(long)]
        harness: String,
        #[arg(long)]
        workdir: Option<String>,
        #[arg(long)]
        input: String,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        output: String,
        #[arg(long)]
        iters: Option<u64>,
        #[arg(long, help = "Use SymQEMU instead of SymCC")]
        symqemu: bool,
        #[arg(long)]
        qemu: Option<String>,
        #[arg(long)]
        llvm_symbolizer: Option<String>,
        #[arg(long)]
        interactive: bool,
        #[arg(long)]
        self_correct: bool,
        #[arg(long)]
        python: String,
        #[arg(long)]
        resolve_script: String,
    },
}

pub struct RunConcolic {
    harness: PathBuf,
    workdir: PathBuf,
    input: PathBuf,
    timeout_ms: Option<u64>,
    output_dir: PathBuf,
    iters: u64,
    symqemu: bool,
    qemu: PathBuf,
    llvm_symbolizer: PathBuf,
    interactive: bool,
    self_correct: bool,
    python: PathBuf,
    resolve_script: PathBuf,
}

impl RunConcolic {
    pub fn new(
        harness: String,
        workdir: Option<String>,
        input: String,
        timeout_ms: Option<u64>,
        output: String,
        iters: Option<u64>,
        symqemu: bool,
        qemu: Option<String>,
        llvm_symbolizer: Option<String>,
        interactive: bool,
        self_correct: bool,
        python: String,
        resolve_script: String,
    ) -> Self {
        let workdir = PathBuf::from(workdir.as_deref().unwrap_or("workdir"));
        let qemu = PathBuf::from(qemu.as_deref().unwrap_or("/symcc/qemu-x86_64"));
        let llvm_symbolizer = PathBuf::from(
            llvm_symbolizer
                .as_deref()
                .unwrap_or("/usr/bin/llvm-symbolizer"),
        );
        RunConcolic {
            harness: PathBuf::from(harness),
            workdir,
            input: PathBuf::from(input),
            timeout_ms,
            output_dir: PathBuf::from(output),
            iters: iters.unwrap_or(1),
            symqemu,
            qemu,
            llvm_symbolizer,
            interactive,
            self_correct,
            python: PathBuf::from(python),
            resolve_script: PathBuf::from(resolve_script),
        }
    }

    pub fn process<'ctxp, 'ctxs, S>(
        &self,
        mut queue: Vec<Vec<u8>>,
        mut sym_state: S,
    ) -> Result<(), Error>
    where
        S: SymState<'ctxp, 'ctxs> + SelfCorrectingSymState<'ctxp, 'ctxs>,
        S::PCM: Into<Option<SrcLocation>> + Clone,
        S::AUX: Serialize + Default + IsSymCCAux<'ctxp>,
    {
        for id in 0..self.iters {
            println!("[*] Running id={}...", id);
            let input_bytes = match queue.pop() {
                Some(b) => b,
                None => {
                    println!("[*] No more inputs.");
                    break;
                }
            };
            let id: InputID = id.into();
            if !self.self_correct {
                match sym_state.process(id, &input_bytes) {
                    Ok(res) => {
                        println!("[+] Succssfully processed input id={}", id);
                        let parent_dir = self.output_dir.join(format!("{}", id));
                        if !parent_dir.exists() {
                            std::fs::create_dir_all(&parent_dir)?;
                        }
                        for (i, data) in res.new_inputs.into_iter().enumerate() {
                            let file = parent_dir.join(format!("{}", i));
                            std::fs::write(&file, &data)?;
                            queue.insert(0, data);
                        }
                        for (i, pc) in res.new_input_constraints.iter().enumerate() {
                            let pc_info = serde_json::to_string_pretty(pc)?;
                            let info_file = parent_dir.join(format!("{}-info.json", i));
                            std::fs::write(&info_file, pc_info)?;
                        }
                        let unsolved_dir = parent_dir.join("unsolved");
                        if !unsolved_dir.exists() {
                            std::fs::create_dir_all(&unsolved_dir)?;
                        }
                        for (unsolved_id, unsolved) in
                            res.unsolved_path_constraints.into_iter().enumerate()
                        {
                            let unsolved_file =
                                unsolved_dir.join(format!("{}-info.json", unsolved_id));
                            let unsolved_info = serde_json::to_string_pretty(&unsolved)?;
                            std::fs::write(&unsolved_file, &unsolved_info)?;
                        }
                        let aux_file = parent_dir.join("aux.json");
                        let aux = res.aux;
                        let aux_json = serde_json::to_string_pretty(&aux)?;
                        std::fs::write(&aux_file, aux_json)?;
                    }
                    Err(e) => {
                        println!("[!] Failed to process input id={}, {}", id, e);
                        let file = self.output_dir.join(format!("{}/error.txt", id));
                        if let Some(parent) = file.parent() {
                            if !parent.exists() {
                                std::fs::create_dir_all(parent)?;
                            }
                        }
                        std::fs::write(&file, format!("{}", e))?;
                        break;
                    }
                };
                sym_state.profile_data().write(&self.output_dir)?;
                sym_state
                    .executor()
                    .profile_data()
                    .write(&self.output_dir)?;
            } else {
                sym_state.process_with_self_correction(id, &input_bytes)?;
            }
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let initial = std::fs::read(&self.input)?;
        let queue = vec![initial.clone()];
        if !self.output_dir.exists() {
            std::fs::create_dir_all(&self.output_dir)?;
        }
        let z3_ctx_shared = z3::Context::new(&z3::Config::new());
        let solution_cache = Arc::new(RwLock::new(SymCCSolutionCache::new(&z3_ctx_shared)));
        let z3_ctx_private = z3::Context::new(&z3::Config::new());

        if self.symqemu {
            let config = SymQEMUSymStateConfig {
                harness: self.harness.clone(),
                qemu: self.qemu.clone(),
                llvm_symbolizer: self.llvm_symbolizer.clone(),
                executor_timeout_ms: self.timeout_ms,
                python: self.python.clone(),
                max_len: 10000,
                resolve_script: self.resolve_script.clone(),
            };
            let sym_state = new_symqemu_symstate(
                &config,
                1337,
                &self.workdir,
                &z3_ctx_private,
                solution_cache.clone(),
                self.interactive,
            )?;
            self.process(queue, sym_state)?;
        } else {
            let config = SymCCSymStateConfig {
                harness: self.harness.clone(),
                executor_timeout_ms: self.timeout_ms,
                python: self.python.clone(),
                max_len: 10000,
                resolve_script: self.resolve_script.clone(),
            };
            let sym_state = new_symcc_symstate(
                &config,
                &self.workdir,
                &z3_ctx_private,
                solution_cache.clone(),
            )?;
            self.process(queue, sym_state)?;
        }
        Ok(())
    }
}

fn parse_map(harness: &str, output: &str) {
    let map = parse_symcc_map(&PathBuf::from(harness)).expect("Failed to parse symcc map");
    let mut file = std::fs::File::create(output).expect("Failed to create output file");
    serde_json::to_writer_pretty(&mut file, &map).expect("Failed to write output");
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::ParseMap { harness, output } => parse_map(&harness, &output),
        Commands::Run {
            harness,
            workdir,
            input,
            timeout_ms,
            output,
            iters,
            symqemu,
            qemu,
            llvm_symbolizer,
            interactive,
            self_correct,
            python,
            resolve_script,
        } => {
            let mut runner = RunConcolic::new(
                harness,
                workdir,
                input,
                timeout_ms,
                output,
                iters,
                symqemu,
                qemu,
                llvm_symbolizer,
                interactive,
                self_correct,
                python,
                resolve_script,
            );
            runner.run().expect("Execution failed");
        }
    }
}
