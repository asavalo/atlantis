use super::super::Solver;
use super::{
    load_trace_common, PathConstraint, SrcLocation, SymCCAux, SymCCPathConstraintMetadata,
    SymCCSolutionCache, SymCCSolutionToInput, SymCCTR, SymState, SymStateProfileData, TraceManager,
};
use crate::common::{Error, InputID};
use crate::concolic::symstate::path_constraint_transformer::{
    transformer_symqemu, ComplexPathConstraintTransformer, ReduceLoopPatterns,
};
use crate::concolic::{PathConstraintTransformer, SymQEMUExecutor, SymQEMUSingleStepSession};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use z3::Context;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SymQEMUSymStateConfig {
    pub harness: PathBuf,
    pub qemu: PathBuf,
    pub llvm_symbolizer: PathBuf,
    pub executor_timeout_ms: Option<u64>,
    pub max_len: usize,
    pub python: PathBuf,
    pub resolve_script: PathBuf,
}

pub struct SymQEMUTraceManager<'ctx> {
    ctx: &'ctx Context,
    image_mem_range: (usize, usize),
    llvm_symbolizer: PathBuf,
    executable: PathBuf,
    src_locations_cache: HashMap<u64, SrcLocation>,
    max_path_constraints: Option<usize>,
    capture_constant_path_constraints: bool,
}

impl<'ctx> SymQEMUTraceManager<'ctx> {
    pub fn new(
        ctx: &'ctx Context,
        image_mem_range: (usize, usize),
        llvm_symbolizer: &PathBuf,
        executable: &PathBuf,
        max_path_constraints: Option<usize>,
        capture_constant_path_constraints: bool,
    ) -> Result<Self, Error> {
        Ok(SymQEMUTraceManager {
            ctx,
            image_mem_range,
            llvm_symbolizer: llvm_symbolizer.canonicalize()?,
            executable: executable.canonicalize()?,
            src_locations_cache: HashMap::new(),
            max_path_constraints,
            capture_constant_path_constraints,
        })
    }
}

impl<'ctx> TraceManager<'ctx, SymCCTR, SymCCPathConstraintMetadata, SymCCAux<'ctx>>
    for SymQEMUTraceManager<'ctx>
{
    fn load_trace<'a>(
        &'a mut self,
        _input_id: InputID,
        trace: SymCCTR,
        previous_aux: Option<&SymCCAux<'ctx>>,
    ) -> Result<
        (
            Vec<PathConstraint<'ctx, SymCCPathConstraintMetadata>>,
            SymCCAux<'ctx>,
        ),
        Error,
    > {
        let mut unidentified_sites = vec![];
        let ctx = self.ctx;
        let max_path_constraints = self.max_path_constraints;
        let capture_constant_path_constraints = self.capture_constant_path_constraints;
        let src_location_fn = |location_u64: u64| {
            let (begin, end) = self.image_mem_range;
            if location_u64 < begin as u64 || location_u64 >= end as u64 {
                return None;
            }
            if let Some(src_location) = self.query_llvm_symbolizer(location_u64 - begin as u64) {
                Some(src_location.clone())
            } else {
                let msb = 1 << 63;
                if location_u64 & msb != 0 {
                    Some(SrcLocation {
                        src_path: "runtime".to_string(),
                        line: 0,
                        column: 0,
                    })
                } else {
                    unidentified_sites.push(location_u64);
                    None
                }
            }
        };
        let result = load_trace_common(
            ctx,
            trace,
            src_location_fn,
            max_path_constraints,
            capture_constant_path_constraints,
            previous_aux,
        )?;
        Ok((
            result.path_constraints,
            SymCCAux {
                messages: result.messages,
                translations: result.translations,
                coerced_values: result.coerced_values,
                unidentified_sites,
                failed_hook_calls: result.failed_hook_calls,
            },
        ))
    }
}

#[derive(Debug, Deserialize)]
pub struct LlvmSymbolizerOuput {
    #[serde(rename = "Symbol")]
    symbol: Vec<LlvmSymbolizerSymbol>,
}

#[derive(Debug, Deserialize)]
pub struct LlvmSymbolizerSymbol {
    #[serde(rename = "FileName")]
    file_name: String,
    #[serde(rename = "Line")]
    line: u64,
    #[serde(rename = "Column")]
    column: u64,
}

impl<'ctx> SymQEMUTraceManager<'ctx> {
    fn query_llvm_symbolizer(&mut self, location: u64) -> Option<SrcLocation> {
        if let Some(src_location) = self.src_locations_cache.get(&location) {
            return Some(src_location.clone());
        }
        let args = vec![
            self.llvm_symbolizer.to_str().unwrap().to_string(),
            format!("--obj={}", self.executable.to_str().unwrap()),
            "--output-style=JSON".to_string(),
            format!("0x{:x}", location),
        ];
        let output = match std::process::Command::new(&args[0])
            .args(&args[1..])
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                eprintln!("Failed to run llvm-symbolizer: {}", e);
                return None;
            }
        };
        let symbolizer_output: Vec<LlvmSymbolizerOuput> =
            match serde_json::from_slice(&output.stdout) {
                Ok(output) => output,
                Err(_) => {
                    eprintln!(
                        "Failed to parse llvm-symbolizer output: {}",
                        String::from_utf8_lossy(&output.stdout)
                    );
                    return None;
                }
            };
        // for now, let's just take the first symbol
        let symbol = symbolizer_output[0].symbol.get(0)?;
        let ret = SrcLocation {
            src_path: symbol.file_name.clone(),
            line: symbol.line,
            column: symbol.column,
        };
        self.src_locations_cache.insert(location, ret.clone());
        Some(ret)
    }
}

pub const MAX_SYMQEMU_CONSTRAINTS: usize = 1000;

pub struct SymQEMUSymState<'ctxp, 'ctxs> {
    executor: SymQEMUExecutor,
    workdir: PathBuf,
    transformer: ReduceLoopPatterns,
    trace_manager: SymQEMUTraceManager<'ctxp>,
    solver: Solver<'ctxp>,
    solution_to_input: SymCCSolutionToInput,
    solution_cache: Arc<RwLock<SymCCSolutionCache<'ctxs>>>,
    #[cfg(feature = "concolic_profiling")]
    profile_data: SymStateProfileData,
}

impl<'ctxp, 'ctxs> SymState<'ctxp, 'ctxs> for SymQEMUSymState<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    type SingleStepSession = SymQEMUSingleStepSession;
    type ConcolicExecutor = SymQEMUExecutor;
    type PathConstraintTransformer = ComplexPathConstraintTransformer;
    type Trace = SymCCTR;
    type PCM = SymCCPathConstraintMetadata;
    type AUX = SymCCAux<'ctxp>;
    type TraceManager = SymQEMUTraceManager<'ctxp>;
    type SolutionToInput = SymCCSolutionToInput;
    type SolutionCache = SymCCSolutionCache<'ctxs>;

    fn executor(&mut self) -> &mut Self::ConcolicExecutor {
        &mut self.executor
    }

    fn python(&self) -> &PathBuf {
        todo!()
    }

    fn resolve_script(&self) -> &PathBuf {
        todo!()
    }

    fn workdir(&self) -> &PathBuf {
        &self.workdir
    }

    fn transform(
        &mut self,
        input_id: InputID,
        input: &[u8],
        path_constraints: &mut Vec<PathConstraint<'ctxp, Self::PCM>>,
        aux: &mut Self::AUX,
    ) -> Result<(), Error> {
        self.transformer.transform(
            &mut self.executor,
            &mut self.trace_manager,
            input_id,
            input,
            path_constraints,
            aux,
        )?;
        Ok(())
    }

    fn trace_manager(&mut self) -> &mut Self::TraceManager {
        &mut self.trace_manager
    }

    fn solution_cache(&self) -> Arc<RwLock<Self::SolutionCache>> {
        self.solution_cache.clone()
    }

    fn solver(&mut self) -> &mut Solver<'ctxp> {
        &mut self.solver
    }

    fn solution_to_input(&mut self) -> &Self::SolutionToInput {
        &mut self.solution_to_input
    }

    fn profile_data(&self) -> &SymStateProfileData {
        &self.profile_data
    }

    fn profile_data_mut(&mut self) -> &mut SymStateProfileData {
        &mut self.profile_data
    }
}

pub fn new_symqemu_symstate<'ctxp, 'ctxs>(
    config: &SymQEMUSymStateConfig,
    worker_idx: usize,
    workdir: &PathBuf,
    z3_ctx_private: &'ctxp z3::Context,
    solution_cache: Arc<RwLock<SymCCSolutionCache<'ctxs>>>,
    interactive: bool,
) -> Result<SymQEMUSymState<'ctxp, 'ctxs>, Error>
where
    'ctxp: 'ctxs,
{
    let basic_hook = include_str!("../hook_basic.py").to_string();
    let executor = SymQEMUExecutor::new(
        &config.qemu,
        &config.harness,
        &workdir.join("executor"),
        worker_idx,
        config.executor_timeout_ms,
        interactive,
        false,
        &basic_hook,
    )?;
    let image_mem_range = executor.get_image_mem_range()?;
    let trace_manager = SymQEMUTraceManager::new(
        z3_ctx_private,
        image_mem_range,
        &config.llvm_symbolizer,
        &config.harness,
        Some(MAX_SYMQEMU_CONSTRAINTS),
        false,
    )?;
    let solver = Solver::new(z3_ctx_private);
    let solution_to_input = SymCCSolutionToInput::new(config.max_len);

    Ok(SymQEMUSymState {
        executor,
        workdir: workdir.clone(),
        transformer: transformer_symqemu(),
        trace_manager,
        solver,
        solution_to_input,
        solution_cache,
        #[cfg(feature = "concolic_profiling")]
        profile_data: SymStateProfileData::default(),
    })
}
