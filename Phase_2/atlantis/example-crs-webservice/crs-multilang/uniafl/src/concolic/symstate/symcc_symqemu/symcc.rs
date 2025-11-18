use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use z3::Context;

use super::super::common::path_constraint::PathConstraint;
use super::super::SymState;
use super::{
    load_trace_common, parse_symcc_map, Solver, SrcLocation, SymCCAux, SymCCMap,
    SymCCPathConstraintMetadata, SymCCSolutionCache, SymCCSolutionToInput, SymCCTR,
    SymStateProfileData, TraceManager,
};
use crate::common::{Error, InputID};
use crate::concolic::symstate::path_constraint_transformer::{
    transformer_symcc, ComplexPathConstraintTransformer,
};
use crate::concolic::{
    PathConstraintTransformer, SymCCExecutor, SymCCInstallFunctionCallHook, SymCCSingleStepSession,
};

pub struct SymCCTraceManager<'ctx> {
    ctx: &'ctx Context,
    symcc_map: SymCCMap,
    max_path_constraints: Option<usize>,
    capture_constant_path_constraints: bool,
}

impl<'ctx> TraceManager<'ctx, SymCCTR, SymCCPathConstraintMetadata, SymCCAux<'ctx>>
    for SymCCTraceManager<'ctx>
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
        let src_location_fn = |location_u64: u64| {
            if let Some(src_location) = self.symcc_map.inner.get(&location_u64) {
                Some(src_location.clone())
            } else {
                /*
                 * This can happen when the site ID is generated inside the runtime
                 * or the symcc map is incorrect (incomplete).
                 * For SymCC runtime site IDs, it should have an MSB of 1.
                 */
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
            self.ctx,
            trace,
            src_location_fn,
            self.max_path_constraints,
            self.capture_constant_path_constraints,
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

impl<'ctx> SymCCTraceManager<'ctx> {
    pub fn new(
        ctx: &'ctx Context,
        harness: &PathBuf,
        max_path_constraints: Option<usize>,
    ) -> Result<Self, Error> {
        let symcc_map = parse_symcc_map(harness)?;
        Ok(SymCCTraceManager {
            ctx,
            symcc_map,
            max_path_constraints,
            capture_constant_path_constraints: false,
        })
    }

    #[allow(dead_code)]
    pub fn set_capture_constant_path_constraints(
        &mut self,
        capture_constant_path_constraints: bool,
    ) {
        self.capture_constant_path_constraints = capture_constant_path_constraints;
    }
}

pub struct SymCCSymState<'ctxp, 'ctxs> {
    executor: SymCCExecutor,
    workdir: PathBuf,
    transformer: ComplexPathConstraintTransformer,
    trace_manager: SymCCTraceManager<'ctxp>,
    solver: Solver<'ctxp>,
    solution_to_input: SymCCSolutionToInput,
    solution_cache: Arc<RwLock<SymCCSolutionCache<'ctxs>>>,
    config: SymCCSymStateConfig,
    #[cfg(feature = "concolic_profiling")]
    profile_data: SymStateProfileData,
}

impl<'ctxp, 'ctxs> SymState<'ctxp, 'ctxs> for SymCCSymState<'ctxp, 'ctxs>
where
    'ctxp: 'ctxs,
{
    type SingleStepSession = SymCCSingleStepSession;
    type ConcolicExecutor = SymCCExecutor;
    type PathConstraintTransformer = ComplexPathConstraintTransformer;
    type Trace = SymCCTR;
    type PCM = SymCCPathConstraintMetadata;
    type AUX = SymCCAux<'ctxp>;
    type TraceManager = SymCCTraceManager<'ctxp>;
    type SolutionToInput = SymCCSolutionToInput;
    type SolutionCache = SymCCSolutionCache<'ctxs>;

    fn executor(&mut self) -> &mut Self::ConcolicExecutor {
        &mut self.executor
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
        )
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

    fn workdir(&self) -> &PathBuf {
        &self.workdir
    }

    fn python(&self) -> &PathBuf {
        &self.config.python
    }

    fn resolve_script(&self) -> &PathBuf {
        &self.config.resolve_script
    }

    fn profile_data(&self) -> &SymStateProfileData {
        &self.profile_data
    }

    fn profile_data_mut(&mut self) -> &mut SymStateProfileData {
        &mut self.profile_data
    }
}

pub const MAX_SYMCC_CONSTRAINTS: usize = usize::MAX;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymCCSymStateConfig {
    pub harness: PathBuf,
    pub executor_timeout_ms: Option<u64>,
    pub python: PathBuf,
    pub resolve_script: PathBuf,
    pub max_len: usize,
}

pub fn new_symcc_symstate<'ctxp, 'ctxs>(
    config: &SymCCSymStateConfig,
    workdir: &PathBuf,
    z3_ctx_private: &'ctxp z3::Context,
    solution_cache: Arc<RwLock<SymCCSolutionCache<'ctxs>>>,
) -> Result<SymCCSymState<'ctxp, 'ctxs>, Error>
where
    'ctxp: 'ctxs,
{
    // unsafe: the Context pointer comes from a box and is live until SymStatePrivate is destructed
    let trace_manager =
        SymCCTraceManager::new(z3_ctx_private, &config.harness, Some(MAX_SYMCC_CONSTRAINTS))?;
    let solver = Solver::new(z3_ctx_private);
    let solution_to_input = SymCCSolutionToInput::new(config.max_len);
    let mut executor = SymCCExecutor::new(
        &config.harness,
        &workdir.join("executor"),
        config.executor_timeout_ms,
    )?;
    let python_code = include_str!("../hook_basic.py").to_string();
    executor.install_function_call_hook(python_code)?;
    executor.set_ignore_nonzero_exits(true);
    Ok(SymCCSymState {
        executor,
        workdir: workdir.join("symstate"),
        transformer: transformer_symcc(),
        trace_manager,
        solver,
        solution_to_input,
        solution_cache,
        config: config.clone(),
        profile_data: SymStateProfileData::default(),
    })
}
