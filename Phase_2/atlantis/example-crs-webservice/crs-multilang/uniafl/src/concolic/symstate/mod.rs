use super::SingleStepSession;
#[cfg(feature = "concolic_profiling")]
use super::SymStateProfileData;
use crate::common::{Error, InputID};
use serde::{ser::SerializeStruct, Serialize, Serializer};
use std::sync::{Arc, RwLock};
use std::time::Instant;
mod common;
mod path_constraint_transformer;
mod self_correction;
mod symcc_symqemu;

use crate::concolic::executor::{ConcolicExecutor, SingleStepResult};
#[allow(unused_imports)]
pub use common::path_constraint::{ConcolicTrace, PathConstraint};
pub use common::solution_cache::SolutionCache;
pub use common::solution_to_input::SolutionToInput;
use common::solver::IdentifierMap;
pub use common::solver::{AnnotatedSolution, Solver};
pub use common::trace_manager::TraceManager;
pub use path_constraint_transformer::PathConstraintTransformer;
#[allow(unused_imports)]
pub use self_correction::SelfCorrectingSymState;
use std::path::PathBuf;
#[allow(unused_imports)]
pub use symcc_symqemu::{
    new_symcc_symstate, new_symqemu_symstate, offset_to_symbol, parse_symcc_map, IsSymCCAux,
    SrcLocation, SymCCAux, SymCCMap, SymCCPathConstraintMetadata, SymCCSolutionCache,
    SymCCSymState, SymCCSymStateConfig, SymCCTR, SymCCTraceManager, SymExpr, SymExprRef,
    SymQEMUSymState, SymQEMUSymStateConfig, SymQEMUTraceManager, TranslationEntry,
};

impl<'a, PCM> Serialize for PathConstraint<'a, PCM>
where
    PCM: Into<Option<SrcLocation>> + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let expr_ast = if self.taken {
            self.expr.expr.clone()
        } else {
            self.expr.expr.not()
        };
        let mut identifier_map = IdentifierMap::new();
        let expr_string = if self.expr.expr_depth < 100 {
            Some(expr_ast.to_string())
        } else {
            None
        };
        let related_identifiers: Vec<String> =
            Solver::gather_identifiers(self.expr.clone().into(), &mut identifier_map)
                .iter()
                .map(|x| x.to_string())
                .collect();
        let mut state = serializer.serialize_struct("PathConstraint", 4)?;
        state.serialize_field("related_identifiers", &related_identifiers)?;
        state.serialize_field("expr_string", &expr_string)?;
        let src_location: Option<SrcLocation> = self.metadata.clone().into();
        state.serialize_field("src_location", &src_location)?;
        state.serialize_field("site_id", &self.site_id)?;
        state.end()
    }
}

#[derive(Debug, Serialize)]
pub struct MissedPathConstraint {
    pub site_id: u64,
    pub src_location: Option<SrcLocation>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct SymStateProcessResult<'ctxp, T, PCM> {
    pub new_inputs: Vec<Vec<u8>>,
    pub new_input_constraints: Vec<PathConstraint<'ctxp, PCM>>,
    pub is_new_input: bool,
    pub unsolved_path_constraints: Vec<PathConstraint<'ctxp, PCM>>,
    pub aux: T,
}

impl<'ctxp, T, PCM> Serialize for SymStateProcessResult<'ctxp, T, PCM>
where
    T: Serialize,
    PCM: Into<Option<SrcLocation>> + Clone,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SymStateProcessResult", 4)?;
        state.serialize_field("new_input_constraints", &self.new_input_constraints)?;
        state.serialize_field("is_new_input", &self.is_new_input)?;
        state.serialize_field("unsolved_path_constraints", &self.unsolved_path_constraints)?;
        state.serialize_field("aux", &self.aux)?;
        state.end()
    }
}

/// Abstraction for trace parsing, solving and solution caching
/// This struct is the entry point for concolic solving.
/// 'ctx: The lifetime of the Z3 context
/// TR: The type of trace (e.g. String, Vec<u8>, FilePath)
/// TM: Trace Manager is responsible for parsing the trace into a common internal form
/// (Vec<PathConstraint>) and (optionally) caching it for subsequent optimizations
/// STI: Solution To Input implements the synthesis of new inputs from the obtained Z3 model.
/// SC: Solution Cache maintains a mapping from (inputID) => (new_inputs).
pub trait SymState<'ctxp, 'ctxs> {
    type SingleStepSession: SingleStepSession;
    type ConcolicExecutor: ConcolicExecutor<Self::Trace, Self::SingleStepSession>;
    type PathConstraintTransformer: PathConstraintTransformer<
        'ctxp,
        Self::SingleStepSession,
        Self::PCM,
        Self::ConcolicExecutor,
        Self::TraceManager,
        Self::Trace,
        Self::AUX,
    >;
    type Trace;
    type PCM: Into<Option<SrcLocation>> + Clone;
    type AUX: Serialize + Default;
    type TraceManager: TraceManager<'ctxp, Self::Trace, Self::PCM, Self::AUX>;
    type SolutionToInput: SolutionToInput;
    type SolutionCache: SolutionCache<'ctxp, 'ctxs, Self::PCM, Self::AUX>;

    fn executor(&mut self) -> &mut Self::ConcolicExecutor;
    fn workdir(&self) -> &PathBuf;
    fn python(&self) -> &PathBuf;
    fn resolve_script(&self) -> &PathBuf;
    fn transform(
        &mut self,
        input_id: InputID,
        input: &[u8],
        path_constraints: &mut Vec<PathConstraint<'ctxp, Self::PCM>>,
        aux: &mut Self::AUX,
    ) -> Result<(), Error>;
    fn trace_manager(&mut self) -> &mut Self::TraceManager;
    fn solution_cache(&self) -> Arc<RwLock<Self::SolutionCache>>;
    fn solver(&mut self) -> &mut Solver<'ctxp>;
    fn solution_to_input(&mut self) -> &Self::SolutionToInput;
    fn profile_data(&self) -> &SymStateProfileData;
    fn profile_data_mut(&mut self) -> &mut SymStateProfileData;
    fn crossover(
        &mut self,
        input_id: InputID,
        input: &[u8],
        cached_solution: AnnotatedSolution,
    ) -> Result<SymStateProcessResult<'ctxp, Self::AUX, Self::PCM>, Error> {
        let cached_solution = cached_solution.clone();
        let mut exclude = vec![input_id];
        let mut solutions = vec![cached_solution];
        let solution_cache = self.solution_cache();
        for _ in 0..CROSSOVER_CNT {
            if let Some((_, solution)) = {
                let handle = solution_cache.read().unwrap();
                handle.get_random_cached_solution(&exclude)
            } {
                solutions.push(solution.clone());
            } else {
                break;
            }
            exclude.push(input_id);
        }
        let mut new_inputs = vec![];
        let mut current_input = input.to_vec();
        if solutions.len() > 1 {
            for solution in solutions {
                let mut inputs_from_solution = self
                    .solution_to_input()
                    .solution_to_input(&current_input, &solution)?;
                if let Some(current_input_) = inputs_from_solution.last().map(|x| x.to_vec()) {
                    new_inputs.append(&mut inputs_from_solution);
                    current_input = current_input_;
                }
            }
        }
        self.profile_data_mut().total_crossover_count += 1;
        Ok(SymStateProcessResult {
            new_inputs,
            new_input_constraints: vec![],
            is_new_input: false,
            unsolved_path_constraints: vec![],
            aux: Self::AUX::default(),
        })
    }

    fn concolic_mutation(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<SymStateProcessResult<'ctxp, Self::AUX, Self::PCM>, Error> {
        let mut new_inputs = vec![];
        let mut unsolved_path_constraints = vec![];
        let mut new_input_constraints = vec![];
        let mut time_begin = Instant::now();
        let trace = self.executor().execute(input_id, input)?;
        println!(
            "execution complete in {} ms",
            time_begin.elapsed().as_millis()
        );
        time_begin = Instant::now();
        let (mut path_constraints, mut aux) =
            self.trace_manager().load_trace(input_id, trace, None)?;
        println!(
            "trace loading complete in {} ms",
            time_begin.elapsed().as_millis()
        );
        time_begin = Instant::now();
        self.transform(input_id, input, &mut path_constraints, &mut aux)?;
        println!(
            "transformation complete in {} ms",
            time_begin.elapsed().as_millis()
        );
        time_begin = Instant::now();
        // if still empty after transforming, we give up
        if path_constraints.is_empty() {
            return Err(Error::invalid_trace_generation());
        }
        let solution_cache_handle_ = self.solution_cache();
        let maybe_solutions = self.solver().flip_all(
            &path_constraints,
            {
                let solution_cache_handle = solution_cache_handle_.clone();
                move |path_constraints| {
                    Ok(solution_cache_handle
                        .read()
                        .unwrap()
                        .is_interesting(path_constraints))
                }
            },
            {
                let solution_cache_handle = solution_cache_handle_.clone();
                let new_input_constraints = &mut new_input_constraints;
                move |path_constraints: &[PathConstraint<'ctxp, Self::PCM>],
                      solution: &AnnotatedSolution| {
                    // ignore errors
                    let _ = solution_cache_handle.write().unwrap().add_solution(
                        input_id,
                        solution.clone(),
                        path_constraints,
                    );
                    new_input_constraints.push(path_constraints.last().unwrap().clone());
                    Ok(())
                }
            },
            {
                |path_constraints: &[PathConstraint<'ctxp, Self::PCM>]| {
                    // ignore errors
                    unsolved_path_constraints.push(path_constraints.last().unwrap().clone());
                    Ok(())
                }
            },
        );
        println!(
            "solving complete in {} ms",
            time_begin.elapsed().as_millis()
        );
        self.profile_data_mut().solver_invocation_count += 1;
        self.profile_data_mut().total_solving_time_ms += time_begin.elapsed().as_millis() as u64;
        // TODO: afaik there are no paths inside the solver that can return an error, is this true?
        let solutions = maybe_solutions?;
        for solution in solutions {
            // if UNSAT, solution will be None
            if let Some(solution) = solution {
                let mut inputs_from_solution = self
                    .solution_to_input()
                    .solution_to_input(input, &solution)?;
                new_inputs.append(&mut inputs_from_solution);
                self.profile_data_mut().sat_path_constraint_count += 1;
            } else {
                self.profile_data_mut().unsat_path_constraint_count += 1;
            }
        }
        Ok(SymStateProcessResult {
            new_inputs,
            new_input_constraints,
            is_new_input: true,
            unsolved_path_constraints,
            aux,
        })
    }

    fn process(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<SymStateProcessResult<'ctxp, Self::AUX, Self::PCM>, Error> {
        if let Some(cached_solution) = {
            let lock = self.solution_cache();
            let handle = lock.read().unwrap();
            handle.get_cached_solution(input_id)
        } {
            self.crossover(input_id, input, cached_solution)
        } else {
            self.concolic_mutation(input_id, input)
        }
    }
}

const CROSSOVER_CNT: usize = 3;
