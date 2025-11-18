use crate::common::{Error, InputID};
use crate::concolic::{ConcolicExecutor, PathConstraint, SingleStepSession};

pub use include_data_length::IncludeDataLength;
pub use reduce_loop_patterns::ReduceLoopPatterns;

use super::TraceManager;

mod include_data_length;
mod reduce_loop_patterns;

pub type ComplexPathConstraintTransformer = (ReduceLoopPatterns, IncludeDataLength);

pub fn transformer_symcc() -> ComplexPathConstraintTransformer {
    (ReduceLoopPatterns::new(), IncludeDataLength::new())
}

pub fn transformer_symqemu() -> ReduceLoopPatterns {
    ReduceLoopPatterns::new()
}

pub trait PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX>
where
    EX: ConcolicExecutor<TR, S>,
    TM: TraceManager<'ctx, TR, PCM, AUX>,
    S: SingleStepSession,
{
    fn transform(
        &mut self,
        executor: &mut EX,
        trace_manager: &mut TM,
        input_id: InputID,
        input: &[u8],
        path_constraints: &mut Vec<PathConstraint<'ctx, PCM>>,
        aux: &mut AUX,
    ) -> Result<(), Error>;
}

impl<'ctx, PCM, EX, TM, TR, S, AUX> PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX> for ()
where
    EX: ConcolicExecutor<TR, S>,
    TM: TraceManager<'ctx, TR, PCM, AUX>,
    S: SingleStepSession,
{
    fn transform(
        &mut self,
        _executor: &mut EX,
        _trace_manager: &mut TM,
        _input_id: InputID,
        _input: &[u8],
        _path_constraints: &mut Vec<PathConstraint<'ctx, PCM>>,
        _aux: &mut AUX,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<'ctx, PCM, EX, TM, TR, S, AUX, Head, Tail>
    PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX> for (Head, Tail)
where
    EX: ConcolicExecutor<TR, S>,
    TM: TraceManager<'ctx, TR, PCM, AUX>,
    S: SingleStepSession,
    Head: PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX>,
    Tail: PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX>,
{
    fn transform(
        &mut self,
        _executor: &mut EX,
        _trace_manager: &mut TM,
        _input_id: InputID,
        _input: &[u8],
        _path_constraints: &mut Vec<PathConstraint<'ctx, PCM>>,
        _aux: &mut AUX,
    ) -> Result<(), Error> {
        self.0.transform(
            _executor,
            _trace_manager,
            _input_id,
            _input,
            _path_constraints,
            _aux,
        )?;
        self.1.transform(
            _executor,
            _trace_manager,
            _input_id,
            _input,
            _path_constraints,
            _aux,
        )?;
        Ok(())
    }
}
