use super::PathConstraintTransformer;
use crate::common::{Error, InputID};
use crate::concolic::{
    ConcolicExecutor, PathConstraint, SingleStepSession, SymCCEnableDataLengthSymbolization,
    TraceManager, SrcLocation
};

pub struct IncludeDataLength {}

#[allow(unused)]
impl IncludeDataLength {
    pub fn new() -> Self {
        IncludeDataLength {}
    }
}

impl<'ctx, 'e, S, PCM, EX, TM, TR, AUX> PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX>
    for IncludeDataLength
where
    EX: ConcolicExecutor<TR, S> + SymCCEnableDataLengthSymbolization,
    TM: TraceManager<'ctx, TR, PCM, AUX>,
    S: SingleStepSession,
    PCM: Clone + Into<Option<SrcLocation>>,
{
    fn transform(
        &mut self,
        executor: &mut EX,
        trace_manager: &mut TM,
        input_id: InputID,
        input: &[u8],
        path_constraints: &mut Vec<PathConstraint<'ctx, PCM>>,
        aux: &mut AUX,
    ) -> Result<(), Error> {
        if path_constraints.len() == 0 {
            executor.enable_data_length_symbolization();
            let trace = executor.execute(input_id, input)?;
            executor.disable_data_length_symbolization();
            (*path_constraints, *aux) = trace_manager.load_trace(input_id, trace, None)?;
        }
        Ok(())
    }
}
