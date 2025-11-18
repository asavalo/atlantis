use super::path_constraint::PathConstraint;
use crate::common::{afl::InputID, errors::Error};

pub trait TraceManager<'ctx, TR, PCM, AUX> {
    fn load_trace<'a>(
        &'a mut self,
        input_id: InputID,
        trace: TR,
        previous_aux: Option<&AUX>,
    ) -> Result<(Vec<PathConstraint<'ctx, PCM>>, AUX), Error>;
}
