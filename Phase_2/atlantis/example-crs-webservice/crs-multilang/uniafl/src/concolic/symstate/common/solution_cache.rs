use super::path_constraint::PathConstraint;
use super::solver::AnnotatedSolution;
use crate::common::{afl::InputID, errors::Error};

pub trait SolutionCache<'ctxp, 'ctxs, PCM, AUX> {
    fn add_solution(
        &mut self,
        input_id: InputID,
        sol: AnnotatedSolution,
        path_constraints: &[PathConstraint<'ctxp, PCM>],
    ) -> Result<(), Error>;
    fn is_interesting(&self, path_constraints: &[PathConstraint<'ctxp, PCM>]) -> bool;
    fn get_cached_solution(&self, input_id: InputID) -> Option<AnnotatedSolution>;
    fn get_random_cached_solution(
        &self,
        exclude: &[InputID],
    ) -> Option<(InputID, AnnotatedSolution)>;
    #[allow(unused)]
    fn process_aux(&mut self, aux: AUX) -> Result<(), Error>;
}
