use super::PathConstraintTransformer;
use crate::common::{Error, InputID};
use crate::concolic::symstate::common::solver::PathConstraintExpr;
use crate::concolic::{ConcolicExecutor, PathConstraint, SingleStepSession, TraceManager};

pub struct ReduceLoopPatterns {}

impl ReduceLoopPatterns {
    pub fn new() -> Self {
        ReduceLoopPatterns {}
    }

    /// This function calculates clusters of path constraints based on their site IDs.
    /// It groups consecutive path constraints with the same site ID into clusters.
    /// cluster == (start, end) where end is inclusive.
    fn calculate_clusters<PCM>(
        &self,
        path_constraints: &[PathConstraint<'_, PCM>],
    ) -> Vec<(usize, usize)> {
        let mut clusters = Vec::new();
        let mut i = 0;
        while i < path_constraints.len() {
            let start = i;
            while i + 1 < path_constraints.len()
                && path_constraints[i].site_id == path_constraints[i + 1].site_id
            {
                i += 1;
            }
            if i > start {
                let cluster = (start, i);
                clusters.push(cluster);
            }
            i += 1;
        }
        clusters
    }

    fn try_optimize_conseutive_path_constraints<'ctx, PCM: Clone>(
        &self,
        path_constraints: &[PathConstraint<'ctx, PCM>],
    ) -> Result<Option<PathConstraint<'ctx, PCM>>, Error> {
        let exprs = path_constraints
            .iter()
            .map(|pc| {
                if pc.taken {
                    pc.expr.clone()
                } else {
                    pc.expr.not()
                }
            })
            .collect::<Vec<_>>();
        let expr = PathConstraintExpr::and(&exprs);
        let site_id = path_constraints[0].site_id;
        let metadata = path_constraints[0].metadata.clone();
        let to_addrs = None;
        let taken = true;
        Ok(Some(PathConstraint::new(
            site_id, to_addrs, taken, expr, metadata,
        )))
    }
}

impl<'ctx, 'e, S, PCM, EX, TM, TR, AUX> PathConstraintTransformer<'ctx, S, PCM, EX, TM, TR, AUX>
    for ReduceLoopPatterns
where
    EX: ConcolicExecutor<TR, S>,
    TM: TraceManager<'ctx, TR, PCM, AUX>,
    S: SingleStepSession,
    PCM: Clone,
{
    fn transform(
        &mut self,
        _executor: &mut EX,
        _trace_manager: &mut TM,
        _input_id: InputID,
        _input: &[u8],
        path_constraints_: &mut Vec<PathConstraint<'ctx, PCM>>,
        _aux_: &mut AUX,
    ) -> Result<(), Error> {
        // find consecutive path constraints with the same site_id
        let clusters = self.calculate_clusters(path_constraints_);
        let mut i = 0;
        let mut path_constraints = vec![];
        for (start, end) in clusters {
            for j in i..=start {
                path_constraints.push(path_constraints_[j].clone());
            }
            if let Some(optimized) =
                self.try_optimize_conseutive_path_constraints(&path_constraints_[start..=end])?
            {
                path_constraints.push(optimized);
            } else {
                for j in start..=end {
                    path_constraints.push(path_constraints_[j].clone());
                }
            }
            i = end + 1;
        }
        for j in i..path_constraints_.len() {
            path_constraints.push(path_constraints_[j].clone());
        }
        *path_constraints_ = path_constraints;
        Ok(())
    }
}
