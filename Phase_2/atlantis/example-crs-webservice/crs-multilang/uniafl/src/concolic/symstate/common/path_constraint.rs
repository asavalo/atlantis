use super::solver::PathConstraintExpr;
use crate::common::afl::BlockAddr;

type FromAddr = BlockAddr;
type ToAddr = BlockAddr;
type TakenAddr = BlockAddr;
type NotTakenAddr = BlockAddr;
#[allow(dead_code)]
type NextAddr = BlockAddr;

pub type Taken = bool;

/// A PathConstraint for a branch observed during execution.
#[derive(Debug, Clone)]
pub struct PathConstraint<'ctx, PCM> {
    /// The site ID of the branch. It does not necessarily have to be the address of the branch.
    #[allow(dead_code)]
    pub site_id: FromAddr,
    /// The destination addresses of the branch, in the order of taken and not taken.
    /// We leave this field None for instrumentation frameworks/languages such that the destination addresses are unknown
    to_addrs: Option<(TakenAddr, NotTakenAddr)>,
    /// Whether the branch was taken or not during execution.
    pub taken: Taken,
    /// The branch predicate in z3 format
    pub expr: PathConstraintExpr<'ctx>,
    /// Metadata for the path constraint
    pub metadata: PCM,
}

#[allow(unused)]
/// A vector of PathConstraints is called a concolic 'trace'.
pub type ConcolicTrace<'ctx, PCM> = Vec<PathConstraint<'ctx, PCM>>;

impl<'ctx, PCM> PathConstraint<'ctx, PCM> {
    pub fn new(
        site_id: FromAddr,
        to_addrs: Option<(TakenAddr, NotTakenAddr)>,
        taken: Taken,
        expr: PathConstraintExpr<'ctx>,
        metadata: PCM,
    ) -> Self {
        Self {
            site_id,
            to_addrs,
            taken,
            expr,
            metadata,
        }
    }

    pub fn flip_expr(&self) -> PathConstraintExpr<'ctx> {
        if self.taken {
            self.expr.not()
        } else {
            self.expr.clone()
        }
    }

    pub fn get_taken_expr(&self) -> PathConstraintExpr<'ctx> {
        if self.taken {
            self.expr.clone()
        } else {
            self.expr.not()
        }
    }

    #[allow(dead_code)]
    pub fn get_to_addr(&self) -> Option<ToAddr> {
        match self.to_addrs {
            Some((taken_addr, not_taken_addr)) => {
                if self.taken {
                    Some(taken_addr)
                } else {
                    Some(not_taken_addr)
                }
            }
            None => None,
        }
    }
}
