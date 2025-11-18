use super::super::symcc_symqemu::TranslationEntry;
use super::solver::Solver;
use crate::common::Error;
use z3::{
    ast::{Ast, Dynamic, BV},
    Context, DeclKind, SatResult, Solver as Z3Solver,
};

pub trait ExprOptimizer<'ctx> {
    fn optimize(
        &mut self,
        expr: TranslationEntry<'ctx, Dynamic<'ctx>>,
    ) -> Result<TranslationEntry<'ctx, Dynamic<'ctx>>, Error>;
}

pub struct ConcatOptimizer<'ctx> {
    z3_ctx: &'ctx Context,
}

impl<'ctx> ConcatOptimizer<'ctx> {
    pub fn new(z3_ctx: &'ctx Context) -> Self {
        ConcatOptimizer { z3_ctx }
    }

    fn optimize_data_length(
        &self,
        expr: TranslationEntry<'ctx, Dynamic<'ctx>>,
        data_length: Dynamic<'ctx>,
    ) -> Result<TranslationEntry<'ctx, Dynamic<'ctx>>, Error> {
        // check if the expression can be reduced into a form data_length + C
        let addend = BV::new_const(
            &self.z3_ctx,
            "addend",
            data_length.as_bv().unwrap().get_size(),
        );
        let compound_expr = data_length.as_bv().unwrap().bvadd(&addend);
        let solver = Z3Solver::new(self.z3_ctx);
        // we can safely assume expr is of type BV because we check get_sort equality before
        // calling this function
        solver.assert(&compound_expr._eq(&expr.expr().as_bv().unwrap()));
        let result = solver.check();
        match result {
            SatResult::Sat => {
                if let Some(model) = solver.get_model() {
                    let addend_value = model.eval(&addend, false).unwrap();
                    let new_expr = data_length.as_bv().unwrap().bvadd(&addend_value);

                    // check that this is the only solution
                    solver.assert(&addend._eq(&addend_value).not());
                    match solver.check() {
                        SatResult::Sat => {
                            // there are multiple solutions, we cannot optimize
                            return Ok(expr);
                        }
                        SatResult::Unsat => {
                            // this is the only solution
                            return Ok(TranslationEntry::new_scalar(
                                new_expr.into(),
                                1,
                                expr.coerced_values().clone(),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Ok(expr)
    }

    fn optimize_other(
        &self,
        expr: TranslationEntry<'ctx, Dynamic<'ctx>>,
        other: Dynamic<'ctx>,
    ) -> Result<TranslationEntry<'ctx, Dynamic<'ctx>>, Error> {
        let solver = Z3Solver::new(self.z3_ctx);
        solver.assert(&other._eq(&expr.expr()));
        let result = solver.check();
        match result {
            SatResult::Sat => {
                return Ok(TranslationEntry::new_scalar(other.into(), 0, expr.coerced_values().clone()));
            }
            _ => {}
        }
        Ok(expr)
    }
}

impl<'ctx> ExprOptimizer<'ctx> for ConcatOptimizer<'ctx> {
    fn optimize(
        &mut self,
        expr: TranslationEntry<'ctx, Dynamic<'ctx>>,
    ) -> Result<TranslationEntry<'ctx, Dynamic<'ctx>>, Error> {
        if expr.depth() < 5 && expr.expr().is_app() {
            if let DeclKind::CONCAT = expr.expr().decl().kind() {
                let identifiers: Vec<Dynamic<'ctx>> =
                    Solver::gather_const_apps(expr.expr().clone().into())
                        .into_iter()
                        .collect();
                if identifiers.len() != 1 {
                    // If there are multiple identifiers, we cannot optimize
                    return Ok(expr);
                }
                let const_app = identifiers[0].clone();
                // test if the two expressions are equivalent
                if expr.expr().get_sort() != const_app.get_sort() {
                    return Ok(expr);
                }
                if const_app.decl().name() == "data_length" {
                    return self.optimize_data_length(expr, const_app);
                } else {
                    return self.optimize_other(expr, const_app);
                }
            }
        }
        Ok(expr)
    }
}
