use super::graph_utils::connected_components;
use super::path_constraint::PathConstraint;
use crate::common::errors::Error;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use z3::ast::BV;
use z3::Optimize;
use z3::{
    ast::{Ast, Bool, Dynamic},
    Config, Context, Model, SatResult, Solver as Z3Solver,
};
use z3_sys::Z3_ast;

pub type VarId = String;
pub type Value = u64;

#[derive(Debug, Clone)]
pub struct PathConstraintExpr<'ctx> {
    pub expr: Bool<'ctx>,
    pub expr_depth: usize,
    pub coerced_values: HashSet<Dynamic<'ctx>>,
}

impl<'ctx> From<&PathConstraintExpr<'ctx>> for Dynamic<'ctx> {
    fn from(c: &PathConstraintExpr<'ctx>) -> Self {
        c.expr.clone().into()
    }
}

impl<'ctx> From<PathConstraintExpr<'ctx>> for Dynamic<'ctx> {
    fn from(c: PathConstraintExpr<'ctx>) -> Self {
        c.expr.into()
    }
}

impl<'ctx> PathConstraintExpr<'ctx> {
    pub fn new(
        expr: Bool<'ctx>,
        expr_depth: usize,
        coerced_values: HashSet<Dynamic<'ctx>>,
    ) -> Self {
        Self {
            expr,
            expr_depth,
            coerced_values,
        }
    }

    pub fn depth(&self) -> usize {
        self.expr_depth
    }

    pub fn not(&self) -> Self {
        PathConstraintExpr::new(
            self.expr.not(),
            self.expr_depth + 1,
            self.coerced_values.clone(),
        )
    }

    pub fn and(others: &[PathConstraintExpr<'ctx>]) -> Self {
        assert!(others.len() > 0);
        let mut others_expr = vec![];
        let mut expr_depth = 0;
        let mut coerced_values = HashSet::new();
        for c in others.iter() {
            others_expr.push(c.expr.clone());
            expr_depth = usize::max(expr_depth, c.expr_depth);
            coerced_values.extend(c.coerced_values.clone());
        }
        PathConstraintExpr::new(
            Bool::and(others[0].expr.get_ctx(), others_expr.as_slice()),
            expr_depth + 1,
            coerced_values,
        )
    }
}

pub type Constraints<'ctx> = Vec<PathConstraintExpr<'ctx>>;
pub type IdentifierMap = HashMap<Z3_ast, HashSet<VarId>>;
pub type RelationGraph = HashMap<VarId, HashSet<VarId>>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Solution {
    inner: HashSet<(VarId, Value)>,
}

impl Hash for Solution {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut sorted_solution: Vec<_> = self.inner.iter().collect();
        sorted_solution.sort_by_key(|&(ref var_id, ref value)| (var_id, value));

        for (var_id, value) in sorted_solution {
            var_id.hash(state);
            value.hash(state);
        }
    }
}

impl Solution {
    pub fn new() -> Self {
        Solution {
            inner: HashSet::new(),
        }
    }

    pub fn insert(&mut self, symbol: VarId, value: Value) {
        self.inner.insert((symbol, value));
    }

    pub fn iter(&self) -> std::collections::hash_set::Iter<'_, (VarId, Value)> {
        self.inner.iter()
    }
}

#[derive(Debug)]
pub struct Solver<'ctx> {
    ctx: &'ctx Context,
    max_data_length_created: u64,
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum SolutionType {
    Normal,
    Optimistic,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AnnotatedSolution {
    pub sol_type: SolutionType,
    pub sol: Solution,
}

const TIMEOUT: u64 = 30 * 1000; // 30s

#[allow(unused)]
impl<'ctx> Solver<'ctx> {
    #[allow(dead_code)]
    pub fn new_ctx() -> Context {
        let mut cfg = Config::new();
        cfg.set_timeout_msec(TIMEOUT);
        Context::new(&cfg)
    }

    pub fn new(ctx: &'ctx Context) -> Self {
        Self {
            ctx,
            max_data_length_created: 0,
        }
    }

    fn new_z3_solver(&self) -> Z3Solver<'ctx> {
        Z3Solver::new(self.ctx)
    }

    fn new_z3_optimize(&self) -> Optimize<'ctx> {
        Optimize::new(self.ctx)
    }

    pub fn gather_identifiers(expr: Dynamic, identifier_map: &mut IdentifierMap) -> HashSet<VarId> {
        let z3_ast = expr.get_z3_ast();
        if !identifier_map.contains_key(&z3_ast) {
            let mut vars = HashSet::new();
            let mut stack = vec![expr.clone()];
            while let Some(expr) = stack.pop() {
                if expr.is_const() && expr.kind() == z3::AstKind::App {
                    let id = expr.decl().name();
                    vars.insert(id);
                }
                for child in expr.children() {
                    stack.push(child);
                }
            }
            identifier_map.insert(z3_ast, vars.clone());
        }
        identifier_map.get(&z3_ast).unwrap().clone()
    }

    pub fn gather_const_apps(expr: Dynamic<'ctx>) -> HashSet<Dynamic<'ctx>> {
        let mut vars = HashSet::new();
        let mut stack = vec![expr.clone()];
        while let Some(expr) = stack.pop() {
            if expr.is_const() && expr.kind() == z3::AstKind::App {
                vars.insert(expr.clone());
            }
            for child in expr.children() {
                stack.push(child);
            }
        }
        vars
    }

    fn construct_relation_graph(
        bases: &[PathConstraintExpr<'ctx>],
        identifier_map: &mut IdentifierMap,
    ) -> RelationGraph {
        let mut graph = RelationGraph::new();
        for base in bases {
            let idents = Self::gather_identifiers(base.into(), identifier_map);
            for ident in idents.iter() {
                graph
                    .entry(ident.clone())
                    .or_insert(HashSet::new())
                    .extend(idents.clone());
            }
        }
        graph
    }

    // Obtain a set of variables that are related to at least one of the target variables
    fn get_related_vars(graph: &RelationGraph, targets: &HashSet<VarId>) -> HashSet<VarId> {
        let mut related_vars = HashSet::new();
        let mut stack: Vec<String> = targets.iter().cloned().collect();
        let mut visited = targets.clone();
        while let Some(var) = stack.pop() {
            if related_vars.insert(var.clone()) {
                if let Some(neighbors) = graph.get(&var) {
                    for neighbor in neighbors {
                        if visited.insert(neighbor.clone()) {
                            stack.push(neighbor.clone())
                        }
                    }
                }
            }
        }
        related_vars
    }

    /// Check if the expression e contains any of the target variables
    fn has_vars(
        e: &PathConstraintExpr,
        ident_map: &mut IdentifierMap,
        targets: &HashSet<VarId>,
    ) -> bool {
        let vars = Self::gather_identifiers(e.expr.clone().into(), ident_map);
        !vars.is_disjoint(targets)
    }

    const DATA_LENGTH_CLUSTER_ID: usize = 0;

    fn cluster_constraints(&self, constraints: &Constraints<'ctx>) -> (usize, Vec<usize>, bool) {
        let mut ret = vec![usize::MAX; constraints.len()];
        let mut ident_map = IdentifierMap::new();
        let var_graph = Self::construct_relation_graph(constraints.as_slice(), &mut ident_map);
        let mut clusters: Vec<HashSet<String>> = connected_components(&var_graph);
        let mut found_data_length = false;
        let mut cluster_zero_only_contains_data_length = false;
        let mut reverse_map = HashMap::new();
        for i in 0..clusters.len() {
            let cluster = &clusters[i];
            if cluster.contains("data_length") {
                let temp = clusters[i].clone();
                cluster_zero_only_contains_data_length = cluster.len() == 1;
                clusters[i] = clusters[0].clone();
                clusters[0] = temp;
                found_data_length = true;
                break;
            }
        }
        for (i, cluster) in clusters.iter().enumerate() {
            for var in cluster {
                if reverse_map.insert(var.clone(), i).is_some() {
                    // If the variable is already in the reverse map, it means it's a duplicate
                    // which should not exist.
                    unreachable!();
                }
            }
        }

        // insert placehodler for data_length cluster so that its cluster id is always 0
        if !found_data_length {
            clusters.insert(0, HashSet::new());
        }

        for i in 0..constraints.len() {
            let terms =
                Self::gather_identifiers(constraints[i].expr.clone().into(), &mut ident_map);
            if terms.len() == 0 {
                unreachable!();
            }
            ret[i] = *reverse_map
                .get(terms.iter().next().unwrap().as_str())
                .unwrap();
        }
        (clusters.len(), ret, cluster_zero_only_contains_data_length)
    }

    fn model_to_solution(&self, model: &Model) -> Result<Solution, Error> {
        let mut sol = Solution::new();
        let empty_args = vec![];
        for item in model.iter() {
            let item_name = item.name();
            if item_name.starts_with("k!") {
                let item_ast =
                    model
                        .get_const_interp(&item.apply(&empty_args))
                        .ok_or(Error::other(format!(
                            "could not interpret funcdecl {} as constant",
                            item_name
                        )))?;
                let item_str = item_ast.to_string();
                let value_str = item_str.strip_prefix("#x").ok_or(Error::other(format!(
                    "invalid value {} for symbol {}",
                    item_name, item_str
                )))?;
                let value = u64::from_str_radix(value_str, 16)?;
                sol.insert(item_name, value);
            }
        }
        Ok(sol)
    }

    fn optimistic_solve(
        &self,
        optimistic_solver: &Z3Solver<'ctx>,
        e: &PathConstraintExpr,
    ) -> Result<Option<AnnotatedSolution>, Error> {
        optimistic_solver.reset();
        optimistic_solver.assert(&e.expr);
        let result = optimistic_solver.check();
        if result != SatResult::Sat {
            return Ok(None);
        }
        let sol_type = SolutionType::Optimistic;
        if let Some(model) = optimistic_solver.get_model() {
            let sol = self.model_to_solution(&model)?;
            Ok(Some(AnnotatedSolution { sol_type, sol }))
        } else {
            Ok(None)
        }
    }

    fn solve(
        &self,
        solver: &Z3Solver<'ctx>,
        optimistic_solver: &Z3Solver<'ctx>,
        e: &PathConstraintExpr,
    ) -> Result<Option<AnnotatedSolution>, Error> {
        solver.push();
        solver.assert(&e.expr);
        if solver.check() != SatResult::Sat {
            solver.pop(1);
            return self.optimistic_solve(optimistic_solver, e);
        }
        let sol_type = SolutionType::Normal;
        let asol = if let Some(model) = solver.get_model() {
            let sol = self.model_to_solution(&model)?;
            Some(AnnotatedSolution { sol_type, sol })
        } else {
            None
        };

        solver.pop(1);
        Ok(asol)
    }

    fn optimize_data_length(
        &mut self,
        optimizer: &Optimize<'ctx>,
        e: &PathConstraintExpr,
        data_length: &Dynamic<'ctx>,
    ) -> Result<Option<AnnotatedSolution>, Error> {
        optimizer.push();
        optimizer.maximize(data_length);
        let ctx = data_length.get_ctx();
        let data_length_bitwidth = data_length.as_bv().unwrap().get_size();
        let positive_assumption =
            data_length
                .as_bv()
                .unwrap()
                .bvsgt(&BV::from_u64(ctx, 0, data_length_bitwidth));
        let assumptions = vec![e.expr.clone(), positive_assumption];
        if optimizer.check(&assumptions) != SatResult::Sat {
            optimizer.pop();
            return Ok(None);
        }
        let asol = if let Some(model) = optimizer.get_model() {
            let sol_type = SolutionType::Normal;
            let mut sol: HashSet<(VarId, Value)> = HashSet::new();
            let data_length = model
                .eval(data_length, false)
                .ok_or_else(|| Error::other("Failed to evaluate data_length"))?
                .as_bv()
                .unwrap()
                .as_u64()
                .unwrap();
            if data_length == u64::MAX {
                optimizer.pop();
                return Ok(None);
            }
            if data_length + 1 > self.max_data_length_created {
                self.max_data_length_created = data_length + 1;
                sol.insert(("data_length".to_string(), data_length + 1));
                Some(AnnotatedSolution {
                    sol_type,
                    sol: Solution { inner: sol },
                })
            } else {
                None
            }
        } else {
            None
        };
        optimizer.pop();
        Ok(asol)
    }

    pub fn constrain_all<PCM>(
        &mut self,
        pcs: &[PathConstraint<'ctx, PCM>],
    ) -> Result<Option<AnnotatedSolution>, Error> {
        let solver = self.new_z3_solver();
        for pc in pcs {
            solver.assert(&pc.get_taken_expr().expr);
        }
        if solver.check() != SatResult::Sat {
            return Ok(None);
        }
        let sol_type = SolutionType::Normal;
        let asol = if let Some(model) = solver.get_model() {
            let sol = self.model_to_solution(&model)?;
            Some(AnnotatedSolution { sol_type, sol })
        } else {
            None
        };
        Ok(asol)
    }

    pub fn flip_all<
        PCM,
        F1: Fn(&[PathConstraint<'ctx, PCM>]) -> Result<bool, Error>,
        F2: FnMut(&[PathConstraint<'ctx, PCM>], &AnnotatedSolution) -> Result<(), Error>,
        F3: FnMut(&[PathConstraint<'ctx, PCM>]) -> Result<(), Error>,
    >(
        &mut self,
        pcs: &[PathConstraint<'ctx, PCM>],
        is_interesting: F1,
        mut add_solution: F2,
        mut unsat_callback: F3,
    ) -> Result<Vec<Option<AnnotatedSolution>>, Error> {
        let mut sols = Vec::new();

        let constraints: Constraints = pcs.iter().map(|pc| pc.get_taken_expr()).collect();
        let (cluster_cnt, cluster_num, cluster_zero_only_contains_data_length) =
            self.cluster_constraints(&constraints);
        // TODO: bitwidth may change
        let data_length_expr: Dynamic<'ctx> = BV::new_const(self.ctx, "data_length", 64).into();

        // Create Solvers to reuse
        // If cluster 0 contains terms other than data_length, it is treated with a regular solver
        // instead of the optimzier. Thus, we need to create cluster_cnt length solvers. Most of
        // the time, solvers[0] will not be used.
        let solvers = vec![self.new_z3_solver(); cluster_cnt];
        let optimistic_solver = self.new_z3_solver();
        let optimizer = self.new_z3_optimize();
        for idx in 0..pcs.len() {
            let solver_num = cluster_num[idx];
            if solver_num == Self::DATA_LENGTH_CLUSTER_ID && cluster_zero_only_contains_data_length
            {
                let sol =
                    self.optimize_data_length(&optimizer, &constraints[idx], &data_length_expr)?;
                if let Some(valid_sol) = &sol {
                    add_solution(&pcs[0..idx + 1], valid_sol)?;
                } else {
                    unsat_callback(&pcs[0..idx + 1])?;
                }
                sols.push(sol);
            } else {
                let solver = &solvers[solver_num];
                if !is_interesting(&pcs[0..idx + 1])? {
                    solver.assert(&constraints[idx].expr);
                    sols.push(None);
                    continue;
                }

                let target = pcs[idx].flip_expr();
                let sol = self.solve(solver, &optimistic_solver, &target)?;

                if let Some(valid_sol) = &sol {
                    add_solution(&pcs[0..idx + 1], valid_sol)?;
                } else {
                    unsat_callback(&pcs[0..idx + 1])?;
                }
                solver.assert(&constraints[idx].expr);
                sols.push(sol);
            }
        }
        Ok(sols)
    }
}

#[cfg(test)]
mod test {
    use super::Solver;
    use z3::{
        ast::{Ast, BV},
        Symbol,
    };

    #[test]
    fn test_solver_stack_overflow() {
        let ctx = Solver::new_ctx();
        let mut sum = BV::new_const(&ctx, Symbol::String("x0".to_string()), 32);
        let rec_cnt = 10000;
        for i in 0..rec_cnt {
            let new_expr = BV::new_const(&ctx, Symbol::String(format!("x{}", i + 1)), 32);
            sum = sum.bvadd(&new_expr);
        }
        let cond = sum._eq(&BV::from_i64(&ctx, 0, 32));
        let idents = Solver::gather_identifiers(cond.into(), &mut Default::default());
        assert_eq!(idents.len(), rec_cnt + 1);
    }
}
