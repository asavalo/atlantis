use super::common::path_constraint::PathConstraint;
use super::symcc_symqemu::SymCCFailedHookCall;
use super::{SingleStepResult, SolutionToInput, SrcLocation, SymState, TraceManager};
use crate::common::{Error, InputID};
use crate::concolic::{
    ConcolicExecutor, IsSymCCAux, SingleStepSession, SymCCHook,
    SymCCInstallFunctionCallHook,
};
use chrono::Local;
use rand::Rng;
use serde::{ser::SerializeStruct, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::process::Stdio;
use z3::ast::{Ast, Dynamic};

#[derive(Debug, Clone)]
pub struct InconsistentValue<'ctx> {
    pub name: String,
    pub src_location: Option<SrcLocation>,
    pub coerced_value_a: Dynamic<'ctx>,
    pub coerced_value_b: Dynamic<'ctx>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Inconsistency<'ctx> {
    pub hex_input_a: String,
    pub hex_input_b: String,
    pub src_location: Option<SrcLocation>,
    pub inconsistent_values: Vec<InconsistentValue<'ctx>>,
    pub failed_hook_calls: Vec<SymCCFailedHookCall>,
}

#[allow(unused)]
#[derive(Debug, Clone)]
enum CompareTraceResult<'ctx> {
    DifferentSiteId {
        site_id_a: u64,
        site_id_b: u64,
    },
    SameSiteId {
        site_id: u64,
        taken_a: bool,
        taken_b: bool,
        inconsistency: Inconsistency<'ctx>,
    },
}

impl Serialize for InconsistentValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("InconsistentCoercedValue", 5)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("src_location", &self.src_location)?;
        state.serialize_field("coerced_value_a", &self.coerced_value_a.to_string())?;
        state.serialize_field("coerced_value_b", &self.coerced_value_b.to_string())?;
        state.end()
    }
}

#[derive(Debug, Clone)]
pub enum Action {
    None,
    ReplaceHook { hook_contents: String },
}

#[derive(Debug, Clone)]
pub enum Application {
    None,
    ReplaceHook {
        original_hook: Option<SymCCHook>,
    },
}

fn compare_traces<'ctx, PCM: Clone + Into<Option<SrcLocation>>, AUX: IsSymCCAux<'ctx>>(
    input_a: &[u8],
    input_b: &[u8],
    pc_a: &PathConstraint<'ctx, PCM>,
    aux_a: &AUX,
    pc_b: &PathConstraint<'ctx, PCM>,
    aux_b: &AUX,
) -> Result<CompareTraceResult<'ctx>, Error> {
    if pc_a.site_id != pc_b.site_id {
        return Ok(CompareTraceResult::DifferentSiteId {
            site_id_a: pc_a.site_id,
            site_id_b: pc_b.site_id,
        });
    }

    // check if their keys are the same
    let coerced_names_a: HashSet<String> = pc_a
        .expr
        .coerced_values
        .iter()
        .map(|x| x.decl().name())
        .collect();
    let coerced_names_b: HashSet<String> = pc_b
        .expr
        .coerced_values
        .iter()
        .map(|x| x.decl().name())
        .collect();
    // TODO: is it possible that the two traces have different keys?
    if coerced_names_a != coerced_names_b {
        return Err(Error::self_correction_logic_error(
            "Two traces have different set of coerced values",
        ));
    }
    let src_location: Option<SrcLocation> = pc_a.metadata.clone().into();
    if let Some(src_location) = src_location {
        if src_location.line == 168 {
            for name in coerced_names_a.iter() {
                let coerced_value_a = aux_a.coerced_values().get(name).unwrap().clone();
                let coerced_value_b = aux_b.coerced_values().get(name).unwrap().clone();

                // Failed function hook calls may differ between A and B if the hook
                // behaves differently depending on the arguments.
                // Therefore, it is necessary to obtain the union of failed function hooks from both cases.
                println!(
                    "{} | a: {} / b: {}",
                    name, coerced_value_a.concrete_value, coerced_value_b.concrete_value
                );
            }
        }
    }
    let mut inconsistent_values = Vec::new();
    for name in coerced_names_a.into_iter() {
        let coerced_value_a = aux_a.coerced_values().get(&name).unwrap().clone();
        let coerced_value_b = aux_b.coerced_values().get(&name).unwrap().clone();

        // Failed function hook calls may differ between A and B if the hook
        // behaves differently depending on the arguments.
        // Therefore, it is necessary to obtain the union of failed function hooks from both cases.

        if coerced_value_a.concrete_value != coerced_value_b.concrete_value {
            inconsistent_values.push(InconsistentValue {
                name,
                // TODO: is this safe to assme equivalence
                src_location: coerced_value_a.src_location.clone(),
                coerced_value_a: coerced_value_a.concrete_value.clone(),
                coerced_value_b: coerced_value_b.concrete_value.clone(),
            });
        }
    }
    Ok(CompareTraceResult::SameSiteId {
        site_id: pc_a.site_id,
        taken_a: pc_a.taken,
        taken_b: pc_b.taken,
        inconsistency: Inconsistency {
            hex_input_a: hex::encode(input_a),
            hex_input_b: hex::encode(input_b),
            src_location: pc_a.metadata.clone().into(),
            inconsistent_values,
            failed_hook_calls: aux_a.failed_function_hook_calls().clone(),
        },
    })
}
/// Trait for symbolic execution states that can perform self-correction
#[allow(unused)]
pub trait SelfCorrectingSymState<'ctxp, 'ctxs> {
    fn find_inconsistency(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<Vec<Inconsistency<'ctxp>>, Error>;

    fn obtain_candidate(&mut self, input_id: InputID, input: &[u8]) -> Result<Vec<u8>, Error>;

    fn process_with_self_correction(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<(), Error>;

    fn apply_action(&mut self, action: Action) -> Result<Application, Error>;
    fn revert_action(&mut self, application: Application) -> Result<(), Error>;
    fn resolve(&mut self, inconsistency: Inconsistency<'ctxp>) -> Result<Action, Error>;
}

fn random_candidate(input: &[u8]) -> Result<Vec<u8>, Error> {
    // this loop should terminate someday
    let len = input.len();
    let mut rng = rand::thread_rng();
    let mut candidate = vec![0u8; len];
    loop {
        rng.fill(&mut candidate[..]);
        if candidate != input {
            break;
        }
    }
    Ok(candidate)
}

impl<'ctxp, 'ctxs, 'a, S> SelfCorrectingSymState<'ctxp, 'ctxs> for S
where
    S: SymState<'ctxp, 'ctxs>,
    S::AUX: IsSymCCAux<'ctxp>,
    S::PCM: Into<Option<SrcLocation>>,
    S::ConcolicExecutor: SymCCInstallFunctionCallHook,
{
    fn apply_action(&mut self, action: Action) -> Result<Application, Error> {
        match action {
            Action::None => Ok(Application::None),
            Action::ReplaceHook { hook_contents } => {
                let original_hook = self.executor().install_function_call_hook(hook_contents)?;
                Ok(Application::ReplaceHook { original_hook })
            }
        }
    }

    fn revert_action(&mut self, application: Application) -> Result<(), Error> {
        match application {
            Application::None => Ok(()),
            Application::ReplaceHook { original_hook } => {
                if let Some(original_hook) = original_hook {
                    self.executor().install_function_call_hook(original_hook)?;
                }
                Ok(())
            }
        }
    }

    fn obtain_candidate(&mut self, input_id: InputID, input: &[u8]) -> Result<Vec<u8>, Error> {
        let trace = self.executor().execute(input_id, input)?;
        let (pcs, _aux) = self.trace_manager().load_trace(input_id, trace, None)?;
        // try to create an input that satisfies everything in pcs but rest is random
        let sol = self.solver().constrain_all(&pcs)?;

        match sol {
            Some(sol) => {
                let mut candidates = self.solution_to_input().solution_to_input(input, &sol)?;
                if let Some(candidate) = candidates.pop() {
                    Ok(candidate)
                } else {
                    random_candidate(input)
                }
            }
            None => random_candidate(input),
        }
    }

    fn find_inconsistency(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<Vec<Inconsistency<'ctxp>>, Error> {
        let candidate = self.obtain_candidate(input_id, input)?;
        let mut inconsistencies = vec![];
        let mut session_a = self.executor().execute_single_step(input_id, input)?;
        let input_id_b = input_id | (1 << (InputID::BITS - 1));
        let input_id_c = input_id | (1 << (InputID::BITS - 2));
        let mut session_b = self
            .executor()
            .execute_single_step(input_id_b, &candidate)?;
        let mut session_c = self.executor().execute_single_step(input_id_c, input)?;
        let mut previous_aux_a = None;
        let mut previous_aux_b = None;
        let mut previous_aux_c = None;

        loop {
            let ss_a = self.executor().single_step(&mut session_a)?;
            let ss_b = self.executor().single_step(&mut session_b)?;
            let ss_c = self.executor().single_step(&mut session_c)?;

            // Step 1: Assert that pcs_a and pcs_b are identical.
            // If they differ, it indicates that two instances with the same input
            // are exhibiting divergent behavior. This should never happen under
            // normal conditions, except in rare cases (e.g., out-of-memory errors,
            // randomness, etc.).
            // In such cases, tracing should halt and a SelfCorrectionLogicError should be raised.
            let (pcs_a, aux_a, _pcs_c, aux_c) = match (ss_a, ss_c) {
                (SingleStepResult::Finished(_tr_a), SingleStepResult::Finished(_tr_c)) => {
                    session_a.kill()?;
                    session_b.kill()?;
                    session_c.kill()?;
                    break;
                }
                (SingleStepResult::Continued(tr_a), SingleStepResult::Continued(tr_c)) => {
                    // Step 2: Compare the coerced values of the two path constraints.
                    // The site ID and 'taken' flag should match. If the coerced values differ,
                    // skip this branch. This scenario can occur when the coerced value is a
                    // pointer (e.g., ptr != null), which may evaluate differently across runs.
                    let (pcs_a, aux_a) =
                        self.trace_manager()
                            .load_trace(input_id, tr_a, previous_aux_a.as_ref())?;
                    let (pcs_c, aux_c) =
                        self.trace_manager()
                            .load_trace(input_id, tr_c, previous_aux_c.as_ref())?;

                    if pcs_a.len() == 0 || pcs_c.len() == 0 || pcs_a.len() != pcs_c.len() {
                        return Err(Error::invalid_trace_generation());
                    }

                    match compare_traces(
                        input,
                        &candidate,
                        &pcs_a.last().unwrap(),
                        &aux_a,
                        &pcs_c.last().unwrap(),
                        &aux_c,
                    )? {
                        CompareTraceResult::DifferentSiteId { .. } => {
                            session_a.kill()?;
                            session_b.kill()?;
                            session_c.kill()?;
                            return Err(Error::self_correction_logic_error(
                                "Two processes with the same input have diverging site ID sequences",
                            ));
                        }
                        CompareTraceResult::SameSiteId {
                            inconsistency,
                            taken_a,
                            taken_b,
                            ..
                        } => {
                            if taken_a != taken_b {
                                session_a.kill()?;
                                session_b.kill()?;
                                session_c.kill()?;
                                return Err(Error::self_correction_logic_error(
                                    "Two processes with the same input have different branching behaviors",
                                ));
                            }

                            if inconsistency.inconsistent_values.len() > 0 {
                                continue;
                            }
                        }
                    }
                    (pcs_a, aux_a, pcs_c, aux_c)
                }
                // the two cases below may happen due to OOM (one process OOMs and the other does not)
                (SingleStepResult::Finished(_), SingleStepResult::Continued(_))
                | (SingleStepResult::Continued(_), SingleStepResult::Finished(_)) => {
                    session_a.kill()?;
                    session_b.kill()?;
                    session_c.kill()?;
                    return Err(Error::self_correction_logic_error(
                        "Two processes with the same input have different behaviors",
                    ));
                }
            };

            // Upon reaching this point, ss_a and ss_c are in the Continued state.
            let (pcs_b, aux_b) = match ss_b {
                // Implies a segfault or similar error
                SingleStepResult::Finished(_) => {
                    session_a.kill()?;
                    session_b.kill()?;
                    session_c.kill()?;
                    break;
                }
                SingleStepResult::Continued(tr_b) => {
                    let (pcs_b, aux_b) = self.trace_manager().load_trace(
                        input_id_b,
                        tr_b,
                        previous_aux_b.as_ref(),
                    )?;
                    if pcs_b.len() == 0 {
                        session_a.kill()?;
                        session_b.kill()?;
                        session_c.kill()?;
                        break;
                    }
                    if pcs_b.len() != pcs_a.len() {
                        session_a.kill()?;
                        session_b.kill()?;
                        session_c.kill()?;
                        return Err(Error::invalid_trace_generation());
                    }
                    (pcs_b, aux_b)
                }
            };

            // Step 3: Check for inconsistencies in the coerced values of pcs_a and pcs_b.
            // If they differ, flag this as an inconsistency.
            // If the site IDs differ, this indicates a bug in the instrumentation—
            // likely due to uninstrumented conditional statements—resulting in
            // divergent control flow not captured in one of the executions.
            //
            // TODO: do stride detection within a function!!!
            let result = compare_traces(
                input,
                &candidate,
                &pcs_a.last().unwrap(),
                &aux_a,
                &pcs_b.last().unwrap(),
                &aux_b,
            )?;
            previous_aux_a = Some(aux_a);
            previous_aux_b = Some(aux_b);
            previous_aux_c = Some(aux_c);
            match result {
                // A different site ID may occur if there are indirect calls, as indirect calls
                // are not captured in the trace.
                //
                // The same site ID with a different 'taken' value is also possible. This likely
                // indicates the first path constraint that depends on the contents of the input.
                // This is expected behavior—not an instrumentation bug—and should be observed
                // rather than flagged.
                CompareTraceResult::DifferentSiteId { .. } => {
                    session_a.kill()?;
                    session_b.kill()?;
                    session_c.kill()?;
                    break;
                }
                CompareTraceResult::SameSiteId {
                    inconsistency,
                    taken_a,
                    taken_b,
                    ..
                } => {
                    if inconsistency.inconsistent_values.len() > 0 {
                        inconsistencies.push(inconsistency);
                    }
                    if taken_a != taken_b {
                        session_a.kill()?;
                        session_b.kill()?;
                        session_c.kill()?;
                        break;
                    }
                }
            }
        }
        Ok(inconsistencies)
    }
    fn process_with_self_correction(
        &mut self,
        input_id: InputID,
        input: &[u8],
    ) -> Result<(), Error> {
        let inconsistencies = self.find_inconsistency(input_id, input)?;
        for inconsistency in inconsistencies {
            let action = self.resolve(inconsistency)?;
            self.apply_action(action)?;
        }
        Ok(())
    }

    fn resolve(&mut self, inconsistency: Inconsistency<'ctxp>) -> Result<Action, Error> {
        let now = Local::now();
        let resolve_id = format!("{}", now.format("%Y-%m-%d_%H-%M-%S"));
        let workdir = self.workdir().join("resolve").join(&resolve_id);
        std::fs::create_dir_all(&workdir)?;

        let python = self.python();
        let activate = python.parent().unwrap().join("activate");
        if !activate.exists() {
            return Err(Error::other(format!(
                "Activate script not found at {}",
                activate.display()
            )));
        }
        let previous_code = workdir.join("previous.py");
        if let Some(previous_code_contents) = self.executor().get_function_call_hook()? {
            std::fs::write(&previous_code, previous_code_contents)?;
        } else {
            std::fs::write(&previous_code, "")?;
        }
        let resolve_script = self.resolve_script();
        let output_path = workdir.join("new.py");
        let inconsistency_file = workdir.join("inconsistency.json");
        serde_json::to_writer(std::fs::File::create(&inconsistency_file)?, &inconsistency)?;

        if false {
            let cmd = format!(
                "source {} && {} --output {} --workdir {} --inconsistency {} --previous-code {}",
                activate.display(),
                resolve_script.display(),
                output_path.display(),
                workdir.display(),
                inconsistency_file.display(),
                previous_code.display()
            );
            let mut child = std::process::Command::new("bash")
                .arg("-c")
                .arg(cmd)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            let status = child.wait()?;

            let mut stdout = String::new();
            let mut stderr = String::new();
            child.stdout.take().unwrap().read_to_string(&mut stdout)?;
            child.stderr.take().unwrap().read_to_string(&mut stderr)?;
            let stdout_file = workdir.join("stdout.txt");
            let stderr_file = workdir.join("stderr.txt");
            std::fs::write(&stdout_file, stdout)?;
            std::fs::write(&stderr_file, stderr)?;

            if !status.success() {
                return Err(Error::other(format!(
                    "Resolve script failed with status {}",
                    status
                )));
            } else {
                let mut output = std::fs::File::open(&output_path)?;
                let mut hook_contents = String::new();
                output.read_to_string(&mut hook_contents)?;
                Ok(Action::ReplaceHook { hook_contents })
            }
        } else {
            std::thread::sleep(std::time::Duration::from_secs(1));
            Ok(Action::None)
        }
    }
}
