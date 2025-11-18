use libafl::inputs::{BytesInput, HasMutatorBytes};
use libafl::observers::concolic::serialization_format::MessageFileReader;
use libafl::observers::concolic::SymExprRef;
use libafl::stages::concolic::{
    construct_replacement_string, create_new_inputs, generate_mutations, ConcolicMutationResult,
    SatQuery, UnsatQuery,
};
use serde::{Deserialize, Serialize};
use std::io::Read;
use symcc_runtime::tracing::SymExpr;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SolveConstraintSummary {
    trace: Vec<(SymExprRef, SymExpr)>,
    unsat_queries: Vec<UnsatQuery>,
    sat_queries: Vec<SatQuery>,
    mutations: Vec<ConcolicMutationResult>,
}

pub fn solve_constraints<R: Read>(
    reader: &mut MessageFileReader<R>,
    input_bytes: &[u8],
) -> anyhow::Result<()> {
    let mut summary = SolveConstraintSummary::default();
    let mut constraints = vec![];
    while let Some(maybe_msg) = reader.next_message() {
        if let Ok((sym_expr_id, sym_expr)) = maybe_msg {
            constraints.push((sym_expr_id, sym_expr));
        } else {
            return Err(anyhow::anyhow!("Failed to read message"));
        }
    }

    summary.trace = constraints.clone();

    let mutations = generate_mutations(constraints.into_iter());

    summary.unsat_queries = mutations.unsat_queries.clone();
    summary.sat_queries = mutations.sat_queries.clone();
    summary.mutations = mutations.mutations.clone();

    if let Ok(report_file) = std::env::var("SYMCC_REPORT_FILE") {
        let mut file = std::fs::File::create(report_file)?;
        serde_json::to_writer(&mut file, &summary)?;
    } else {
        println!("Trace:");
        for (sym_expr_id, sym_expr) in summary.trace.iter() {
            println!("  {}: {:?}", sym_expr_id, sym_expr);
        }

        println!("=====================");
        println!("Attempted but failed mutations:");
        for (j, unsat_query) in summary.unsat_queries.iter().enumerate() {
            println!("Unsat {}:", j);
            for (i, condition) in unsat_query.assertions.iter().enumerate() {
                println!("  {}: {}", i, condition);
            }
        }

        println!("=====================");
        println!("Successful mutations:");
        for (j, sat_query) in summary.sat_queries.iter().enumerate() {
            println!("Sat {}:", j);
            for (i, condition) in sat_query.assertions.iter().enumerate() {
                println!("  {}: {}", i, condition);
            }
        }

        println!("=====================");
        println!("Generated mutations:");
        if summary.mutations.is_empty() {
            println!("No mutations generated");
        } else {
            for (i, mutation) in summary.mutations.iter().enumerate() {
                println!("Mutation {i}");
                for (offset, new_byte) in mutation.byte_replacements.iter() {
                    println!(
                        "  Replace #k!{} {} ---> {})",
                        offset, input_bytes[*offset], new_byte
                    );
                }
                for replacement in mutation.string_replacements.iter() {
                    let begin = replacement.begin;
                    let end = replacement.end;
                    let orig_bytes = &input_bytes[begin..end].to_vec();
                    let new_str = &replacement.value;
                    println!(
                        "  Replace #k![{}:{}] {:?} ---> {}",
                        begin, end, orig_bytes, new_str
                    );
                }
            }
        }
    }
    Ok(())
}
