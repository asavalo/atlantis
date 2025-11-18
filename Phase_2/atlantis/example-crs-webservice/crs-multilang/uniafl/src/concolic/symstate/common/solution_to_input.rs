use super::solver::AnnotatedSolution;
use crate::common::errors::Error;

/// A trait that takes in an input and the solution (~=model) to construct a vector of new inputs
/// e.g. solution_to_input("ABCD", [k#!0 => 0x44]) = ["DBCD"]
/// The return value is a Vec<Vec<u8>> and not a Vec<u8> because certain models may result in
/// multiple mutations for a single model. This may happen if we declare symbols that overlap (such
/// as a range of the input bytes and a single byte within that range.)
/// e.g. solution_to_input("ABCD", [k#!0 => 0x44, k#!0:2 => 0x434343]) = ["DBCD", "CCCD"]
pub trait SolutionToInput {
    fn solution_to_input(
        &self,
        input: &[u8],
        solution: &AnnotatedSolution,
    ) -> Result<Vec<Vec<u8>>, Error>;
}
