import cpp
import semmle.code.cpp.commons.Exclusions
import external.ExternalArtifact

external predicate sink_candidates(string function_name);

predicate isSystemFunction(Function f) {
  f.getFile().getAbsolutePath().regexpMatch("^/(usr|lib|lib32|lib64|opt).*")
}

predicate isOssFuzzFunction(Function f) {
  f.getFile().getAbsolutePath().regexpMatch("^/src/(aflplusplus|fuzzer-test-suite|fuzztest|honggfuzz|libfuzzer|libprotobuf-mutator|LPM).*")
}

predicate isTestFunction(Function f) {
  f.getFile().getAbsolutePath().matches("%/test/%") or
  f.getFile().getAbsolutePath().matches("%/tests/%") or
  f.getFile().getBaseName().matches("test_%") or
  f.getFile().getBaseName().matches("%_test.%") or
  f.getFile().getBaseName().matches("%_tests.%")
}

from Function sink_candidate, Function sink_caller, Call call
where
  sink_candidates(sink_candidate.getName())
  and not isSystemFunction(sink_caller)
  // and not isSystemFunction(sink_candidate)
  and not isOssFuzzFunction(sink_caller)
  and not isTestFunction(sink_caller)
  and call.getTarget() = sink_candidate 
  and call.getEnclosingFunction() = sink_caller
  select sink_caller.getName() as func_name, sink_caller.getFile().getBaseName() as func_file_name, call.getLocation().getStartLine() as line_start, call.getLocation().getStartColumn() as column_start, call.getLocation().getEndLine() as line_end, call.getLocation().getEndColumn() as column_end, call.getLocation() as location, call.getTarget().getName() as sink_func_name