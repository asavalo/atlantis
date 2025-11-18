import java
import external.ExternalArtifact

external predicate sink_candidates(string function_name);

predicate isSystemMethod(Method m) {
  m.getDeclaringType().getFile().getAbsolutePath().regexpMatch("^/(usr|lib|lib32|lib64|opt).*")
}

predicate isOssFuzzMethod(Method m) {
  m.getDeclaringType().getFile().getAbsolutePath().regexpMatch("^/src/(aflplusplus|fuzzer-test-suite|fuzztest|honggfuzz|libfuzzer|libprotobuf-mutator|LPM).*")
}

from Method sink_candidate, Method sink_caller, MethodCall call
where
  sink_candidates(sink_candidate.getName())
  and not isSystemMethod(sink_caller)
  and not isSystemMethod(sink_candidate)
  and not isOssFuzzMethod(sink_caller)
  and call.getCallee().getName() = sink_candidate.getName() and
  call.getEnclosingCallable() = sink_caller
  select sink_caller.getName() as func_name, sink_caller.getFile().getBaseName() as func_file_name, call.getLocation().getStartLine() as line_start, call.getLocation().getStartColumn() as column_start, call.getLocation().getEndLine() as line_end, call.getLocation().getEndColumn() as column_end, call.getLocation() as location