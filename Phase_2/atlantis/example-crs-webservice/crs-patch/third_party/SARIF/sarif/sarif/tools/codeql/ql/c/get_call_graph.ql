import cpp
import safe_function
import semmle.code.cpp.pointsto.CallGraph

from SafeFunction caller, SafeFunction callee
where
    not isSystemFunction(caller) and
    not isSystemFunction(callee) and
    allCalls(caller, callee)
    
select
    caller as from_func,
    caller.getSafeBaseName() as from_file,
    caller.getSafeAbsolutePath() as from_file_abs,
    caller.getSafeSignature() as from_sig,
    caller.getSafeStartLineString() as from_start_line,
    caller.getSafeEndLineString() as from_end_line,
    callee as to_func,
    callee.getSafeBaseName() as to_file,
    callee.getSafeAbsolutePath() as to_file_abs,
    callee.getSafeSignature() as to_sig,
    callee.getSafeStartLineString() as to_start_line,
    callee.getSafeEndLineString() as to_end_line,
    caller.hasDirectCall(callee) as is_direct
