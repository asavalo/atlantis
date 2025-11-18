import java
import safe_callable

from SafeCallable caller, SafeCallable callee
where
  caller.polyCalls(callee)
  // not isSystemCallable(caller) and
  // not isSystemCallable(callee)

select
  caller as from_func,
  caller.getSafeBaseName() as from_file,
  caller.getSafeAbsolutePath() as from_file_abs,
  caller.getSafeStartLineString() as from_start_line,
  caller.getSafeEndLineString() as from_end_line,
  caller.getSafeDeclaringTypeName() as from_class,
  caller.getSafeSignature() as from_sig,
  caller.getSafeMethodDesc() as from_method_desc,
  callee as to_func,
  callee.getSafeBaseName() as to_file,
  callee.getSafeAbsolutePath() as to_file_abs,
  callee.getSafeStartLineString() as to_start_line,
  callee.getSafeEndLineString() as to_end_line,
  callee.getSafeDeclaringTypeName() as to_class,
  callee.getSafeSignature() as to_sig,
  callee.getSafeMethodDesc() as to_method_desc,
  caller.hasDirectCall(callee) as is_direct