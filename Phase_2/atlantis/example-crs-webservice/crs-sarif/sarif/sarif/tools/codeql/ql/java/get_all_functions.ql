import java
import safe_callable

from SafeCallable c
// where not isSystemCallable(c)
select
  c as func,
  c.getSafeAbsolutePath() as file_abs,
  c.getSafeStartLineString() as start_line,
  c.getSafeEndLineString() as end_line,
  c.getSafeDeclaringTypeSimpleName() as class_name,
  c.getSafeFullSignature() as sig,
  c.getSafeMethodDesc() as method_desc