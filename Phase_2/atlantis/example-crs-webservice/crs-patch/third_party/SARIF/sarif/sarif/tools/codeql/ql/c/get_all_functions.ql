import cpp
import safe_function

from SafeFunction f
where not isSystemFunction(f)
select 
  f as func,
  f.getSafeBaseName() as file,
  f.getSafeAbsolutePath() as file_abs,
  f.getSafeSignature() as sig,
  f.getSafeStartLineString() as start_line,
  f.getSafeEndLineString() as end_line