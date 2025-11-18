import cpp
import safe_function

string getClassIfLLVMFuzzer(SafeFunction f) {
    if f.getName() = "LLVMFuzzerTestOneInput" 
    then result = f.getALinkTarget().getBinary().getBaseName()
    else result = "UNKNOWN"
}

from SafeFunction f
where not isSystemFunction(f)
select 
  f as func,
  f.getSafeAbsolutePath() as file_abs,
  f.getSafeSignature() as sig,
  f.getSafeStartLineString() as start_line,
  f.getSafeEndLineString() as end_line,
  getClassIfLLVMFuzzer(f) as class_name