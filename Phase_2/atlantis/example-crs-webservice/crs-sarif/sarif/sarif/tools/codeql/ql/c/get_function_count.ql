import cpp
import safe_function
import semmle.code.cpp.pointsto.CallGraph

select
    count(SafeFunction f |
        not isSystemFunction(f)
    )