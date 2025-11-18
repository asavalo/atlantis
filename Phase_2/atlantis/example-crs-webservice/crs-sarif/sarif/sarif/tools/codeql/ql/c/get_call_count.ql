import cpp
import safe_function
import semmle.code.cpp.pointsto.CallGraph

select
    count(SafeFunction caller, SafeFunction callee |
        not isSystemFunction(caller) and
        not isSystemFunction(callee) and
        allCalls(caller, callee)
    )