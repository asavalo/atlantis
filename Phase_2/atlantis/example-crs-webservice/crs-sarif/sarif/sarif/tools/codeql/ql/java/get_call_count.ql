import java
import safe_callable

select
  count(SafeCallable caller, SafeCallable callee |
        caller.polyCalls(callee)
  )
