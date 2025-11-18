# Dynamic Disabling of Short-Circuiting in SymCC

This document outlines the design and implementation of **dynamically disabling short-circuiting** in SymCC.

## Background

SymCC uses a short-circuiting mechanism to optimize symbolic computation. Specifically, symbolic helper functions (e.g., `_sym_build_add`, `_sym_build_sub`) are only invoked if at least one of the arguments is symbolic. If all arguments are concrete (represented as `null` symbolic expressions), the helper call is skipped entirely.

If only some arguments are symbolic, the concrete ones are wrapped using primitives like `_sym_build_integer` before invoking the helper function.

## Dynamic Disabling

We introduce a mechanism to **dynamically disable short-circuiting** using an environment variable. When set, this variable disables short-circuiting logic at runtime—**without requiring recompilation**. In this mode, all symbolic helper functions will be invoked regardless of the symbolic status of their arguments.

Currently, this feature acts as a **global toggle**. In future work, we plan to assign **unique IDs** to symbolic computation sites to enable fine-grained disabling of short-circuiting on a per-site basis.

## Caveat in Existing Logic

SymCC contains an optimization that assumes:

> If `numUnknownConcreteness == 1` and the short-circuiting slow path is taken, then the unknown argument must be symbolic.

This assumption is no longer valid when dynamic disabling is enabled. Since the slow path may now be entered even when **all arguments are concrete**, this check can lead to incorrect behavior.

### Relevant code:

```cpp
// We only need a run-time check for concreteness if the argument isn't
// known to be concrete at compile time already. However, there is one
// exception: if the computation only has a single argument of unknown
// concreteness, then we know that it must be symbolic since we ended up
// in the slow path. Therefore, we can skip expression generation in
// that case.
bool needRuntimeCheck = originalArgExpression != nullExpression;
if (needRuntimeCheck && (numUnknownConcreteness == 1))
  continue;
```

## Action Required

This optimization must be removed or revised. The assumption that a single unknown argument implies symbolic status is no longer sound. Continuing under this assumption may result in incorrect symbolic state construction and missed instrumentation when dynamic short-circuiting is disabled.

