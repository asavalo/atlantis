import cpp
import semmle.code.cpp.Print

class SafeFunction extends Function {
  SafeFunction() { this instanceof Function }

  string getSafeBaseName() {
    if exists(this.getFile()) then result = this.getFile().getBaseName() else result = "UNKNOWN"
  }

  string getSafeAbsolutePath() {
    if exists(this.getFile()) then result = this.getFile().getAbsolutePath() else result = "UNKNOWN"
  }

  string getSafeSignature() {
    if exists(getIdentityString(this)) then result = getIdentityString(this) else result = "UNKNOWN"
  }

  string getSafeStartLineString() {
    if exists(this.getBlock().getLocation().getStartLine())
    then result = this.getBlock().getLocation().getStartLine().toString()
    else result = "UNKNOWN"
  }

  string getSafeEndLineString() {
    if exists(this.getBlock().getLocation().getEndLine())
    then result = this.getBlock().getLocation().getEndLine().toString()
    else result = "UNKNOWN"
  }

  boolean hasDirectCall(Function callee) {
    if this.calls(callee)
    then result = true
    else result = false
  }
}

predicate isSystemFunction(Function f) {
  // f.getFile().getAbsolutePath().indexOf("/src") != 0
  f instanceof BuiltInFunction or
  f.getFile().getAbsolutePath().regexpMatch("^/(usr|lib|lib32|lib64|opt).*")
}
