import java

class SafeCallable extends Callable {
    SafeCallable() { this instanceof Callable }
  
    string getSafeBaseName() {
      if exists(this.getFile())
      then result = this.getFile().getBaseName()
      else result = "UNKNOWN"
    }
  
    string getSafeAbsolutePath() {
      if exists(this.getFile())
      then result = this.getFile().getAbsolutePath()
      else result = "UNKNOWN"
    }
  
    string getSafeStartLineString() {
      if exists(this.getBody().getLocation())
      then result = this.getBody().getLocation().getStartLine().toString()
      else result = "UNKNOWN"
    }
  
    string getSafeEndLineString() {
      if exists(this.getBody().getLocation())
      then result = this.getBody().getLocation().getEndLine().toString()
      else result = "UNKNOWN"
    }
  
    string getSafeDeclaringTypeName() {
      if exists(this.getDeclaringType().getQualifiedName())
      then result = this.getDeclaringType().getQualifiedName()
      else result = "UNKNOWN"
    }
  
    string getSafeSignature() {
      if exists(this.getSignature())
      then result = this.getSignature()
      else result = "UNKNOWN"
    }
  
    string getSafeMethodDesc() {
      if exists(this.getMethodDescriptor())
      then result = this.getMethodDescriptor()
      else result = "UNKNOWN"
    }

    boolean hasDirectCall(Callable callee) {
      if this.calls(callee)
      then result = true
      else result = false
    }
  }
  
  predicate isSystemCallable(Callable c) {
    exists(string qname |
      qname = c.getDeclaringType().getQualifiedName() and
      (qname.matches("java.%") or qname.matches("javax.%"))
    )
  }