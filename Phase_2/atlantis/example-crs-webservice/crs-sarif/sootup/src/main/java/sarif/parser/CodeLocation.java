package sarif.parser;

import sootup.core.graph.BasicBlock;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.LinePosition;
import sootup.core.model.Position;
import sootup.core.signatures.MethodSignature;

import java.util.Objects;
import java.util.Optional;

public class CodeLocation {
    // Contains a MethodSignature and an optional LinePosition
    public final MethodSignature method;
    public final Optional<LinePosition> linePosition;

    public CodeLocation(MethodSignature method, Optional<LinePosition> linePosition) {
        this.method = method;
        this.linePosition = linePosition;
    }

    public String toString() {
        return method.toString() + (linePosition.isPresent() ? ":" + linePosition.get().toString() : "");
    }

    public boolean matches(MethodSignature method, BasicBlock bb) {
        // If the method signatures don't match, we consider it a mismatch
        if (!this.method.equals(method)) {
            return false;
        }

        // If no line position is specified, the entire method is considered a match
        if (!linePosition.isPresent()) {
            return true;
        }

        // If any of the bb's statements' position location matches, we consider it a match
        for (Object stmt : bb.getStmts()) {
            if (stmt instanceof Stmt && positionMatches((Stmt) stmt)) {
                return true;
            }
        }
        return false;
    }

    private boolean positionMatches(Stmt stmt) {
        // We assume that the line position is always present
        Position position = stmt.getPositionInfo().getStmtPosition();
        int targetLine = linePosition.get().getFirstLine();
        return position.getFirstLine() <= targetLine && targetLine < position.getLastLine();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CodeLocation that = (CodeLocation) o;
        return Objects.equals(method, that.method) &&
               Objects.equals(linePosition, that.linePosition);
    }

    @Override
    public int hashCode() {
        return Objects.hash(method, linePosition);
    }
}
