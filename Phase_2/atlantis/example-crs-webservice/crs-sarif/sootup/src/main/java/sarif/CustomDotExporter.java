package sarif;

import sootup.callgraph.CallGraph;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.views.View;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.stream.Collectors;

public class CustomDotExporter {
    private final CallGraph callGraph;
    private final View view;

    public CustomDotExporter(CallGraph callGraph, View view) {
        this.callGraph = callGraph;
        this.view = view;
    }

    public String exportAsDot() {
        StringBuilder dotFormatBuilder = new StringBuilder();
        dotFormatBuilder.append("digraph {\n");

        // Sort method signatures for consistent output
        callGraph.getMethodSignatures().stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(methodSig -> {
                view.getMethod(methodSig).ifPresent(method -> {
                    String nodeLabel = formatNodeLabel(method);
                    dotFormatBuilder.append("\"").append(nodeLabel).append("\";\n");
                });
            });

        // Add edges
        callGraph.getMethodSignatures().stream()
            .sorted(Comparator.comparing(MethodSignature::toString))
            .forEach(sourceMethod -> {
                callGraph.callTargetsFrom(sourceMethod).stream()
                    .sorted(Comparator.comparing(MethodSignature::toString))
                    .forEach(targetMethod -> {
                        view.getMethod(sourceMethod).ifPresent(source -> {
                            view.getMethod(targetMethod).ifPresent(target -> {
                                String sourceLabel = formatNodeLabel(source);
                                String targetLabel = formatNodeLabel(target);
                                dotFormatBuilder.append("\"").append(sourceLabel).append("\" -> \"")
                                    .append(targetLabel).append("\";\n");
                            });
                        });
                    });
            });

        dotFormatBuilder.append("}");
        return dotFormatBuilder.toString();
    }

    private String formatNodeLabel(SootMethod method) {
        String className = method.getSignature().getDeclClassType().toString();
        
        // Get the source path from the class source
        String sourcePath = view.getClass(method.getSignature().getDeclClassType()).get().getClassSource().getSourcePath().toString();
        
        // If the path is in a jar file, extract the source path
        if (sourcePath.contains(".jar!")) {
            sourcePath = sourcePath.substring(sourcePath.indexOf("!") + 1);
        }
        
        // Convert class file path to Java source file path
        String javaSourcePath = sourcePath.replace(".class", ".java");
        
        // If the path is relative, make it absolute using the project path
        // if (!javaSourcePath.startsWith("/")) {
        //     javaSourcePath = projectPath + "/" + javaSourcePath;
        // }
        
        String label = String.format(
            "func_name='%s' file_name='%s' class_name='%s' full_sig='%s' func_sig='%s' method_desc='%s' start_line=%d end_line=%d",
            method.getName(),
            javaSourcePath,
            className,
            method.getSignature(),
            method.getSignature().getSubSignature(),
            method.getSignature().getParameterTypes().stream()
                .map(type -> type.toString())
                .collect(Collectors.joining("", "(", ")")),
            method.getPosition().getFirstLine(),
            method.getPosition().getLastLine()
        );
        return label;
    }
} 