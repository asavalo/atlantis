package sarif;

import sootup.callgraph.CallGraph;
import sootup.callgraph.CallGraphAlgorithm;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.java.core.views.JavaView;
import sootup.core.views.View;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CallGraphGenerator {
    private final String projectPath;
    private final String outputPath;
    private JavaView view;
    private CallGraph callGraph;

    public CallGraphGenerator(String projectPath, String outputPath) {
        this.projectPath = projectPath;
        this.outputPath = outputPath;
    }

    public void initialize() {
        // Create input locations for the project
        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        
        // Add the main project's compiled classes
        String mainClassesPath = projectPath + "/src/mock_java/target/classes";
        if (new File(mainClassesPath).exists()) {
            System.out.println("Adding main classes from: " + mainClassesPath);
            inputLocations.add(new JavaClassPathAnalysisInputLocation(mainClassesPath));
        }
        
        // Add the fuzz test classes
        String fuzzClassesPath = projectPath + "/src/fuzz";
        if (new File(fuzzClassesPath).exists()) {
            System.out.println("Adding fuzz classes from: " + fuzzClassesPath);
            inputLocations.add(new JavaClassPathAnalysisInputLocation(fuzzClassesPath));
        }
        
        // Add all JAR files from the jars directory
        String jarsPath = projectPath + "/jars";
        File jarsDir = new File(jarsPath);
        if (jarsDir.exists() && jarsDir.isDirectory()) {
            System.out.println("Scanning JAR files in: " + jarsPath);
            File[] jarFiles = jarsDir.listFiles((dir, name) -> name.endsWith(".jar"));
            if (jarFiles != null) {
                for (File jar : jarFiles) {
                    System.out.println("Adding JAR file: " + jar.getAbsolutePath());
                    inputLocations.add(new JavaClassPathAnalysisInputLocation(jar.getAbsolutePath()));
                }
            }
        }
        
        // Add runtime classes
        inputLocations.add(new DefaultRuntimeAnalysisInputLocation());

        // Create the view
        this.view = new JavaView(inputLocations);
        System.out.println("JavaView created with " + inputLocations.size() + " input locations");
    }

    public void generateCallGraph() {
        // Get all classes in the project
        Set<SootClass> classes = view.getClasses().collect(Collectors.toSet());
        System.out.println("Found " + classes.size() + " classes in the project");
        
        // Find main class or use all classes as entry points
        List<MethodSignature> entryPoints = new ArrayList<>();
        
        for (SootClass sootClass : classes) {
            // Add all methods from each class as entry points
            for (SootMethod method : sootClass.getMethods()) {
                entryPoints.add(method.getSignature());
            }
        }
        
        System.out.println("Using " + entryPoints.size() + " methods as entry points");

        // Create and initialize CHA call graph
        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        this.callGraph = cha.initialize(entryPoints);
    }

    public void exportCallGraph() {
        try {
            // Create output directory if it doesn't exist
            Path outputDir = Paths.get(outputPath);
            if (!Files.exists(outputDir)) {
                Files.createDirectories(outputDir);
            }

            // Export call graph to DOT format
            String dot = callGraph.exportAsDot();
            
            // Write to file
            String outputFile = outputPath + "/callgraph.dot";
            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(dot);
            }

            // Print some statistics
            System.out.println("\nCall graph generated successfully!");
            System.out.println("Number of methods: " + callGraph.getMethodSignatures().size());
            System.out.println("Number of calls: " + callGraph.callCount());
            System.out.println("Call graph exported to: " + outputFile);

        } catch (IOException e) {
            System.err.println("Error exporting call graph: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java CallGraphGenerator <projectPath> <outputPath>");
            return;
        }

        String projectPath = args[0];
        String outputPath = args[1];

        System.out.println("Project path: " + projectPath);
        System.out.println("Output path: " + outputPath);

        CallGraphGenerator generator = new CallGraphGenerator(projectPath, outputPath);
        generator.initialize();
        generator.generateCallGraph();
        generator.exportCallGraph();
    }
} 