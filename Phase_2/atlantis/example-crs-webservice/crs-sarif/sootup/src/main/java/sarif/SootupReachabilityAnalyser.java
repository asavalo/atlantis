package sarif;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import qilin.core.PTA;
import qilin.driver.PTAFactory;
import qilin.driver.PTAOption;
import qilin.driver.PTAPattern;
import qilin.pta.PTAConfig;
import qilin.util.PTAUtils;
import sootup.callgraph.CallGraph;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.core.views.View;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import java.io.IOException;
import java.nio.file.Files;

enum CGMethod    {
    CHA("cha"), // class hierarchy analysis
    RTA("rta"), // rapid type analysis
    PTA("pta"); // Qilin pointer analysis

    private final String value;

    CGMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static CGMethod fromString(String text) {
        for (CGMethod method : CGMethod.values()) {
            if (method.value.equalsIgnoreCase(text)) {
                return method;
            }
        }
        throw new IllegalArgumentException("Unknown CG method: " + text);
    }
}

enum PTAAlgorithm {
    // Full list: https://soot-oss.github.io/SootUp/v2_0_0/qilin/
    INSENS("insens"), // Andersen's context-insensitive pointer analysis
    CALLSITE_SENSITIVE_1("1c"), // call-site sensitive pointer analysis
    CALLSITE_SENSITIVE_2("2c"), // call-site sensitive pointer analysis
    OBJECT_SENSITIVE_1("1o"), // object-sensitive pointer analysis
    OBJECT_SENSITIVE_2("2o"), // object-sensitive pointer analysis
    TYPE_SENSITIVE_1("1t"), // type-sensitive pointer analysis
    TYPE_SENSITIVE_2("2t"), // type-sensitive pointer analysis
    HYBRID_OBJECT_SENSITIVE_1("1h"), // hybrid object-sensitive pointer analysis
    HYBRID_OBJECT_SENSITIVE_2("2h"), // hybrid object-sensitive pointer analysis
    HYBRID_TYPE_SENSITIVE_1("1ht"), // hybrid type-sensitive pointer analysis
    HYBRID_TYPE_SENSITIVE_2("2ht"), // hybrid type-sensitive pointer analysis
    EAGLE_OBJECT_SENSITIVE_1("E-1o"), // eagle object-sensitive pointer analysis
    EAGLE_OBJECT_SENSITIVE_2("E-2o"), // eagle object-sensitive pointer analysis
    ZIPPER_OBJECT_SENSITIVE_1("Z-1o"), // zipper object-sensitive pointer analysis
    ZIPPER_OBJECT_SENSITIVE_2("Z-2o"), // zipper object-sensitive pointer analysis
    ZIPPER_CALLSITE_SENSITIVE_1("Z-1c"), // zipper call-site sensitive pointer analysis
    ZIPPER_CALLSITE_SENSITIVE_2("Z-2c"); // zipper call-site sensitive pointer analysis
    
    private final String value;

    PTAAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static PTAAlgorithm fromString(String text) {
        for (PTAAlgorithm algorithm : PTAAlgorithm.values()) {
            if (algorithm.value.equalsIgnoreCase(text)) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown PTA algorithm: " + text);
    }
}

@Command(name = "sootup-reachability", 
         description = "Analyzes method reachability using SootUp")
public class SootupReachabilityAnalyser {
    private List<String> inputDirs;
    private List<AnalysisInputLocation> inputLocations = new ArrayList<>();
    private HashSet<JavaSootClass> sourceClasses = new HashSet<>();
    private HashSet<JavaSootMethod> sourceMethods = new HashSet<>();
    private JavaSootMethod sinkMethod = null;
    private Map<JavaSootMethod, String> sourceJarMap = new HashMap<>();
    private JavaView view = null;
    private CallGraph cg = null;
    private CGMethod cgMethod;
    private PTAAlgorithm ptaAlgorithm;
    private Logger logger = Logger.getLogger(SootupReachabilityAnalyser.class.getName());
    private final String fuzzingEntryPoint = "fuzzerTestOneInput";
    private String jrePath;
    private boolean dumpCallGraph;
    private String outputDir;
    // Default constructor for Picocli
    public SootupReachabilityAnalyser() {}

    public SootupReachabilityAnalyser(List<String> classpath, CGMethod cgMethod, PTAAlgorithm ptaAlgorithm, String jrePath, boolean dumpCallGraph, String outputDir) throws Exception {
        this.inputDirs = classpath;
        this.cgMethod = cgMethod;
        this.ptaAlgorithm = ptaAlgorithm;
        this.jrePath = jrePath;
        this.dumpCallGraph = dumpCallGraph;
        this.outputDir = outputDir;

        // Process multiple input paths - directly add as classpath locations
        for (String inputPath : classpath) {
            System.out.println("Adding classpath: " + inputPath);
            try {
                this.inputLocations.add(new JavaClassPathAnalysisInputLocation(inputPath));
                System.out.println("Successfully added classpath: " + inputPath);
            } catch (IllegalArgumentException e) {
                System.out.println("Warning: Skipping invalid classpath '" + inputPath + "': " + e.getMessage());
                continue;
            } catch (Exception e) {
                System.out.println("Warning: Skipping problematic classpath '" + inputPath + "': " + e.getMessage());
                continue;
            }
        }

        this.view = new JavaView(this.inputLocations);
        
        initSourceMethods();
    }

    // Convenience constructor for single directory/path (backward compatibility)
    public SootupReachabilityAnalyser(String inputPathOrDir, CGMethod cgMethod, PTAAlgorithm ptaAlgorithm, String jrePath, boolean dumpCallGraph, String outputDir) throws Exception {
        this(Arrays.asList(inputPathOrDir), cgMethod, ptaAlgorithm, jrePath, dumpCallGraph, outputDir);
    }

    private void initSourceMethods() throws Exception {
        List<JavaSootClass> classes = this.view.getClasses().collect(Collectors.toList());
        for (JavaSootClass cls : classes) {
            for (JavaSootMethod m : cls.getMethods()) {
                if (m.getSignature().getName().equals(fuzzingEntryPoint)) {
                    this.sourceMethods.add(m);
                    this.sourceClasses.add(cls);
                    this.sourceJarMap.put(m, cls.getClassSource().getSourcePath().toString());
                }
            }
        }

        if (this.sourceMethods.isEmpty()) {
            throw new Exception("Fuzzing entry point not found: " + fuzzingEntryPoint);
        }
    }

    private JavaSootMethod findSinkMethod(String sinkMethodSignature) throws Exception {
            List<JavaSootClass> classes = this.view.getClasses().collect(Collectors.toList());
            for (JavaSootClass cls : classes) {
                for (JavaSootMethod m : cls.getMethods()) {
                    if (m.getSignature().toString().equals(sinkMethodSignature)) {
                        return m;
                    }
                }
            }

        throw new Exception("Sink method not found: " + sinkMethodSignature);
    }

    public CallGraph getCallGraph(JavaSootClass mainClass) throws Exception {
        this.logger.info("Constructing call graph");

        switch (this.cgMethod) {
            case CHA:
                ClassHierarchyAnalysisAlgorithm chaCG = new ClassHierarchyAnalysisAlgorithm(this.view);
                this.cg = chaCG.initialize(this.sourceMethods.stream().map(source -> source.getSignature()).collect(Collectors.toList()));
                break;
            case RTA:
                RapidTypeAnalysisAlgorithm rtaCG = new RapidTypeAnalysisAlgorithm(this.view);
                this.cg = rtaCG.initialize(this.sourceMethods.stream().map(source -> source.getSignature()).collect(Collectors.toList()));
                break;
            case PTA:
                this.logger.info("Constructing PTA call graph for " + mainClass.toString());

                try{
                    // Combine all input directories into a single classpath
                    String combinedInputPath = String.join(File.pathSeparator, this.inputDirs);
                    
                    String[] args = new String[] {
                        "-apppath", combinedInputPath,
                        "-libpath", combinedInputPath,
                        "-mainclass", mainClass.toString(),
                        "-se", "-pae", "-pe", "-clinit=APP", "-lcs", "-mh", "-pta=" + this.ptaAlgorithm.getValue(),  "-cga=QILIN",
                        "-jre=" + this.jrePath,
                    };
                    logger.info("PTA args: " + String.join(" ", args));
                    new PTAOption().parseCommandLine(args);
                    PTAConfig.ApplicationConfiguration appConfig = PTAConfig.v().getAppConfig();
                    View view2 = PTAUtils.createView();
                    PTAPattern ptaPattern = PTAConfig.v().getPtaConfig().ptaPattern;
                    PTA pta = PTAFactory.createPTA(ptaPattern, view2, appConfig.MAIN_CLASS);
                    pta.run();
                    this.cg = pta.getCallGraph();
                } catch (Exception e) {
                    logger.info("Error: " + e.getMessage());
                    e.printStackTrace();
                    throw e;
                }
                break;
        }

        this.logger.info("Call graph constructed");
        this.logger.info("CG callCount:" + cg.callCount());
        this.logger.info("CG methodCount:" + cg.getMethodSignatures().size());

        if (this.dumpCallGraph) {
            this.logger.info("Dumping call graph to " + this.outputDir + "/" + mainClass + "_" + this.cgMethod.getValue() + "_callgraph.dot");
            // String dot = this.cg.exportAsDot();
            this.logger.info("Dumping call graph new way");
            CustomDotExporter exporter = new CustomDotExporter(this.cg, this.view);
            String dot = exporter.exportAsDot();
            try (FileWriter writer = new FileWriter(this.outputDir + "/" + mainClass + "_" + this.cgMethod.getValue() + "_callgraph.dot")) {
                writer.write(dot);
            }
        }

        return this.cg;
    }

    public Set<MethodSignature> getAllReachableMethods() throws Exception {
        this.logger.info("Getting all reachable methods");

        Set<MethodSignature> reachableMethods = new HashSet<>();

        if (this.cgMethod == CGMethod.PTA) {
            // PTA does not support multiple classes
            for (JavaSootClass cls : this.sourceClasses) {
                CallGraph cg = getCallGraph(cls);
                reachableMethods.addAll(cg.getMethodSignatures());
            }
        } else {
            CallGraph cg = getCallGraph(null);
            reachableMethods = cg.getMethodSignatures();
        }

        this.logger.info("All # of reachable methods: " + reachableMethods.size());

        return reachableMethods;
    }

    public boolean checkReachability(String sinkMethodSignature) throws Exception {
        this.logger.info("Checking reachability");

        sinkMethod = findSinkMethod(sinkMethodSignature);

        Set<MethodSignature>  reachableMethods = getAllReachableMethods();
        boolean result = reachableMethods.contains(sinkMethod.getSignature());

        this.logger.info("Reachability check result: " + result);

        return result;
    }

    public HashSet<JavaSootClass> getSourceClasses() {
        return this.sourceClasses;
    }
    
    public JavaView getView() {
        return this.view;
    }

    public static List<Path> findSourceFiles(Path directory) throws IOException {
        List<Path> sourceFiles = new ArrayList<>();
        Files.walk(directory)
            .filter(path -> path.toString().endsWith(".java"))
            .forEach(sourceFiles::add);
        return sourceFiles;
    }

    public static List<Path> findJarFiles(Path directory) throws IOException {
        List<Path> jarFiles = new ArrayList<>();
        Files.walk(directory)
            .filter(path -> path.toString().endsWith(".jar"))
            .forEach(jarFiles::add);
        return jarFiles;
    }

    public static String buildClasspath(List<Path> jarFiles) {
        return jarFiles.stream()
            .map(Path::toString)
            .collect(Collectors.joining(File.pathSeparator));
    }

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new SootupReachabilityAnalyser())
            .addSubcommand(new GetAllReachableMethods())
            .addSubcommand(new CheckReachability())
            .addSubcommand(new GenerateCallGraph());
        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }
}

@Command(name = "get-all-reachable-methods", 
         description = "Get all reachable methods from entry point")
class GetAllReachableMethods implements Runnable {
    @CommandLine.Parameters(index = "0", 
            description = "Directory containing JAR files, or direct classpath(s) (colon-separated for multiple).")
    private String classpathRaw;

    @Option(names = {"--cg-method"}, 
            description = "CG method", 
            required = false,
            defaultValue = "cha")
    private String cgMethod;

    @Option(names = {"--pta-algorithm"}, 
            description = "PTA algorithm", 
            required = false,
            defaultValue = "insens")
    private String ptaAlgorithm;
    
    @Option(names = {"-o", "--output"}, 
            description = "Output file path", 
            required = false,
            defaultValue = "reachable_methods.json")
    private String outPath;

    @Option(names = {"--jre-path"}, 
            description = "JRE path", 
            required = false,
            defaultValue = "./jre1.6.0_45")
    private String jrePath;

    @Option(names = {"--dump-call-graph"}, 
            description = "Dump call graph", 
            required = false,
            defaultValue = "false")
    private boolean dumpCallGraph;

    @Option(names = {"--output-dir"}, 
            description = "Output directory", 
            required = false,
            defaultValue = "")
    private String outputDir;

    @Override
    public void run() {
        try {
            // Parse multiple directories from inputDir (colon-separated)
            List<String> classpath = new ArrayList<>();
            if (classpathRaw.contains(":")) {
                String[] paths = classpathRaw.split(":");
                for (String path : paths) {
                    String trimmed = path.trim();
                    if (!trimmed.isEmpty()) {
                        classpath.add(trimmed);
                    }
                }
            } else {
                classpath.add(classpathRaw.trim());
            }

            SootupReachabilityAnalyser analyser = new SootupReachabilityAnalyser(
                classpath, CGMethod.fromString(cgMethod), PTAAlgorithm.fromString(ptaAlgorithm), jrePath, dumpCallGraph, outputDir);
            Set<MethodSignature> result = analyser.getAllReachableMethods();
            Set<String> stringResult = result.stream()
                .map(MethodSignature::toString)
                .collect(Collectors.toSet());
            
            try (FileWriter writer = new FileWriter(outPath)) {
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                gson.toJson(stringResult, writer);
            }
            System.out.println("\nAnalysis complete. Results written to: " + outPath);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}

@Command(name = "check-reachability", 
         description = "Check if sink method is reachable from entry point")
class CheckReachability implements Runnable {
    @CommandLine.Parameters(index = "0", 
            description = "Directory containing JAR files, or direct classpath(s) (colon-separated for multiple).")
    private String classpathRaw;

    @CommandLine.Parameters(index = "1", 
            description = "Sink method signature")
    private String sinkMethodSignature;

    @Option(names = {"--cg-method"}, 
            description = "CG method", 
            required = false,
            defaultValue = "cha")
    private String cgMethod;

    @Option(names = {"--pta-algorithm"}, 
            description = "PTA algorithm", 
            required = false,
            defaultValue = "insens")
    private String ptaAlgorithm;
    
    @Option(names = {"-o", "--output"}, 
            description = "Output file path", 
            required = false,
            defaultValue = "")
    private String outPath;

    @Option(names = {"--jre-path"}, 
            description = "JRE path", 
            required = false,
            defaultValue = "./jre1.6.0_45")
    private String jrePath;

    @Option(names = {"--dump-call-graph"}, 
            description = "Dump call graph", 
            required = false,
            defaultValue = "false")
    private boolean dumpCallGraph;

    @Option(names = {"--output-dir"}, 
            description = "Output directory", 
            required = false,
            defaultValue = "")
    private String outputDir;

    @Override
    public void run() {
        try {
            // Parse multiple directories from inputDir (colon-separated)
            List<String> classpath = new ArrayList<>();
            if (classpathRaw.contains(":")) {
                String[] paths = classpathRaw.split(":");
                for (String path : paths) {
                    String trimmed = path.trim();
                    if (!trimmed.isEmpty()) {
                        classpath.add(trimmed);
                    }
                }
            } else {
                classpath.add(classpathRaw.trim());
            }

            SootupReachabilityAnalyser analyser = new SootupReachabilityAnalyser(
                classpath, CGMethod.fromString(cgMethod), PTAAlgorithm.fromString(ptaAlgorithm), jrePath, dumpCallGraph, outputDir);
            boolean result = analyser.checkReachability(sinkMethodSignature);
            System.out.println("Reachability check result: " + result);

            if (outPath != null && !outPath.isEmpty()) {
                try (FileWriter writer = new FileWriter(outPath)) {
                    writer.write(String.valueOf(result));
                }
            }

            System.out.println("\nAnalysis complete. Results written to: " + outPath);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}

@Command(name = "generate-call-graph", 
         description = "Generate and dump call graph to a dot file")
class GenerateCallGraph implements Runnable {
    @CommandLine.Parameters(index = "0", 
            description = "Directory containing JAR files, or direct classpath(s) (colon-separated for multiple).")
    private String classpathRaw;

    @Option(names = {"--cg-method"}, 
            description = "CG method", 
            required = false,
            defaultValue = "cha")
    private String cgMethod;

    @Option(names = {"--pta-algorithm"}, 
            description = "PTA algorithm", 
            required = false,
            defaultValue = "insens")
    private String ptaAlgorithm;
    
    @Option(names = {"-o", "--output"}, 
            description = "Output dot file path", 
            required = false,
            defaultValue = "callgraph.dot")
    private String outPath;

    @Option(names = {"--jre-path"}, 
            description = "JRE path", 
            required = false,
            defaultValue = "./jre1.6.0_45")
    private String jrePath;

    @Override
    public void run() {
        try {
            List<String> classpath = parseClasspath(classpathRaw);
            
            System.out.println("Generating call graph using " + cgMethod + " method...");
            
            SootupReachabilityAnalyser analyser = new SootupReachabilityAnalyser(
                classpath, CGMethod.fromString(cgMethod), PTAAlgorithm.fromString(ptaAlgorithm), jrePath, false, "");
            
            if (CGMethod.fromString(cgMethod) == CGMethod.PTA) {
                generatePTACallGraphs(analyser);
            } else {
                generateSingleCallGraph(analyser);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private List<String> parseClasspath(String classpathRaw) {
        List<String> classpath = new ArrayList<>();
        if (classpathRaw.contains(":")) {
            String[] paths = classpathRaw.split(":");
            for (String path : paths) {
                String trimmed = path.trim();
                if (!trimmed.isEmpty()) {
                    classpath.add(trimmed);
                }
            }
        } else {
            classpath.add(classpathRaw.trim());
        }
        return classpath;
    }
    
    private void generatePTACallGraphs(SootupReachabilityAnalyser analyser) throws Exception {
        System.out.println("Generating PTA call graphs for " + analyser.getSourceClasses().size() + " source classes...");
        
        int processedClasses = 0;
        String baseFileName = outPath.replaceAll("\\.dot$", "");
        
        for (JavaSootClass cls : analyser.getSourceClasses()) {
            String className = cls.getName().replace(".", "_");
            String classOutputPath = baseFileName + "_" + className + ".dot";
            
            System.out.println("Processing source class: " + cls.getName());
            CallGraph classCg = analyser.getCallGraph(cls);
            
            printCallGraphStats(classCg);
            exportCallGraphToDot(classCg, classOutputPath, analyser.getView());
            
            processedClasses++;
        }
        
        System.out.println("Successfully exported " + processedClasses + " call graphs for PTA");
        System.out.println("Use glob pattern: " + baseFileName + "_*.dot to find all generated files");
    }
    
    private void generateSingleCallGraph(SootupReachabilityAnalyser analyser) throws Exception {
        CallGraph cg = analyser.getCallGraph(null);
        
        System.out.println("Call graph generated successfully:");
        printCallGraphStats(cg);
        
        System.out.println("Exporting call graph to dot format...");
        exportCallGraphToDot(cg, outPath, analyser.getView());
        
        System.out.println("Call graph exported to: " + outPath);
    }
    
    private void printCallGraphStats(CallGraph cg) {
        System.out.println("  - Methods: " + cg.getMethodSignatures().size());
        System.out.println("  - Calls: " + cg.callCount());
    }
    
    private void exportCallGraphToDot(CallGraph cg, String outputPath, JavaView view) throws Exception {
        System.out.println("  - Exporting to: " + outputPath);
        String dot;
        try {
            CustomDotExporter exporter = new CustomDotExporter(cg, view);
            // dot = exporter.exportAsDot();
            dot = cg.exportAsDot();
        } catch (Exception e) {
            System.out.println("  - Using default dot export method due to error with custom exporter: " + e.getMessage());
            dot = cg.exportAsDot();
        }
        
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(dot);
        }
    }
}
