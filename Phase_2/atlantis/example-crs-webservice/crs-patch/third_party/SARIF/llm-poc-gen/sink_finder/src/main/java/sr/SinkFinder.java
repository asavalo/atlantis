package sr;

import sr.parser.TargetParser;
import sr.parser.TargetLocation;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import sootup.callgraph.CallGraph;
import sootup.callgraph.CallGraphAlgorithm;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.graph.StmtGraph;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.basic.StmtPositionInfo;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SourceType;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.inputlocation.DefaultRTJarAnalysisInputLocation;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SinkFinder {
    private String classDir;
    private Set<MethodSignature> targetMethods = new HashSet<>();
    private JavaView view = null;
    private CallGraph cg = null;

    public SinkFinder(String classDir) throws Exception {
        this.classDir = classDir;
        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        inputLocations.add(new JavaClassPathAnalysisInputLocation(classDir));
        this.view = new JavaView(inputLocations);
        initTargetMethods();
    }

    private void initTargetMethods() {
        Set<String> targetStrings = new HashSet<>();
        for (TargetLocation targetLocation : new TargetParser(this.view).getTargetMethods()) {
            targetStrings.add(targetLocation.toString());
        }
        for (JavaSootClass cls : this.view.getClasses()) {
            for (JavaSootMethod m : cls.getMethods()) {
                if (targetStrings.contains(m.getSignature().toString()) || m.getSignature().getName().equals("fuzzerTestOneInput")) {
                    // fuzzerTestOneInput should be added for better result
                    this.targetMethods.add(m.getSignature());
                }
            }
        }
    }

    private Map<String, Set<String>> extractPackageMap(String srcDir) throws Exception {
        Map<String, Set<String>> ret = new HashMap<>();
        Pattern regexPattern = Pattern.compile(srcDir + "/?(.+.java):package (.+?);");
        List<String> command = Arrays.asList("grep", "-Eros", "^package .+;", srcDir);
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process = processBuilder.start();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = regexPattern.matcher(line);
                if (matcher.find()) {
                    Path filepath = Paths.get(matcher.group(1));
                    String pkg = matcher.group(2);
                    ret.computeIfAbsent(pkg, k -> new HashSet<>()).add(filepath.toString());
                }
            }
        }
        return ret;
    }

    private Map<MethodSignature, Set<String>> extractFilePathMap(String srcDir) throws Exception {
        Map<MethodSignature, Set<String>> ret = new HashMap<>();
        Map<String, Set<String>> pkgMap = extractPackageMap(srcDir);
        for (JavaSootClass cls : this.view.getClasses()) {
            String pkgName = cls.getType().getPackageName().toString();
            String clsFileName = cls.getClassSource().getSourcePath().getFileName().toString();
            String javaFileName = clsFileName.split("\\$")[0].replace(".class", ".java");
            for (JavaSootMethod m : cls.getMethods()) {
                if (!pkgMap.containsKey(pkgName)) {
                    continue;
                }
                for (String filePath : pkgMap.get(pkgName)) {
                    if (new File(filePath).getName().equals(javaFileName)) {
                        ret.computeIfAbsent(m.getSignature(), k -> new HashSet<>()).add(filePath);
                    }
                }
            }
        }
        return ret;
    }

    public CallGraph getCallGraph() throws Exception {
        if (this.cg == null) {
            RapidTypeAnalysisAlgorithm rtaCG = new RapidTypeAnalysisAlgorithm(this.view);
            this.cg = rtaCG.initialize(new ArrayList<>(this.targetMethods));
            System.out.println("CG callCount:" + cg.callCount());
        }
        return this.cg;
    }

    public Set<String> findSinks(String srcDir) throws Exception {
        Set<String> ret = new HashSet<>();
        Map<MethodSignature, Set<String>> filePathMap = extractFilePathMap(srcDir);
        CallGraph cg = getCallGraph();

        Set<Map.Entry<MethodSignature, MethodSignature>> sinkEdges = new HashSet<>();

        Deque<Map.Entry<MethodSignature, MethodSignature>> workList = new ArrayDeque<>();
        for (MethodSignature method : this.targetMethods) {
            workList.add(new AbstractMap.SimpleEntry<>(method, null));
        }
        Set<MethodSignature> visited = new HashSet<>();
        while (!workList.isEmpty()) {
            Map.Entry<MethodSignature, MethodSignature> callerCallee = workList.removeFirst();
            MethodSignature caller = callerCallee.getKey();
            MethodSignature callee = callerCallee.getValue();

            if (filePathMap.containsKey(caller)) {
                sinkEdges.add(new AbstractMap.SimpleEntry<>(caller, callee));
            }
            if (visited.contains(caller)) {
                continue;
            }
            visited.add(caller);
            if (cg.containsMethod(caller)) {
                for (MethodSignature nextCaller : cg.callsTo(caller)) {
                    workList.add(new AbstractMap.SimpleEntry<>(nextCaller, caller));
                }
            }
        }

        for (Map.Entry<MethodSignature, MethodSignature> callerCallee : sinkEdges) {
            MethodSignature caller = callerCallee.getKey();
            MethodSignature callee = callerCallee.getValue();
            JavaSootMethod callerMethod = this.view.getMethod(caller).get();
            if (!callerMethod.hasBody())
                continue;

            callerMethod.getBody().getStmts().stream()
                .filter(Stmt::containsInvokeExpr)
                .filter(s -> callee == null || s.getInvokeExpr().getMethodSignature().getName().equals(callee.getName()))
                .forEach(s -> {
                    // TODO: Check isSubType
                    int lineNo = s.getPositionInfo().getStmtPosition().getFirstLine();
                    for (String filePath : filePathMap.get(caller)) {
                        ret.add(filePath + ":" + lineNo);
                    }
                });
        }
        return ret;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: java -jar SinkFinder <class_dir> <src_dir> <out_filepath>");
            System.exit(1);
        }

        String classDir = args[0];
        String srcDir = args[1];
        String outPath = args[2];

        if (!new File(classDir).exists()) {
            System.out.println("<class_dir> not exists: " + classDir);
            System.exit(1);
        }
        if (!new File(srcDir).exists()) {
            System.out.println("<src_dir> not exists: " + srcDir);
            System.exit(1);
        }

        try (FileWriter writer = new FileWriter(outPath)) {
            SinkFinder finder = new SinkFinder(classDir);
            ArrayList<String> sinkList = new ArrayList<>(finder.findSinks(srcDir));
            Collections.sort(sinkList);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(sinkList, writer);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
