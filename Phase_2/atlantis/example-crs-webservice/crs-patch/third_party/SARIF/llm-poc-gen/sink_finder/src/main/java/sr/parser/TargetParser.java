package sr.parser;

import sootup.core.model.LinePosition;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.Type;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaIdentifierFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class TargetParser {
    private final JavaView view;

    public TargetParser(JavaView view) {
        this.view = view;
    }

    // Helper class for holding the regex and group order
    private static class PatternInfo {
        Pattern pattern;
        int[] groupOrder;

        PatternInfo(String regex, int... groupOrder) {
            this.pattern = Pattern.compile(regex);
            this.groupOrder = groupOrder;
        }
    }

    // Common regex patterns
    private static final String GENERIC = "<[^>]+>";
    private static final String RETURN_CLASS = "[\\w\\.\\$\\[\\]]+";
    private static final String RETURN_TYPE = String.format("(%s)(?:%s)?", RETURN_CLASS, GENERIC);
    private static final String DEF_CLASS = "[\\w\\.\\$]+";
    private static final String CLASS_TYPE = String.format("(%s)(?:%s)?", DEF_CLASS, GENERIC);
    private static final String METHOD_NAME = "([\\w\\<\\>]+)";
    private static final String ARGS = "([^\\)]*)";
    private static final String LINE_NUMBER = "(?::(\\d+))?";

    // Combined regex patterns
    private static final PatternInfo PATTERN_INFO_1 = new PatternInfo(
            String.format("^%s\\s+%s\\.%s\\(%s\\)%s$", RETURN_TYPE, CLASS_TYPE, METHOD_NAME, ARGS, LINE_NUMBER), 1, 2, 3, 4, 5);
    private static final PatternInfo PATTERN_INFO_2 = new PatternInfo(
            String.format("^%s\\.%s:%s\\(%s\\)%s$", CLASS_TYPE, METHOD_NAME, RETURN_TYPE, ARGS, LINE_NUMBER), 3, 1, 2, 4, 5);

    private static final List<PatternInfo> patterns = Arrays.asList(PATTERN_INFO_1, PATTERN_INFO_2);

    public Optional<TargetLocation> getTargetLocationForString(String s) {
        // Silently ignore empty lines
        if (s.trim().isEmpty()) {
            return Optional.empty();
        }

        for (PatternInfo patternInfo : patterns) {
            Matcher matcher = patternInfo.pattern.matcher(s.trim());

            if (matcher.find()) {
                String returnType = Util.guessFullClassName(matcher.group(patternInfo.groupOrder[0]));
                String className = matcher.group(patternInfo.groupOrder[1]);
                String methodName = matcher.group(patternInfo.groupOrder[2]);
                String rawArgString = matcher.group(patternInfo.groupOrder[3]);
                String[] argStrings = parseArgumentString(rawArgString);

                List<Type> argTypes = Arrays.stream(argStrings)
                        .map(Util::removeGenericTypes)
                        .map(Util::guessFullClassName)
                        .map(Util::varargsToArray)
                        .map(JavaIdentifierFactory.getInstance()::getType)
                        .collect(Collectors.toList());

                MethodSignature methodSignature = Util.generateMethodSignature(view, className, methodName, returnType, argTypes);

                Optional<LinePosition> linePosition = Optional.empty();
                if (patternInfo.groupOrder.length > 4) {
                    String lineNumberStr = matcher.group(patternInfo.groupOrder[4]);
                    if (lineNumberStr != null) {
                        int lineNumber = Integer.parseInt(lineNumberStr);
                        linePosition = Optional.of(new LinePosition(lineNumber));
                    }
                }

                return Optional.of(new TargetLocation(methodSignature, linePosition));
            }
        }

        System.out.println("Invalid target format: " + s.trim());
        return Optional.empty();
    }

    public static String[] parseArgumentString(String rawArgString) {
        List<String> result = new ArrayList<>();
        StringBuilder currentType = new StringBuilder();
        int angleBracketDepth = 0;

        for (int i = 0; i < rawArgString.length(); i++) {
            char c = rawArgString.charAt(i);

            if (c == ',' && angleBracketDepth == 0) {
                // We've encountered a comma at the top level; split here
                result.add(currentType.toString().trim());
                currentType.setLength(0); // Clear the builder
            } else {
                currentType.append(c);
                if (c == '<') {
                    angleBracketDepth++;
                } else if (c == '>') {
                    angleBracketDepth--;
                }
            }
        }

        // Add the last type
        if (currentType.length() > 0) {
            result.add(currentType.toString().trim());
        }

        return result.toArray(new String[0]);
    }

    public Set<TargetLocation> getTargetMethods() {
        // Here, we go through the trace and return the list of all executed methods
        Set<TargetLocation> l = new HashSet<>();

        // Open the file and read one target from each line
        try (InputStream inputStream = TargetParser.class.getResourceAsStream("/target_locations.txt")) {
            if (inputStream == null) {
                throw new java.io.FileNotFoundException();
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
                String target;
                while ((target = reader.readLine()) != null) {
                    try {
                        Optional<TargetLocation> targetLocation = getTargetLocationForString(target);
                        if (targetLocation.isPresent()) {
                            l.add(targetLocation.get());
                        } else {
                            System.out.println("Unable to get target location for target: " + target);
                        }
                    } catch (Exception e) {
                        System.out.println("Unable to get target location for target: " + target + " - " + e);
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Targets file for directed fuzzing does not exist." + e);
        }

        return l;
    }
}
