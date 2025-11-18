package com.instrumenter;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.AdviceAdapter;

public class JarInstrumenter {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: java com.instrumenter.JarInstrumenter <input-jar> <output-jar>");
            System.exit(1);
        }

        String inputJarPath = args[0];
        String outputJarPath = args[1];

        // Open the input JAR file.
        JarFile jarFile = new JarFile(inputJarPath);
        // Create the output JAR file.
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(outputJarPath))) {

            // Process all existing entries.
            jarFile.stream().forEach(entry -> {
                try {
                    InputStream is = jarFile.getInputStream(entry);
                    byte[] data = is.readAllBytes();
                    JarEntry newEntry = new JarEntry(entry.getName());
                    jos.putNextEntry(newEntry);

                    // If the entry is a class file, instrument it.
                    if (entry.getName().endsWith(".class")) {
                        data = instrumentClass(data);
                    }

                    jos.write(data);
                    jos.closeEntry();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            // Inject Logger.class into the output JAR.
            addLoggerClass(jos);
        }
        jarFile.close();
    }

    /**
     * Adds Logger.class from the resources into the output JAR.
     */
    private static void addLoggerClass(JarOutputStream jos) {
        try {
            InputStream loggerIs = JarInstrumenter.class.getResourceAsStream("/com/instrumenter/Logger.class");
            if (loggerIs == null) {
                System.err.println("Logger class resource not found.");
                return;
            }
            byte[] loggerBytes = loggerIs.readAllBytes();
            JarEntry loggerEntry = new JarEntry("com/instrumenter/Logger.class");
            jos.putNextEntry(loggerEntry);
            jos.write(loggerBytes);
            jos.closeEntry();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Instruments the given class byte array by inserting logging statements:
     * 
     * 1. A method entry log in the format:
     *    [Entry] class: <class name>, method: <method name>, file: <file name>, line: <line number>
     *
     * 2. A log before every method call in the format:
     *    [Invoke] caller class: <caller class>, caller method: <caller method>, callee class: <target class>,
     *    callee method: <target method>, file: <file name>, line: <current line>
     *
     * @param classBytes the original class byte array
     * @return the instrumented class byte array
     */
    private static byte[] instrumentClass(byte[] classBytes) {
        try {
            ClassReader cr = new ClassReader(classBytes);
            ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                private String sourceFile = "Unknown";
                private String currentClass = "Unknown";

                @Override
                public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                    currentClass = name.replace('/', '.');
                    super.visit(version, access, name, signature, superName, interfaces);
                }

                @Override
                public void visitSource(String source, String debug) {
                    sourceFile = source;
                    super.visitSource(source, debug);
                }

                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

                    final String callerClass = currentClass;
                    final String callerMethod = name;
                    final String sourceFileLocal = sourceFile;

                    return new AdviceAdapter(Opcodes.ASM9, mv, access, name, descriptor) {
                        private boolean printedEntry = false;
                        private int currentLine = -1;

                        @Override
                        public void visitLineNumber(int line, Label start) {
                            currentLine = line;
                            if (!printedEntry) {
                                String entryMessage = "[Entry] class: " + callerClass +
                                                      ", method: " + callerMethod +
                                                      ", file: " + sourceFileLocal +
                                                      ", line: " + line;
                                mv.visitFieldInsn(Opcodes.GETSTATIC, "com/instrumenter/Logger", "log", "Ljava/io/PrintStream;");
                                mv.visitLdcInsn(entryMessage);
                                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                        "(Ljava/lang/String;)V", false);
                                printedEntry = true;
                            }
                            super.visitLineNumber(line, start);
                        }

                        @Override
                        public void visitMethodInsn(int opcode, String owner, String invokedName, String descriptor, boolean isInterface) {
                            String invokeMessage = "[Invoke] caller class: " + callerClass +
                                                   ", caller method: " + callerMethod +
                                                   ", callee class: " + owner.replace('/', '.') +
                                                   ", callee method: " + invokedName +
                                                   ", file: " + sourceFileLocal +
                                                   ", line: " + currentLine;
                            mv.visitFieldInsn(Opcodes.GETSTATIC, "com/instrumenter/Logger", "log", "Ljava/io/PrintStream;");
                            mv.visitLdcInsn(invokeMessage);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                    "(Ljava/lang/String;)V", false);
                            super.visitMethodInsn(opcode, owner, invokedName, descriptor, isInterface);
                        }

                        @Override
                        protected void onMethodEnter() {
                            // No additional logging on method enter.
                        }

                        @Override
                        public void visitMaxs(int maxStack, int maxLocals) {
                            if (!printedEntry) {
                                String entryMessage = "[Entry] class: " + callerClass +
                                                      ", method: " + callerMethod +
                                                      ", file: " + sourceFileLocal +
                                                      ", line: -1";
                                mv.visitFieldInsn(Opcodes.GETSTATIC, "com/instrumenter/Logger", "log", "Ljava/io/PrintStream;");
                                mv.visitLdcInsn(entryMessage);
                                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println",
                                        "(Ljava/lang/String;)V", false);
                                printedEntry = true;
                            }
                            super.visitMaxs(maxStack, maxLocals);
                        }
                    };
                }
            };

            cr.accept(cv, ClassReader.SKIP_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            // In case of error, return the original class bytes.
            return classBytes;
        }
    }
}
