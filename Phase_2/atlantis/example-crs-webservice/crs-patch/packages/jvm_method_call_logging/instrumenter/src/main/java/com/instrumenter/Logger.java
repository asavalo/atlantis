package com.instrumenter;

import java.io.FileOutputStream;
import java.io.PrintStream;

public class Logger {
    public static PrintStream log;

    static {
        try {
            log = new PrintStream(new FileOutputStream("/out/call_trace.log", true));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
