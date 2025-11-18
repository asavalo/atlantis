#include <stdio.h>

#ifndef LOG_FILE_PATH
#define LOG_FILE_PATH "/out/call_trace.log"
#endif

const char *logFilePath = LOG_FILE_PATH;

void logFunctionEntry(const char *functionName, const char *fileName, int lineNumber) {
    FILE *logFile = fopen(logFilePath, "a");
    if (logFile == NULL) {
        return;
    }
    fprintf(logFile, "[Entry] Function: %s, File: %s, Line: %d\n", functionName, fileName, lineNumber);
    fclose(logFile);
}

void logFunctionCall(const char *fileName, int lineNumber, const char *callerName, const char *calleeName) {
    FILE *logFile = fopen(logFilePath, "a");
    if (logFile == NULL) {
        return;
    }
    fprintf(logFile, "[Call] File: %s, Line: %d, Caller: %s, Callee: %s\n", fileName, lineNumber, callerName, calleeName);
    fclose(logFile);
}

__attribute__((weak)) int main() {
    printf("Weak main from Logger library\n");
    return 0;
}