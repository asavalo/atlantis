COMMIT_ANALYZER_MAX_TOKEN = 12800


DEFAULT_SANITIZER_PROMPT = """No actual crash information or Proof of Vulnerability (PoV) is available (fuzzing might have failed or sanitizer output was not captured). 

However, the code changes in the provided diff likely contain vulnerabilities that need to be identified. These could include:
- Memory safety issues (buffer overflows, use-after-free, null pointer dereferences)
- Race conditions or thread safety problems
- Resource leaks or allocation failures
- Integer overflow/underflow
- Uninitialized variable usage
- Format string vulnerabilities
- Command injection vulnerabilities
- Input validation issues

Please analyze the code changes carefully to identify potential security issues, regardless of the programming language (C, C++, Java, etc.).
"""

EXAMPLE_CODE_SNIPPET = """
/* Original code */
void some_function(char *data, int len) {{
-      char buffer[10];
-      strcpy(buffer, data);  // Potential buffer overflow
+      char buffer[256];
+      strncpy(buffer, data, sizeof(buffer) - 1);
+      buffer[sizeof(buffer) - 1] = '\\0';  // Ensure null-termination
}}
"""

VULNERABILITY_ANALYSIS_JSON_EXAMPLE = """```json
[
  {{
    "vulnerability_type": "NULL Pointer Dereference",
    "severity": 0.8,
    "description": "The function `process_data` doesn't check if `user_input` pointer is NULL before dereferencing it. This vulnerability was introduced in the following diff:\\\\n\\\\n- void process_data(char *user_input) {{\\\\n-   if (user_input == NULL) {{\\\\n-     return;\\\\n-   }}\\\\n  int len = strlen(user_input);\\\\n  // process data\\\\n}}\\\\n\\\\nThe original code had a NULL check that was removed, introducing a potential segmentation fault if NULL is passed to the function.",
    "recommendation": "Add a NULL check before dereferencing the pointer: `if (user_input == NULL) return;`",
    "problematic_lines": ["file.c:45", "file.c:67"],
    "patches_to_avoid": ["Don't modify the memory allocation at line 30 as it's used correctly elsewhere."]
  }},
  {{
    "vulnerability_type": "Race Condition", 
    "severity": 0.75,
    "description": "The code changes introduce a race condition where multiple threads can access shared data without proper synchronization. The diff shows how mutex locks were removed:\\\\n\\\\n- pthread_mutex_lock(&data_mutex);\\\\n  shared_data->counter++;\\\\n  shared_data->last_updated = time(NULL);\\\\n- pthread_mutex_unlock(&data_mutex);\\\\n\\\\nThe original code had proper mutex locks that protected the shared resources, but they were removed in this commit. This could lead to data corruption or unexpected behavior when multiple threads access shared resources simultaneously.",
    "recommendation": "Restore the mutex locks to protect the shared resources as shown in the original code.",
    "problematic_lines": ["thread.c:120", "thread.c:135"],
    "patches_to_avoid": ["The thread initialization code is correct and should not be modified."]
  }}
]```"""

CALL_STACK_VULNERABILITY_ANALYSIS_SYSTEM_PROMPT = """
You are a software security expert tasked with analyzing code snippets from a codebase to identify potential security vulnerabilities. I will provide:
1. Sanitizer output from a program that detected a potential issue
2. Code snippets/patches showing the relevant parts of the code where the vulnerability might be present
""".format()

CALL_STACK_VULNERABILITY_ANALYSIS_USER_PROMPT = """
Please analyze the following patches related to a call stack for potential vulnerabilities, bugs, or issues.

Sanitizer:
{{sanitizer_prompt}}

Related Commit Patches:
{{combined_patches}}

Focus on:
1. Identifying the most likely line(s) causing the bug or vulnerability
2. Analyzing how the code was changed in the commit and how that relates to the vulnerability
3. Explaining exactly how the issue should be fixed
4. Identifying any patches that shouldn't be modified to avoid breaking functionality

Provide your analysis in JSON format as a list of vulnerabilities found. Each item should include:

1. "vulnerability_type": The type of vulnerability found
2. "severity": A float value between 0 and 1 representing the severity
3. "description": A detailed description of the issue that follows this format:
   - Begin with a brief explanation of the vulnerability (1-2 sentences)
   - Include the relevant code snippet with file name and line numbers
   - Show at least 3 lines of context before and after the changed code
   - Format the code snippet with leading - for removed lines and + for added lines
   - End with a thorough explanation of how the vulnerability was introduced
   - This change introduces a vulnerability because the new code uses a smaller buffer without proper bounds checking..."

4. "recommendation": Specific recommendations for fixing the issue
5. "problematic_lines": A list of the most likely problematic lines
6. "patches_to_avoid": Any patches that shouldn't be modified and why

IMPORTANT: 
- Return your result in proper JSON format.
- For example, code like: {example_code}
- Always include at least one code snippet with context in your description.
- DO NOT use markdown code fences or escape characters for newlines in your code snippets.
- Do NOT include any large multi-line code blocks in your JSON response. Keep code snippets to 10-15 lines maximum.
- Describe the code issue clearly and reference line numbers where appropriate.

Example output format:
{example_json}

Be thorough in your analysis and focus on the relationship between the call stack, the code changes in the patches, and how they relate to potential vulnerabilities.
""".format(
    example_code=EXAMPLE_CODE_SNIPPET, example_json=VULNERABILITY_ANALYSIS_JSON_EXAMPLE
)
