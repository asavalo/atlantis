import inspect

CLAUDE_CODE_USER_PROMPT_TEMPLATE = inspect.cleandoc(
    """
    Create a patch to fix a {bug_class} bug given below and apply it to the code.

    {insights}
    """
).lstrip()

CLAUDE_CODE_USER_PROMPT_TEMPLATE_WITH_FEEDBACK = inspect.cleandoc(
    """
    I tried to fix a {bug_class} vulnerability causing the crash log in the <crash_log> below.
    I failed to fix the vulnerability with the following patches:

    {failed_patch}

    Explain why the patches failed and provide a new patch to fix the vulnerability.
    Do not repeat the same mistakes in the new patch.
    Try a completely different approach to fix the vulnerability.

    {insights}
    """
).lstrip()

DEFAULT_INSIGHTS_TEMPLATE = inspect.cleandoc(
    """
    Below is the crash log:

    <crash_log>
    {crash_log}
    </crash_log>
    """
).lstrip()

DEFAULT_SARIF_INSIGHT_TEMPLATE = inspect.cleandoc(
    """
    Below is static analysis report:

    <report>
    {sarif_report}
    </report>
    """
).lstrip()

FAILED_PATCH_TEMPLATE = inspect.cleandoc(
    """
    ```diff
    {failed_patch}
    ```
    
    """
)
