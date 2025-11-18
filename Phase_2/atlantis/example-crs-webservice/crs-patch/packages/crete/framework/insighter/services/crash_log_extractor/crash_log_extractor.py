from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.commons.utils import remove_ansi_escape_codes
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol


class CrashLogSummarizer(InsighterProtocol):
    def __init__(self, llm_api_manager: LlmApiManager, crash_log: str):
        self.llm_api_manager = llm_api_manager
        self.crash_log = remove_ansi_escape_codes(crash_log)[:40960]

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        prompt = f"""Extract the key information from this crash log. Focus on:
1. Error type/exception
2. Root cause
3. Stack trace with relevant frames

Crash log:
```
{self.crash_log}
```
Extracted information:"""
        with self.llm_api_manager.litellm_completion() as completion:  # pyright: ignore[reportUnknownVariableType]
            response = completion(
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
        response_message = response.choices[0].message.content  # pyright: ignore
        if isinstance(response_message, str):
            return response_message
        else:
            context["logger"].error(
                f"Unexpected response from Gemini: {response_message}"
            )
            return None
