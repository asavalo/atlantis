import json

from litellm.types.utils import Choices, Message, ModelResponse
from pydantic import BaseModel

from python_llm.api.actors import LlmApiManager

from ..contexts import PatchScoringContext
from ..protocols import PatchScorerProtocol


class _Response(BaseModel):
    reasoning: str
    score: float


class OpenAIPatchScorer(PatchScorerProtocol):
    def __init__(
        self,
        llm_api_manager: LlmApiManager,
    ) -> None:
        super().__init__()
        self.llm_api_manager = llm_api_manager

    def score(self, context: PatchScoringContext, diff: str) -> float:
        with self.llm_api_manager.litellm_completion() as completion:  # pyright: ignore[reportUnknownVariableType]
            response = completion(
                messages=[
                    {
                        "role": "system",
                        "content": 'You are an expert programmer. Your task is to analyze two given code snippets and compare their functionality. Determine if they are functionally equivalent and explain your reasoning. Return the output as a JSON string only (without backticks) with the following format: {"reasoning": "<string explaining the comparison>", "score": <score indicating if the snippets are functionally equivalent between 0.0 and 1.0>}.',
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "diff": """@@ -1,2 +1,2 @@
-def add_numbers(a, b):
-    return a + b
+def add_numbers(x, y):
+    return x + y"""
                            }
                        ),
                    },
                    {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "reasoning": "Both snippets define a function that takes two parameters and returns their sum. The parameter names are different (`a`, `b` vs. `x`, `y`), but this does not affect functionality.",
                                "score": 1.0,
                            }
                        ),
                    },
                    {
                        "role": "user",
                        "content": json.dumps({"diff": diff}),
                    },
                ],
            )

        assert isinstance(response, ModelResponse), "Unreachable code"
        assert isinstance(response.choices[0], Choices), "Failed to get choices."
        assert isinstance(response.choices[0].message, Message), (
            "Failed to get message."
        )

        response_message = response.choices[0].message.content
        assert isinstance(response_message, str), "Failed to get message content."

        return _Response.model_validate_json(response_message).score
