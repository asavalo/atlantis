from typing import cast

from langchain_community.chat_models import ChatLiteLLM
from pydantic import BaseModel, Field
from python_llm.api.actors import LlmApiManager

from crete.framework.patch_scorer.contexts import PatchScoringContext
from crete.framework.patch_scorer.functions import source_and_patched_declarations
from crete.framework.patch_scorer.protocols import PatchScorerProtocol


class _PseudoCodeResponse(BaseModel):
    pseudo_code: str = Field(..., description="The summarized pseudo code")


class _ScoreResponse(BaseModel):
    reasoning: str = Field(..., description="The reasoning behind the score")
    score: float = Field(
        ...,
        description="The score indicating if the snippets are functionally equivalent between 0.0 and 1.0",
    )


class PseudoCodePatchScorer(PatchScorerProtocol):
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        super().__init__()

        self._llm_api_manager = llm_api_manager

    def score(self, context: PatchScoringContext, diff: str) -> float:
        affected_declarations = list(source_and_patched_declarations(context, diff))

        source_declarations = [source for source, _ in affected_declarations if source]
        patched_declarations = [
            patched for _, patched in affected_declarations if patched
        ]

        chat_model = self._llm_api_manager.langchain_litellm()
        pseudo_code_chat_model = cast(
            ChatLiteLLM,
            chat_model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                _PseudoCodeResponse
            ),
        )

        source_pseudo_code = [
            cast(
                _PseudoCodeResponse,
                pseudo_code_chat_model.invoke(
                    f"Summarize the following code in short pseudo code: {declaration}"
                ),
            ).pseudo_code
            for declaration in source_declarations
            if declaration
        ]

        context["logger"].info(f"Source pseudo codes:\n{source_pseudo_code}")

        patched_pseudo_code = [
            cast(
                _PseudoCodeResponse,
                pseudo_code_chat_model.invoke(
                    f"Summarize the following in short pseudo code: {declaration}"
                ),
            ).pseudo_code
            for declaration in patched_declarations
            if declaration
        ]

        context["logger"].info(f"Patched pseudo codes:\n{patched_pseudo_code}")

        chat_model = self._llm_api_manager.langchain_litellm()
        score_chat_model = cast(
            ChatLiteLLM,
            chat_model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                _ScoreResponse
            ),
        )

        response = cast(
            _ScoreResponse,
            score_chat_model.invoke(
                f"# Compare the following two pseudo code snippets (A and B) into score.\n\n##A\n{source_pseudo_code}\n\n#B\n{patched_pseudo_code}"
            ),
        )

        return response.score
