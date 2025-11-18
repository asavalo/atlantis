from typing import cast

from langchain_community.chat_models import ChatLiteLLM
from pydantic import BaseModel, Field
from python_llm.api.actors import LlmApiManager

from crete.framework.patch_scorer.contexts import PatchScoringContext
from crete.framework.patch_scorer.functions import source_and_patched_declarations
from crete.framework.patch_scorer.protocols import PatchScorerProtocol


class _DescriptionResponse(BaseModel):
    description: str = Field(..., description="One sentence description of the code")


class _ScoreResponse(BaseModel):
    reasoning: str = Field(..., description="The reasoning behind the score")
    score: float = Field(
        ...,
        description="The score indicating if the snippets are functionally equivalent between 0.0 and 1.0",
    )


class DescriptionPatchScorer(PatchScorerProtocol):
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
        description_chat_model = cast(
            ChatLiteLLM,
            chat_model.with_structured_output(  # pyright: ignore[reportUnknownMemberType]
                _DescriptionResponse
            ),
        )

        source_descriptions = [
            cast(
                _DescriptionResponse,
                description_chat_model.invoke(
                    f"Describe the following code in a one sentence: {declaration}"
                ),
            ).description
            for declaration in source_declarations
            if declaration
        ]

        context["logger"].info(f"Source descriptions:\n{source_descriptions}")

        patched_descriptions = [
            cast(
                _DescriptionResponse,
                description_chat_model.invoke(
                    f"Describe the following in a one sentence: {declaration}"
                ),
            ).description
            for declaration in patched_declarations
            if declaration
        ]

        context["logger"].info(f"Patched descriptions:\n{patched_descriptions}")

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
                f"# Compare the following two code descriptions (A and B) into 0.0 to 1.0 score.\n\n##A\n{source_descriptions}\n\n#B\n{patched_descriptions}"
            ),
        )

        return response.score
