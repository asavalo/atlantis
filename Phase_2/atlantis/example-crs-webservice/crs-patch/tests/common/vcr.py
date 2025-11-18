# As vcr-langchain is not compatible with pyrigt, we need to disable the type checking.
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from typing import Any, Callable, Dict, Literal, override

import litellm
from haystack import Document
from sweagent.environment.swe_env import SWEEnv
from vcr.cassette import Cassette
from vcr_langchain.generic import GenericPatch, lookup
from vcr_langchain.patch import add_patchers

from crete.atoms.action import Action
from crete.atoms.detection import Detection
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.services.oss_fuzz import OssFuzzEnvironment
from crete.framework.evaluator.contexts import EvaluatingContext
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.retriever.contexts import RetrievalContext
from crete.framework.retriever.services.block_statement import BlockStatementRetriever
from tests.common.utils import make_portable


# This is a workaround to avoid the issue if the messages contain
# system-dependent directories. This should be removed once we have a better solution.
class LiteLLMCompletionPatch(GenericPatch):
    def __init__(self, cassette: Cassette):
        super().__init__(cassette, litellm, "completion")

    @override
    def get_same_signature_override(self) -> Callable[..., Any]:
        def _completion(**kwargs: Dict[str, Any]) -> Any:
            return self.generic_override(og_self=None, **kwargs)

        return _completion

    @override
    def filter_kwargs(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        # Remove all system-dependent directories from messages to make tests portable
        for message in kwargs["messages"]:
            message["content"] = make_portable(message["content"])

        return super().filter_kwargs(kwargs)


class BlockStatementRetrieverPatch(GenericPatch):
    def __init__(self, cassette: Cassette):
        super().__init__(
            cassette, BlockStatementRetriever, "retrieve", ["context", "detection"]
        )

    def get_same_signature_override(self) -> Callable[..., Any]:
        def retrieve(
            og_self: BlockStatementRetriever,
            context: RetrievalContext,
            detection: Detection,
            text: str = "",
        ) -> list[Document]:
            return self.generic_override(
                og_self, context=context, detection=detection, text=text
            )

        return retrieve


class SWEEnvPatch(GenericPatch):
    def __init__(self, cassette: Cassette):
        super().__init__(cassette, SWEEnv, "communicate")

    @override
    def get_generic_override_fn(self) -> Callable[..., Any]:
        def fn_override(og_self: Any, **kwargs: str) -> Any:
            # Unlike existing implementation, we always call the original function.
            # This is because the function can raise an exception.
            # Moreover, there are some functions that are not supported by the new implementation.
            request = self.get_request(og_self, kwargs)
            cached_response = lookup(self.cassette, request)
            new_response = self.og_fn(og_self, **kwargs)

            if cached_response is not None:
                return cached_response
            self.cassette.append(request, new_response)
            return new_response

        return fn_override

    def get_same_signature_override(self) -> Callable[..., Any]:
        def communicate(
            og_self: SWEEnv,
            input: str,
            timeout: int = 25,
            *,
            check: Literal["warn", "ignore", "raise"] = "ignore",
            error_msg: str = "Command failed",
        ) -> str:
            before_request = self.cassette._before_record_request  # type: ignore
            self.cassette._before_record_request = lambda request: None  # type: ignore
            response = self.generic_override(
                og_self,
                input=input,
                timeout=timeout,
                check=check,
                error_msg=error_msg,
            )
            self.cassette._before_record_request = before_request  # type: ignore
            return response

        return communicate


class OssFuzzEnvironmentPatch(GenericPatch):
    def __init__(self, cassette: Cassette):
        super().__init__(
            cassette,
            OssFuzzEnvironment,
            "_run_pov",
            ["context"],
        )

    def get_same_signature_override(self) -> Callable[..., Any]:
        def run_pov(
            og_self: OssFuzzEnvironment,
            context: EnvironmentContext,
            blob: bytes,
            harness_name: str,
        ) -> tuple[str, str, bool]:
            return self.generic_override(
                og_self,
                context=context,
                blob=blob,
                harness_name=harness_name,
            )

        return run_pov


class MockEvaluatorPatch(GenericPatch):
    def __init__(self, cassette: Cassette):
        super().__init__(
            cassette,
            MockEvaluator,
            "evaluate",
            ["context"],
        )

    def get_same_signature_override(self) -> Callable[..., Any]:
        def evaluate(
            og_self: MockEvaluator,
            context: EvaluatingContext,
            diff: bytes,
            detection: Detection,
        ) -> Action:
            return self.generic_override(
                og_self, context=context, diff=diff, detection=detection
            )

        return evaluate


def install_patchers():
    add_patchers(
        BlockStatementRetrieverPatch,
        SWEEnvPatch,
        OssFuzzEnvironmentPatch,
        MockEvaluatorPatch,
        # LiteLLMCompletionPatch,
    )
