import os

from crete.commons.tracing import PhoenixTracer
from openinference.instrumentation.langchain import LangChainInstrumentor
from openinference.instrumentation.litellm import LiteLLMInstrumentor
from pytest_mock import MockerFixture


def test_setup_from_environment_true(mocker: MockerFixture) -> None:
    mocker.patch.dict(os.environ, {"PHOENIX_INSTRUMENT_LANGCHAIN": "true"})
    mocker.patch.dict(os.environ, {"PHOENIX_INSTRUMENT_LITELLM": "true"})

    # Ensure the function can be called multiple times without side effects
    PhoenixTracer.setup_from_environment()
    assert PhoenixTracer.tracer_provider is not None
    PhoenixTracer.setup_from_environment()

    # Check LangChain is instrumented
    assert LiteLLMInstrumentor().is_instrumented_by_opentelemetry
    assert LangChainInstrumentor().is_instrumented_by_opentelemetry

    # Unset the tracing
    PhoenixTracer.unset()


def test_setup_from_environment_false(mocker: MockerFixture) -> None:
    mocker.patch.dict(os.environ, {"PHOENIX_INSTRUMENT_LANGCHAIN": "false"})
    mocker.patch.dict(os.environ, {"PHOENIX_INSTRUMENT_LITELLM": "false"})

    PhoenixTracer.setup_from_environment()

    # Check LangChain is not instrumented
    assert not LangChainInstrumentor().is_instrumented_by_opentelemetry
    assert not LiteLLMInstrumentor().is_instrumented_by_opentelemetry


def test_unset(mocker: MockerFixture) -> None:
    """Test that the LangChain tracing is correctly uninstrumented"""
    mocker.patch.dict(os.environ, {"PHOENIX_INSTRUMENT_LANGCHAIN": "true"})
    mocker.patch.dict(os.environ, {"PHOENIX_INSTRUMENT_LITELLM": "true"})

    PhoenixTracer.setup_from_environment()
    assert LangChainInstrumentor().is_instrumented_by_opentelemetry
    assert LiteLLMInstrumentor().is_instrumented_by_opentelemetry

    PhoenixTracer.unset()
    assert not LangChainInstrumentor().is_instrumented_by_opentelemetry
    assert not LiteLLMInstrumentor().is_instrumented_by_opentelemetry
