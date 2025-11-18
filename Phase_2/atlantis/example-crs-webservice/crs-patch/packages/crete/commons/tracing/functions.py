import os

from openinference.instrumentation import TracerProvider


class PhoenixTracer:
    tracer_provider: TracerProvider | None = None

    @classmethod
    def setup_from_environment(cls) -> None:
        instrument_env_vars = {
            "langchain": os.getenv("PHOENIX_INSTRUMENT_LANGCHAIN", ""),
            "litellm": os.getenv("PHOENIX_INSTRUMENT_LITELLM", ""),
        }
        if all(v in ("", "false") for v in instrument_env_vars.values()):
            return

        if cls.tracer_provider is None:
            from phoenix.otel import register

            endpoint = os.getenv("PHOENIX_COLLECTOR_ENDPOINT", "")
            if endpoint == "":
                endpoint = None

            cls.tracer_provider = register(endpoint=endpoint)

        if instrument_env_vars["langchain"] == "true":
            from openinference.instrumentation.langchain import LangChainInstrumentor

            LangChainInstrumentor().instrument(tracer_provider=cls.tracer_provider)

        if instrument_env_vars["litellm"] == "true":
            from openinference.instrumentation.litellm import LiteLLMInstrumentor

            LiteLLMInstrumentor().instrument(tracer_provider=cls.tracer_provider)

    @classmethod
    def unset(cls) -> None:
        from openinference.instrumentation.langchain import LangChainInstrumentor
        from openinference.instrumentation.litellm import LiteLLMInstrumentor

        LangChainInstrumentor().uninstrument()
        LiteLLMInstrumentor().uninstrument()
