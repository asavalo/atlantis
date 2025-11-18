import json
import logging
import os
import time
from typing import Awaitable, Callable

from fastapi import Request, Response
from openai.types.chat.chat_completion import ChatCompletion
from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, TELEMETRY_SDK_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.trace import SpanKind, Status, StatusCode
from starlette.concurrency import iterate_in_threadpool
from starlette.middleware.base import (
    _StreamingResponse,  # pyright: ignore[reportPrivateUsage]
)
from vllm.entrypoints.openai.protocol import ChatCompletionRequest

if os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL") == "grpc":
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
else:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter


# https://github.com/openlit/openlit/blob/main/sdk/python/src/openlit/semcov/__init__.py
class SemanticConvention:
    # General Attributes (OTel Semconv)
    SERVER_PORT = "server.port"
    SERVER_ADDRESS = "server.address"
    ERROR_TYPE = "error.type"

    # GenAI Metric Names (OTel Semconv)
    GEN_AI_CLIENT_TOKEN_USAGE = "gen_ai.client.token.usage"
    GEN_AI_CLIENT_OPERATION_DURATION = "gen_ai.client.operation.duration"
    GEN_AI_SERVER_REQUEST_DURATION = "gen_ai.server.request.duration"
    GEN_AI_SERVER_TBT = "gen_ai.server.time_per_output_token"
    GEN_AI_SERVER_TTFT = "gen_ai.server.time_to_first_token"

    # GenAI Event Names (OTel Semconv)
    GEN_AI_USER_MESSAGE = "gen_ai.user.message"
    GEN_AI_SYSTEM_MESSAGE = "gen_ai.system.message"
    GEN_AI_ASSISTANT_MESSAGE = "gen_ai.assistant.message"
    GEN_AI_TOOL_MESSAGE = "gen_ai.tools.message"
    GEN_AI_CHOICE = "gen_ai.choice"

    # GenAI Request Attributes (OTel Semconv)
    GEN_AI_OPERATION = "gen_ai.operation.name"
    GEN_AI_SYSTEM = "gen_ai.system"
    GEN_AI_OUTPUT_TYPE = "gen_ai.output.type"
    GEN_AI_ENDPOINT = "gen_ai.endpoint"
    GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
    GEN_AI_REQUEST_SEED = "gen_ai.request.seed"
    GEN_AI_REQUEST_ENCODING_FORMATS = "gen_ai.request.encoding_formats"
    GEN_AI_REQUEST_FREQUENCY_PENALTY = "gen_ai.request.frequency_penalty"
    GEN_AI_REQUEST_MAX_TOKENS = "gen_ai.request.max_tokens"
    GEN_AI_REQUEST_PRESENCE_PENALTY = "gen_ai.request.presence_penalty"
    GEN_AI_REQUEST_STOP_SEQUENCES = "gen_ai.request.stop_sequences"
    GEN_AI_REQUEST_TEMPERATURE = "gen_ai.request.temperature"
    GEN_AI_REQUEST_TOP_K = "gen_ai.request.top_k"
    GEN_AI_REQUEST_TOP_P = "gen_ai.request.top_p"

    # GenAI Response Attributes (OTel Semconv)
    GEN_AI_TOKEN_TYPE = "gen_ai.token.type"
    GEN_AI_RESPONSE_FINISH_REASON = "gen_ai.response.finish_reasons"
    GEN_AI_RESPONSE_ID = "gen_ai.response.id"
    GEN_AI_RESPONSE_MODEL = "gen_ai.response.model"
    GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
    GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
    GEN_AI_USAGE_REASONING_TOKENS = "gen_ai.usage.reasoning_tokens"
    GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
    GEN_AI_TOOL_NAME = "gen_ai.tool.name"
    GEN_AI_TOOL_ARGS = "gen_ai.tool.args"

    # GenAI Operation Types (OTel Semconv)
    GEN_AI_OPERATION_TYPE_CHAT = "chat"
    GEN_AI_OPERATION_TYPE_TOOLS = "execute_tool"
    GEN_AI_OPERATION_TYPE_EMBEDDING = "embeddings"
    GEN_AI_OPERATION_TYPE_IMAGE = "image"
    GEN_AI_OPERATION_TYPE_AUDIO = "audio"
    GEN_AI_OPERATION_TYPE_VECTORDB = "vectordb"
    GEN_AI_OPERATION_TYPE_FRAMEWORK = "framework"
    GEN_AI_OPERATION_TYPE_AGENT = "agent"
    GEN_AI_OPERATION_TYPE_CREATE_AGENT = "create_agent"
    GEN_AI_OPERATION_TYPE_EXECUTE_AGENT_TASK = "execute_task"

    # GenAI Output Types (OTel Semconv)
    GEN_AI_OUTPUT_TYPE_IMAGE = "image"
    GEN_AI_OUTPUT_TYPE_JSON = "json"
    GEN_AI_OUTPUT_TYPE_SPEECH = "speech"
    GEN_AI_OUTPUT_TYPE_TEXT = "text"

    # GenAI System Names (OTel Semconv)
    GEN_AI_SYSTEM_ANTHROPIC = "anthropic"
    GEN_AI_SYSTEM_AWS_BEDROCK = "aws.bedrock"
    GEN_AI_SYSTEM_AZURE_AI_INFERENCE = "az.ai.inference"
    GEN_AI_SYSTEM_AZURE_OPENAI = "az.ai.openai"
    GEN_AI_SYSTEM_COHERE = "cohere"
    GEN_AI_SYSTEM_DEEPSEEK = "deepseek"
    GEN_AI_SYSTEM_GEMINI = "gemini"
    GEN_AI_SYSTEM_GROQ = "groq"
    GEN_AI_SYSTEM_IBM_WATSON = "ibm.watson.ai"
    GEN_AI_SYSTEM_MISTRAL = "mistral_ai"
    GEN_AI_SYSTEM_OPENAI = "openai"
    GEN_AI_SYSTEM_PERPLEXITY = "perplexity"
    GEN_AI_SYSTEM_VERTEXAI = "vertex_ai"
    GEN_AI_SYSTEM_XAI = "xai"

    # GenAI OpenAI Attributes (OTel Semconv)
    GEN_AI_REQUEST_SERVICE_TIER = "gen_ai.request.service_tier"
    GEN_AI_RESPONSE_SERVICE_TIER = "gen_ai.response.service_tier"
    GEN_AI_RESPONSE_SYSTEM_FINGERPRINT = "gen_ai.response.system_fingerprint"

    # GenAI System Names (Extra)
    GEN_AI_SYSTEM_HUGGING_FACE = "huggingface"
    GEN_AI_SYSTEM_OLLAMA = "ollama"
    GEN_AI_SYSTEM_GPT4ALL = "gpt4all"
    GEN_AI_SYSTEM_ELEVENLABS = "elevenlabs"
    GEN_AI_SYSTEM_VLLM = "vLLM"
    GEN_AI_SYSTEM_GOOGLE_AI_STUDIO = "google.ai.studio"
    GEN_AI_SYSTEM_REKAAI = "rekaai"
    GEN_AI_SYSTEM_PREMAI = "premai"
    GEN_AI_SYSTEM_LANGCHAIN = "langchain"
    GEN_AI_SYSTEM_LLAMAINDEX = "llama_index"
    GEN_AI_SYSTEM_HAYSTACK = "haystack"
    GEN_AI_SYSTEM_EMBEDCHAIN = "embedchain"
    GEN_AI_SYSTEM_MEM0 = "mem0"
    GEN_AI_SYSTEM_LITELLM = "litellm"
    GEN_AI_SYSTEM_CREWAI = "crewai"
    GEN_AI_SYSTEM_AG2 = "ag2"
    GEN_AI_SYSTEM_MULTION = "multion"
    GEN_AI_SYSTEM_DYNAMIQ = "dynamiq"
    GEN_AI_SYSTEM_PHIDATA = "phidata"
    GEN_AI_SYSTEM_JULEP = "julep"
    GEN_AI_SYSTEM_AI21 = "ai21"
    GEN_AI_SYSTEM_CONTROLFLOW = "controlflow"
    GEN_AI_SYSTEM_ASSEMBLYAI = "assemblyai"
    GEN_AI_SYSTEM_CRAWL4AI = "crawl4ai"
    GEN_AI_SYSTEM_FIRECRAWL = "firecrawl"
    GEN_AI_SYSTEM_LETTA = "letta"
    GEN_AI_SYSTEM_TOGETHER = "together"

    # GenAI Request Attributes (Extra)
    GEN_AI_REQUEST_IS_STREAM = "gen_ai.request.is_stream"
    GEN_AI_REQUEST_USER = "gen_ai.request.user"
    GEN_AI_REQUEST_EMBEDDING_DIMENSION = "gen_ai.request.embedding_dimension"
    GEN_AI_REQUEST_TOOL_CHOICE = "gen_ai.request.tool_choice"
    GEN_AI_REQUEST_AUDIO_VOICE = "gen_ai.request.audio_voice"
    GEN_AI_REQUEST_AUDIO_RESPONSE_FORMAT = "gen_ai.request.audio_response_format"
    GEN_AI_REQUEST_AUDIO_SPEED = "gen_ai.request.audio_speed"
    GEN_AI_REQUEST_AUDIO_SETTINGS = "gen_ai.request.audio_settings"
    GEN_AI_REQUEST_AUDIO_DURATION = "gen_ai.request.audio_duration"
    GEN_AI_REQUEST_IMAGE_SIZE = "gen_ai.request.image_size"
    GEN_AI_REQUEST_IMAGE_QUALITY = "gen_ai.request.image_quality"
    GEN_AI_REQUEST_IMAGE_STYLE = "gen_ai.request.image_style"
    GEN_AI_HUB_OWNER = "gen_ai.hub.owner"
    GEN_AI_HUB_REPO = "gen_ai.hub.repo"
    GEN_AI_RETRIEVAL_SOURCE = "gen_ai.retrieval.source"
    GEN_AI_REQUESTS = "gen_ai.total.requests"
    GEN_AI_DATA_SOURCES = "gen_ai.data_source_count"
    GEN_AI_ENVIRONMENT = "gen_ai.environment"
    GEN_AI_APPLICATION_NAME = "gen_ai.application_name"
    GEN_AI_SDK_VERSION = "gen_ai.sdk.version"

    # GenAI Response Attributes (Extra)
    GEN_AI_USAGE_TOTAL_TOKENS = "gen_ai.usage.total_tokens"
    GEN_AI_USAGE_COST = "gen_ai.usage.cost"
    GEN_AI_RESPONSE_IMAGE = "gen_ai.response.image"
    GEN_AI_TOOL_CALLS = "gen_ai.response.tool_calls"

    # GenAI Content
    GEN_AI_CONTENT_PROMPT_EVENT = "gen_ai.content.prompt"
    GEN_AI_CONTENT_PROMPT = "gen_ai.prompt"
    GEN_AI_CONTENT_COMPLETION_EVENT = "gen_ai.content.completion"
    GEN_AI_CONTENT_COMPLETION = "gen_ai.completion"
    GEN_AI_CONTENT_REVISED_PROMPT = "gen_ai.content.revised_prompt"

    # GenAI Rag
    GEN_AI_RAG_MAX_SEGMENTS = "gen_ai.rag.max_segments"
    GEN_AI_RAG_STRATEGY = "gen_ai.rag.strategy"
    GEN_AI_RAG_SIMILARITY_THRESHOLD = "gen_ai.rag.similarity_threshold"
    GEN_AI_RAG_MAX_NEIGHBORS = "gen_ai.rag.max_neighbors"
    GEN_AI_RAG_DOCUMENTS_PATH = "gen_ai.rag.documents_path"
    GEN_AI_RAG_FILE_IDS = "gen_ai.rag.file_ids"

    # GenAI Evaluation Metrics
    GEN_AI_EVAL_CONTEXT_RELEVANCY = "gen_ai.eval.context_relevancy"
    GEN_AI_EVAL_ANSWER_RELEVANCY = "gen_ai.eval.answer_relevancy"
    GEN_AI_EVAL_GROUNDEDNESS = "gen_ai.eval.groundedness"

    # GenAI Request Attributes (OTel Semconv)
    GEN_AI_AGENT_ID = "gen_ai.agent.id"
    GEN_AI_AGENT_NAME = "gen_ai.agent.name"
    GEN_AI_AGENT_DESCRIPTION = "gen_ai.agent.description"

    GEN_AI_AGENT_TYPE = "gen_ai.agent.type"
    GEN_AI_AGENT_TASK_ID = "gen_ai.agent.task.id"
    GEN_AI_AGENT_ROLE = "gen_ai.agent.role"
    GEN_AI_AGENT_GOAL = "gen_ai.agent.goal"
    GEN_AI_AGENT_CONTEXT = "gen_ai.agent.context"
    GEN_AI_AGENT_ENABLE_CACHE = "gen_ai.agent.enable_cache"
    GEN_AI_AGENT_ENABLE_HISTORY = "gen_ai.agent.enable_history"
    GEN_AI_AGENT_ALLOW_DELEGATION = "gen_ai.agent.allow_delegation"
    GEN_AI_AGENT_ALLOW_CODE_EXECUTION = "gen_ai.agent.allow_code_execution"
    GEN_AI_AGENT_MAX_RETRY_LIMIT = "gen_ai.agent.max_retry_limit"
    GEN_AI_AGENT_TOOLS = "gen_ai.agent.tools"
    GEN_AI_AGENT_TOOL_RESULTS = "gen_ai.agent.tool_results"
    GEN_AI_AGENT_TASK = "gen_ai.agent.task"
    GEN_AI_AGENT_PARAMS = "gen_ai.agent.params"
    GEN_AI_AGENT_INSTRUCTIONS = "gen_ai.agent.instructions"
    GEN_AI_AGENT_STORAGE = "gen_ai.agent.storage"
    GEN_AI_AGENT_EXPECTED_OUTPUT = "gen_ai.agent.expected_output"
    GEN_AI_AGENT_ACTUAL_OUTPUT = "gen_ai.agent.actual_output"
    GEN_AI_AGENT_HUMAN_INPUT = "gen_ai.agent.human_input"
    GEN_AI_AGENT_SCHEMA = "gen_ai.agent.schema"
    GEN_AI_AGENT_TASK_ASSOCIATION = "gen_ai.agent.task_associations"
    GEN_AI_AGENT_BROWSE_URL = "gen_ai.agent.browse_url"
    GEN_AI_AGENT_STEP_COUNT = "gen_ai.agent.step_count"
    GEN_AI_AGENT_RESPONSE_TIME = "gen_ai.agent.response_time"
    GEN_AI_AGENT_STRATEGY = "gen_ai.agent.strategy"

    GEN_AI_AGENT_TYPE_BROWSER = "browser"


resource = Resource.create(
    attributes={
        SERVICE_NAME: os.getenv("OTEL_SERVICE_NAME", "openai-compatible-server"),
        TELEMETRY_SDK_NAME: "openai-compatible-server",
    }
)

trace.set_tracer_provider(TracerProvider(resource=resource))

if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
    span_exporter = OTLPSpanExporter()
    span_processor = BatchSpanProcessor(span_exporter)
else:
    span_processor = ConsoleSpanExporter()
    span_processor = SimpleSpanProcessor(span_processor)

trace.get_tracer_provider().add_span_processor(span_processor)  # type: ignore

tracer = trace.get_tracer(__name__)


async def with_opentelemetry(
    request: Request, call_next: Callable[[Request], Awaitable[_StreamingResponse]]
) -> Response:
    if request.url.path == "/v1/chat/completions":
        request_body = await request.body()
        chat_completion_request = ChatCompletionRequest.model_validate_json(
            request_body
        )

        with tracer.start_as_current_span(
            f"{SemanticConvention.GEN_AI_OPERATION_TYPE_CHAT} {chat_completion_request.model}",
            kind=SpanKind.CLIENT,
        ) as span:
            start_time = time.time()
            response = await call_next(request)
            end_time = time.time()
            response_body_list = [chunk async for chunk in response.body_iterator]
            response.body_iterator = iterate_in_threadpool(iter(response_body_list))
            response_body = b"".join(_bytes_from_stream(_) for _ in response_body_list)

            try:
                chat_completion_response = ChatCompletion.model_validate_json(
                    response_body
                )

                prompt = _string_from_request(chat_completion_request)
                span.set_attribute(TELEMETRY_SDK_NAME, "openai-compatible-server")
                span.set_attribute(
                    SemanticConvention.GEN_AI_OPERATION,
                    SemanticConvention.GEN_AI_OPERATION_TYPE_CHAT,
                )
                span.set_attribute(
                    SemanticConvention.GEN_AI_SYSTEM,
                    SemanticConvention.GEN_AI_SYSTEM_VLLM,
                )
                if chat_completion_request.model:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_MODEL,
                        chat_completion_request.model,
                    )
                if chat_completion_request.seed is not None:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_SEED,
                        chat_completion_request.seed,
                    )
                span.set_attribute(
                    SemanticConvention.SERVER_PORT, request.scope["server"][1]
                )
                span.set_attribute(
                    SemanticConvention.SERVER_ADDRESS, request.scope["server"][0]
                )
                if chat_completion_request.max_completion_tokens is not None:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_MAX_TOKENS,
                        chat_completion_request.max_completion_tokens,
                    )
                if chat_completion_request.stop is not None:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_STOP_SEQUENCES,
                        chat_completion_request.stop,
                    )
                if chat_completion_request.temperature is not None:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_TEMPERATURE,
                        chat_completion_request.temperature,
                    )
                if chat_completion_request.top_p is not None:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_TOP_P,
                        chat_completion_request.top_p,
                    )
                span.set_attribute(
                    SemanticConvention.GEN_AI_RESPONSE_ID, chat_completion_response.id
                )
                span.set_attribute(
                    SemanticConvention.GEN_AI_RESPONSE_MODEL,
                    chat_completion_response.model,
                )
                if chat_completion_response.usage:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_USAGE_INPUT_TOKENS,
                        chat_completion_response.usage.prompt_tokens,
                    )
                    span.set_attribute(
                        SemanticConvention.GEN_AI_USAGE_OUTPUT_TOKENS,
                        chat_completion_response.usage.completion_tokens,
                    )
                if chat_completion_request.user:
                    span.set_attribute(
                        SemanticConvention.GEN_AI_REQUEST_USER,
                        chat_completion_request.user,
                    )
                span.set_attribute(SemanticConvention.GEN_AI_REQUEST_IS_STREAM, False)
                span.set_attribute(
                    SemanticConvention.GEN_AI_SERVER_TTFT, end_time - start_time
                )
                span.add_event(
                    name=SemanticConvention.GEN_AI_CONTENT_PROMPT_EVENT,
                    attributes={
                        SemanticConvention.GEN_AI_CONTENT_PROMPT: prompt,
                    },
                )
                if chat_completion_request.n:
                    for i in range(chat_completion_request.n):
                        span.set_attribute(
                            SemanticConvention.GEN_AI_RESPONSE_FINISH_REASON,
                            [chat_completion_response.choices[i].finish_reason],
                        )

                        try:
                            completion_text = (
                                chat_completion_response.choices[i].message.content
                                or ""
                            )
                        except Exception:
                            completion_text = ""

                        span.add_event(
                            name=SemanticConvention.GEN_AI_CONTENT_COMPLETION_EVENT,
                            attributes={
                                SemanticConvention.GEN_AI_CONTENT_COMPLETION: completion_text,
                            },
                        )

                        if chat_completion_request.tools:
                            span.set_attribute(
                                SemanticConvention.GEN_AI_TOOL_CALLS,
                                str(
                                    chat_completion_response.choices[
                                        i
                                    ].message.tool_calls
                                ),
                            )

                        span.set_attribute(
                            SemanticConvention.GEN_AI_OUTPUT_TYPE, "text"
                        )
                span.set_status(Status(StatusCode.OK))
            except Exception as e:
                logging.exception(e)
            finally:
                return response
    else:
        return await call_next(request)


def _string_from_request(request: ChatCompletionRequest):
    return json.dumps(request.messages, indent=2)


def _bytes_from_stream(value: str | bytes | memoryview):
    match value:
        case str():
            return value.encode()
        case bytes():
            return value
        case memoryview():
            return value.tobytes()
        case bytearray():
            return value
