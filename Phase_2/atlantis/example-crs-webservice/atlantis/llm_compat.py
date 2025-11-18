# Provides functions that look/feel like openai.ChatCompletion(.create)
# so we can replace calls automatically and still return familiar shapes.
import asyncio
from dataclasses import dataclass
from typing import Any, List, Dict
from .llm_client import get_llm

@dataclass
class _Message:
    role: str
    content: str

@dataclass
class _Choice:
    index: int
    message: _Message
    finish_reason: str = "stop"

@dataclass
class _Resp:
    id: str
    object: str
    choices: List[_Choice]

async def a_chat_completions_create(*, model: str | None = None, messages: List[Dict[str, Any]] | None = None, **kwargs) -> _Resp:
    llm = get_llm()
    text = await llm.achat(messages or [], temperature=kwargs.get("temperature", 0.2), max_tokens=kwargs.get("max_tokens", 2048))
    return _Resp(
        id="compat-chat",
        object="chat.completion",
        choices=[_Choice(index=0, message=_Message(role="assistant", content=text))]
    )

def chat_completions_create(*, model: str | None = None, messages: List[Dict[str, Any]] | None = None, **kwargs) -> _Resp:
    # Sync wrapper for code paths that aren't async
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(a_chat_completions_create(model=model, messages=messages, **kwargs))
