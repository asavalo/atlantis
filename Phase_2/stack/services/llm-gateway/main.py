from fastapi import FastAPI
from pydantic import BaseModel
import httpx, os

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b")

app = FastAPI(title="LLM Gateway")

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    temperature: float | None = 0.2
    max_tokens: int | None = 2048
    stream: bool | None = False

@app.post("/v1/chat/completions")
async def chat(req: ChatRequest):
    payload = {
        "model": MODEL,
        "messages": [{"role": m.role, "content": m.content} for m in req.messages],
        "options": {"temperature": req.temperature},
        "stream": False
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()

    content = ""
    if isinstance(data, dict):
        if "message" in data and "content" in data["message"]:
            content = data["message"]["content"]
        else:
            content = data.get("response", "")

    return {
        "id": "ollama-chat",
        "object": "chat.completion",
        "choices": [{
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
            "index": 0
        }]
    }
