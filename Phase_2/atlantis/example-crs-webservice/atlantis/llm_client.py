import os, httpx, asyncio

class LLMClientBase:
    async def achat(self, messages: list[dict], temperature: float = 0.2, max_tokens: int = 2048) -> str:
        raise NotImplementedError
    def chat(self, messages: list[dict], temperature: float = 0.2, max_tokens: int = 2048) -> str:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.achat(messages, temperature, max_tokens))

class LLMClientOllamaGateway(LLMClientBase):
    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = base_url or os.getenv("LLM_GATEWAY_URL", "http://llm-gateway:8080")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3:8b")

    async def achat(self, messages: list[dict], temperature: float = 0.2, max_tokens: int = 2048) -> str:
        payload = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(f"{self.base_url}/v1/chat/completions", json=payload)
            r.raise_for_status()
            data = r.json()
        return data["choices"][0]["message"]["content"]

def get_llm() -> LLMClientBase:
    provider = os.getenv("LLM_PROVIDER", "ollama")
    if provider == "ollama":
        return LLMClientOllamaGateway()
    return LLMClientOllamaGateway()
