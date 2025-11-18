#!/usr/bin/env bash
set -euo pipefail

# Where you run this script (Atlantis webservice root)
ROOT="$(pwd)"

echo "==> Creating adapter modules (atlantis/llm_client.py, atlantis/llm_compat.py)…"
mkdir -p "$ROOT/atlantis"

# --- Adapter 1: LLM client that talks to the gateway (Ollama) ---
cat > "$ROOT/atlantis/llm_client.py" <<'PY'
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
PY

# --- Adapter 2: A small "compat" layer that mimics OpenAI responses ---
cat > "$ROOT/atlantis/llm_compat.py" <<'PY'
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
PY

echo "==> Committing adapters so we can safely revert if needed (requires git repo)…"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git add atlantis/llm_client.py atlantis/llm_compat.py
  git commit -m "chore(llm): add gateway adapter + compat wrappers" || true
else
  echo "(!) Not a git repo — continuing without commit."
fi

echo "==> Running codemod to replace OpenAI/Azure/LangChain chat calls…"

###CODEMOD BLOCK
python - <<'PY'
import os, re, sys, io

ROOT = os.getcwd()
TARGETS = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    # skip typical junk dirs
    if any(p in dirpath for p in ('.git', '__pycache__', '.venv', 'venv', '.mypy_cache', '.pytest_cache')):
        continue
    for f in filenames:
        if not f.endswith('.py'):
            continue
        path = os.path.join(dirpath, f)
        # only process real files (skip dirs, sockets, fifos, broken symlinks)
        if not os.path.isfile(path):
            continue
        if os.path.islink(path):
            try:
                real = os.path.realpath(path)
                if not os.path.isfile(real):
                    continue
            except Exception:
                continue
        TARGETS.append(path)

# Patterns we replace
A_AZURE  = re.compile(r'await\s+[A-Za-z0-9_\.]+\s*\.chat\s*\.completions\s*\.create\s*\(')
A_OPENAI = re.compile(r'await\s+openai\s*\.\s*ChatCompletion\s*\.create\s*\(')
S_AZURE  = re.compile(r'(?<!await\s)(?<!async\s)[A-Za-z0-9_\.]+\s*\.chat\s*\.completions\s*\.create\s*\(')
S_OPENAI = re.compile(r'(?<!await\s)(?<!async\s)openai\s*\.\s*ChatCompletion\s*\.create\s*\(')

def ensure_import(src: str) -> str:
    line = 'from atlantis.llm_compat import a_chat_completions_create, chat_completions_create\n'
    if line in src:
        return src
    lines = src.splitlines(True)
    insert_at = 0
    for i, L in enumerate(lines[:50]):
        if L.startswith('from ') or L.startswith('import '):
            insert_at = i + 1
    lines.insert(insert_at, line)
    return ''.join(lines)

def replace_calls(src: str) -> str:
    src = A_AZURE.sub('await a_chat_completions_create(', src)
    src = A_OPENAI.sub('await a_chat_completions_create(', src)
    src = S_AZURE.sub('chat_completions_create(', src)
    src = S_OPENAI.sub('chat_completions_create(', src)
    return src

PREF_ENCODINGS = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']

changed = 0
skipped = []
for path in TARGETS:
    # try multiple decoders; if all fail, skip file
    src = None
    used_enc = None
    for enc in PREF_ENCODINGS:
        try:
            with io.open(path, 'r', encoding=enc) as f:
                src = f.read()
            used_enc = enc
            break
        except (UnicodeDecodeError, FileNotFoundError, PermissionError, OSError):
            continue
    if src is None:
        skipped.append(path)
        continue

    new = replace_calls(src)
    if new != src:
        new = ensure_import(new)
        try:
            with io.open(path, 'w', encoding=used_enc) as f:
                f.write(new)
            changed += 1
            print(f"patched: {os.path.relpath(path, ROOT)} (enc={used_enc})")
        except (PermissionError, OSError) as e:
            skipped.append(path)

print(f"Done. Files changed: {changed}")
if skipped:
    print("Skipped (unreadable/unwritable):")
    for s in skipped:
        print(" -", os.path.relpath(s, ROOT))
PY

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git add -A
  git commit -m "codemod(llm): replace ChatCompletion/chat.completions.create with gateway compat" || true
fi

echo "==> All set."
echo "Next steps:"
echo "  1) Ensure Atlantis image has httpx installed (in requirements.txt)."
echo "  2) Rebuild and run the atlantis service."
echo "     docker-compose build atlantis && docker-compose up -d atlantis"
echo "  3) Test from inside the container:"
cat <<'TEST'
docker-compose exec atlantis python - <<'PY'
from atlantis.llm_compat import a_chat_completions_create, chat_completions_create
import asyncio
async def go():
    r = await a_chat_completions_create(messages=[{"role":"user","content":"Reply with the word OK"}])
    print("ASYNC:", r.choices[0].message.content)
    r2 = chat_completions_create(messages=[{"role":"user","content":"Say hi"}])
    print("SYNC :", r2.choices[0].message.content[:80])
asyncio.run(go())
PY
TEST
