import os, json, requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
MODEL_NAME = os.environ.get("MODEL_NAME", "llama3.1:8b-instruct-q4_K_M")
# Allow overriding timeouts via env; default: 5s connect, 600s read
CONNECT_TO = float(os.environ.get("OLLAMA_CONNECT_TIMEOUT", "5"))
READ_TO    = float(os.environ.get("OLLAMA_READ_TIMEOUT", "600"))

def _headers():
    return {"Content-Type": "application/json"}

def chat(messages, stream=False, options=None, format=None, **kwargs):
    """
    Minimal Ollama /api/chat wrapper.
    messages: list of {"role","content"}
    options: dict of model params; we map num_predict/temperature if present
    stream: bool -> request streaming from Ollama
    format: "json" or None (Ollama will attempt JSON mode if supported)
    """
    url = f"{OLLAMA_URL}/api/chat"
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": bool(stream),
    }
    if format:
        payload["format"] = format
    if options:
        # map some common options names used by callers
        if "num_predict" in options:
            payload.setdefault("options", {})["num_predict"] = int(options["num_predict"])
        if "temperature" in options:
            payload.setdefault("options", {})["temperature"] = float(options["temperature"])

    try:
        r = requests.post(
            url,
            headers=_headers(),
            data=json.dumps(payload),
            timeout=(CONNECT_TO, READ_TO),
        )
        r.raise_for_status()
        # If streaming=false, body is the final object
        return r.json() if not stream else r.json()
    except requests.exceptions.ReadTimeout as e:
        raise RuntimeError(
            f"Ollama read timeout after {READ_TO}s at {url} (model={MODEL_NAME}). "
            f"Consider lowering context size or num_predict."
        ) from e
    except requests.exceptions.ConnectTimeout as e:
        raise RuntimeError(
            f"Ollama connect timeout after {CONNECT_TO}s at {url}. Is the ollama service reachable?"
        ) from e
    except requests.exceptions.HTTPError as e:
        # Surface Ollama error body to caller
        try:
            body = r.text
        except Exception:
            body = "<unavailable>"
        raise RuntimeError(
            f"Ollama HTTP {r.status_code} at {url}: {body[:400]}"
        ) from e
