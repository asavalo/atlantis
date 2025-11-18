import os, json, traceback, logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from aixcc.providers.ollama_client import chat

logging.basicConfig(level=os.environ.get("LOG_LEVEL","INFO"))
log = logging.getLogger("atlantis-webservice")

app = FastAPI()

@app.get("/healthz")
async def healthz():
    return {"ok": True, "llm": True}

@app.post("/v1/crs/run")
async def run_crs(req: Request):
    try:
        body = await req.json()
    except Exception:
        body = {}

    messages = body.get("messages") or []
    prompt = body.get("prompt")
    if prompt and not messages:
        messages = [{"role": "user", "content": prompt}]

    # Pass through knob from client if present; keep defaults small to avoid timeouts
    llm_opts = {
        "options": {
            "temperature": float(body.get("llm_temperature", 0.0)),
            "num_predict": int(body.get("llm_max_tokens", 512)),
        },
        # when set and supported, forces JSON-shaped output; harmless otherwise
        "format": body.get("format") or None,
        "stream": bool(body.get("stream", True)),
    }

    # Minimal guardrail so plain-English prompts don't kill us:
    if not messages:
        messages = [{"role":"user","content":"Analyze the provided context for security issues."}]

    try:
        out = chat(messages, **llm_opts)  # may be generator if stream=True
        # If streaming, return as-is (your caller is responsible for reading)
        if llm_opts.get("stream"):
            # FastAPI expects a full response; for simplicity, buffer once here
            if hasattr(out, "__iter__") and not isinstance(out, (dict, list, str)):
                chunks = []
                for ch in out:
                    try:
                        chunks.append(ch)
                    except Exception:
                        break
                return JSONResponse(chunks)
            return JSONResponse(out)
        else:
            return JSONResponse(out)
    except Exception as e:
        tb = traceback.format_exc()
        log.error("run_crs failed: %s\n%s", e, tb)
        # Surface the error to the client so you can see what failed
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "type": e.__class__.__name__,
                "trace": tb.splitlines()[-10:],  # last frames summary
            },
        )
