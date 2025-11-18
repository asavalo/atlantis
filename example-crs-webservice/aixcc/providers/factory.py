import os
from . import ollama_client

PROVIDER = os.getenv("PROVIDER", "ollama").lower()

def chat(messages, **kwargs):
    if PROVIDER == "ollama":
        return ollama_client.chat(messages, **kwargs)
    raise RuntimeError(f"Unknown PROVIDER={PROVIDER}")

def generate(prompt, **kwargs):
    if PROVIDER == "ollama":
        return ollama_client.generate(prompt, **kwargs)
    raise RuntimeError(f"Unknown PROVIDER={PROVIDER}")

def embeddings(texts):
    if PROVIDER == "ollama":
        return ollama_client.embeddings(texts)
    raise RuntimeError(f"Unknown PROVIDER={PROVIDER}")

def healthcheck():
    if PROVIDER == "ollama":
        return ollama_client.healthcheck()
    return False