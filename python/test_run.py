#!/usr/bin/env python3
"""
test_bedrock_run.py — Thorough Bedrock runtime smoke test.

Features
- Validates AWS creds via STS (prints Account + ARN).
- Optionally uses a named profile.
- Verifies region access and (best-effort) model availability.
- Provider-aware payloads for Titan & Anthropic; generic fallback for others.
- Supports non-stream and streaming invocations.
- Structured error handling with clear exit codes.
- Measures latency; optional raw JSON output.

Usage examples
  python3 test_bedrock_run.py --model-id amazon.titan-text-lite-v1 --prompt "Hello!"
  python3 test_bedrock_run.py --model-id anthropic.claude-3-haiku-20240307-v1:0 --prompt "Summarize S3."
  python3 test_bedrock_run.py --profile myprof --region us-east-1 --model-id amazon.titan-text-express-v1 --prompt "Write a limerick."
  python3 test_bedrock_run.py --stream --model-id anthropic.claude-3-haiku-20240307-v1:0 --prompt "List 3 facts."
  python3 test_bedrock_run.py --json --model-id openai.gpt-oss-120b-1:0 --prompt "Test generic path."
"""

import argparse
import json
import sys
import time
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError, EndpointConnectionError

EXIT_OK = 0
EXIT_NO_CREDS = 10
EXIT_PARTIAL_CREDS = 11
EXIT_CLIENT_ERR = 12
EXIT_ENDPOINT_ERR = 13
EXIT_OTHER_ERR = 19


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def get_session(profile: Optional[str]) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def validate_creds(session: boto3.Session, region: str) -> Dict[str, str]:
    sts = session.client("sts", region_name=region)
    ident = sts.get_caller_identity()
    return {"Account": ident["Account"], "Arn": ident["Arn"], "UserId": ident["UserId"]}


def list_foundation_models(session: boto3.Session, region: str) -> Optional[list]:
    """
    Best-effort: not all principals/regions allow this call.
    If denied, we just return None (non-fatal for our test).
    """
    try:
        bedrock = session.client("bedrock", region_name=region)
        # limit the noise: only return the first page
        resp = bedrock.list_foundation_models(
            byOutputModality="TEXT"  # keeps it quick & relevant
        )
        return resp.get("modelSummaries", [])
    except ClientError as e:
        # AccessDenied or Unsupported region ≠ fatal for runtime testing
        code = e.response.get("Error", {}).get("Code", "")
        log(f"[warn] Could not list foundation models ({code}). Continuing.")
        return None


def provider_from_model_id(model_id: str) -> str:
    """
    Very lightweight provider detection to choose payload/parse logic.
    """
    mid = model_id.lower()
    if mid.startswith("amazon.titan"):
        return "titan"
    if "anthropic" in mid or mid.startswith("anthropic."):
        return "anthropic"
    return "generic"


def build_request_body(provider: str, prompt: str, max_tokens: int, temperature: float) -> Dict[str, Any]:
    """
    Shape the request body for common providers.
    """
    if provider == "titan":
        return {
            "inputText": prompt,
            "textGenerationConfig": {
                "maxTokenCount": max_tokens,
                "temperature": temperature
            }
        }
    if provider == "anthropic":
        # Bedrock Anthropic Messages format
        return {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": prompt}]}
            ],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
    # Generic fallback — many providers accept something like this, but output parsing will be generic too.
    return {
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature
    }


def parse_response(provider: str, resp_json: Dict[str, Any]) -> str:
    """
    Extract plain text from known schemas; otherwise pretty-print JSON.
    """
    if provider == "titan":
        # Titan text returns: {"results":[{"outputText": "...", "tokenCount": {...}}], ...}
        try:
            return resp_json["results"][0]["outputText"]
        except Exception:
            return json.dumps(resp_json, indent=2)

    if provider == "anthropic":
        # Anthropic messages returns: {"content":[{"type":"text","text":"..."}], ...}
        try:
            parts = resp_json.get("content", [])
            texts = [p.get("text", "") for p in parts if p.get("type") == "text"]
            if texts:
                return "\n".join(t for t in texts if t)
            return json.dumps(resp_json, indent=2)
        except Exception:
            return json.dumps(resp_json, indent=2)

    # Generic: just JSON
    return json.dumps(resp_json, indent=2)


def invoke_non_stream(client, model_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    resp = client.invoke_model(
        modelId=model_id,
        body=json.dumps(body).encode("utf-8"),
        contentType="application/json",
        accept="application/json",
    )
    resp_body = resp["body"].read().decode("utf-8")
    return json.loads(resp_body)


def invoke_stream(client, model_id: str, body: Dict[str, Any]):
    """
    Yields text chunks (best-effort). Exact stream shape varies by provider.
    We try to parse payloads as JSON per event chunk, and print text if obvious.
    """
    stream = client.invoke_model_with_response_stream(
        modelId=model_id,
        body=json.dumps(body).encode("utf-8"),
        contentType="application/json",
        accept="application/json",
    )["body"]

    for event in stream:
        # Each event has 'chunk' with bytes; content varies by provider.
        if "chunk" not in event:
            continue
        data = event["chunk"]["bytes"].decode("utf-8")
        # Try JSON first; fallback to raw text
        try:
            j = json.loads(data)
            # Titan stream example emits {"outputText": "...", ...} fragments or similar.
            # Anthropic streamed messages emit delta-like objects.
            text = None
            if "outputText" in j:
                text = j["outputText"]
            elif "delta" in j:
                # anthropic deltas might look like {"delta":{"type":"text_delta","text":"..."}}
                delta = j["delta"]
                if isinstance(delta, dict) and "text" in delta:
                    text = delta["text"]
            elif "content" in j and isinstance(j["content"], list):
                # sometimes content arrays with text nodes appear
                fragments = [c.get("text", "") for c in j["content"] if c.get("type") == "text"]
                text = "".join(fragments)
            if text:
                yield text
            else:
                # If structure unknown, yield raw chunk (but keep it readable)
                yield ""
        except Exception:
            # Not JSON: just push raw
            yield data


def main():
    ap = argparse.ArgumentParser(description="Thorough Bedrock runtime test")
    ap.add_argument("--model-id", required=True, help="Bedrock model ID (e.g., amazon.titan-text-lite-v1)")
    ap.add_argument("--prompt", required=True, help="Prompt to send to the model")
    ap.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    ap.add_argument("--profile", default=None, help="AWS named profile to use")
    ap.add_argument("--max-tokens", type=int, default=512, help="Max tokens / length")
    ap.add_argument("--temperature", type=float, default=0.7, help="Sampling temperature")
    ap.add_argument("--stream", action="store_true", help="Use streaming API")
    ap.add_argument("--json", action="store_true", help="Print raw JSON response in addition to parsed text")
    ap.add_argument("--timeout", type=int, default=30, help="Socket read timeout (seconds)")
    ap.add_argument("--retries", type=int, default=3, help="Max retry attempts on throttling/5xx")
    args = ap.parse_args()

    # Configure robust retry/timeout behavior for botocore
    cfg = Config(
        retries={"max_attempts": max(1, args.retries), "mode": "standard"},
        read_timeout=max(5, args.timeout),
        connect_timeout=10,
    )

    try:
        session = get_session(args.profile)

        # 1) Creds smoke test
        log("[info] Validating credentials via STS…")
        ident = validate_creds(session, args.region)
        log(f"[ok] Account: {ident['Account']} | ARN: {ident['Arn']}")

        # 2) Optional model catalog peek (non-fatal if denied)
        log("[info] Checking (best-effort) model catalog visibility…")
        _models = list_foundation_models(session, args.region)
        if _models is not None:
            # Quick check if our model id looks present
            present = any(m.get("modelId") == args.model_id for m in _models)
            log(f"[ok] Model list accessible. Model present in list: {present}")
        else:
            log("[warn] Skipping model list verification (no access or unsupported).")

        # 3) Runtime invoke
        brt = session.client("bedrock-runtime", region_name=args.region, config=cfg)
        provider = provider_from_model_id(args.model_id)
        body = build_request_body(provider, args.prompt, args.max_tokens, args.temperature)

        log(f"[info] Invoking {args.model_id} (provider={provider}, stream={args.stream})…")
        t0 = time.perf_counter()

        if args.stream:
            # Stream and collect for a final summary
            collected = []
            try:
                for chunk in invoke_stream(brt, args.model_id, body):
                    if chunk:
                        collected.append(chunk)
                        # Print incrementally for live feel
                        print(chunk, end="", flush=True)
                print()  # newline after stream
            except ClientError as e:
                log(f"[error] Streaming invoke failed: {e}")
                sys.exit(EXIT_CLIENT_ERR)

            elapsed = (time.perf_counter() - t0) * 1000
            log(f"[ok] Stream completed in {elapsed:.0f} ms.")
            if args.json:
                log("[info] Raw stream output not retained as structured JSON (varies by provider).")
        else:
            try:
                resp_json = invoke_non_stream(brt, args.model_id, body)
            except ClientError as e:
                log(f"[error] Invoke failed: {e}")
                sys.exit(EXIT_CLIENT_ERR)

            elapsed = (time.perf_counter() - t0) * 1000
            parsed = parse_response(provider, resp_json)

            print("----- Parsed Output -----")
            print(parsed)
            print("-------------------------")
            log(f"[ok] Non-stream invoke completed in {elapsed:.0f} ms.")

            if args.json:
                print("----- Raw JSON -----")
                print(json.dumps(resp_json, indent=2))
                print("--------------------")

        sys.exit(EXIT_OK)

    except NoCredentialsError:
        log("[fatal] No AWS credentials found. Configure with env vars or ~/.aws/credentials.")
        sys.exit(EXIT_NO_CREDS)
    except PartialCredentialsError:
        log("[fatal] Partial/incomplete AWS credentials.")
        sys.exit(EXIT_PARTIAL_CREDS)
    except EndpointConnectionError as e:
        log(f"[fatal] Could not reach endpoint: {e}")
        sys.exit(EXIT_ENDPOINT_ERR)
    except ClientError as e:
        log(f"[fatal] AWS ClientError: {e}")
        sys.exit(EXIT_CLIENT_ERR)
    except KeyboardInterrupt:
        log("[info] Interrupted.")
        sys.exit(EXIT_OTHER_ERR)
    except Exception as e:
        log(f"[fatal] Unexpected error: {e}")
        sys.exit(EXIT_OTHER_ERR)


if __name__ == "__main__":
    main()
