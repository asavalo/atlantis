#!/usr/bin/env bash
# Run the Team-Atlanta "crs-multilang" module inside your Docker Atlantis stack.

set -Eeuo pipefail

TARGET="${1:-}"
OUT="${2:-$(pwd)/multilang_findings.json}"

[[ -n "$TARGET" ]] || { echo "Usage: $0 <TARGET_PATH> [OUTPUT_JSON]"; exit 2; }
[[ -e "$TARGET" ]] || { echo "ERROR: TARGET does not exist: $TARGET" >&2; exit 2; }

# Check for Docker Compose version
DOCKER_COMPOSE_CMD="docker compose"  # Default V2
if ! command -v "$DOCKER_COMPOSE_CMD" &>/dev/null; then
  echo "ERROR: Docker Compose V2 not found. Trying V1..."
  DOCKER_COMPOSE_CMD="docker-compose"
fi

: "${ENDPOINT:=http://127.0.0.1:8000/v1/crs/run}"
: "${TIMEOUT:=1800}"
: "${LLM_MAX_TOKENS:=900}"
: "${LLM_TEMPERATURE:=0}"
: "${SHOW_LOGS:=0}"

WORK="$(mktemp -d)"
LOGDIR="$WORK/logs"
mkdir -p "$LOGDIR"
echo "WORKDIR: $WORK"

# 1) Bring containers up & basic health
echo "==> Ensuring containers are up"
$DOCKER_COMPOSE_CMD up -d >/dev/null 2>&1 || true

echo "==> docker-compose ps"
$DOCKER_COMPOSE_CMD ps || true

echo "==> Health check: ${ENDPOINT%/v1/crs/run}/healthz"
for i in {1..60}; do
  if curl -sf "${ENDPOINT%/v1/crs/run}/healthz" >/dev/null 2>&1; then
    echo "OK webservice healthy"
    break
  fi
  sleep 1
  if [[ $i -eq 60 ]]; then
    echo "ERROR: webservice not healthy" >&2
    exit 3
  fi
done

# 2) Optional live logs
if [[ "$SHOW_LOGS" == "1" ]]; then
  { docker-compose logs -f --tail=0 atlantis-webservice | tee "$LOGDIR/webservice.log" & echo $! > "$WORK/.logpids"; } 2>/dev/null || true
  { docker-compose logs -f --tail=0 ollama              | tee "$LOGDIR/ollama.log"      & echo $! >> "$WORK/.logpids"; } 2>/dev/null || true
  trap '[[ -f "$WORK/.logpids" ]] && while read -r p; do kill "$p" 2>/dev/null || true; done < "$WORK/.logpids"' EXIT
fi

# 3) Show Atlantis modules + Ollama models
echo "==> Atlantis modules in use + env"
docker exec -i atlantis-webservice python - <<'PY' || true
import importlib, os, json
mods = ["aixcc.auth","aixcc.providers.factory","aixcc.providers.ollama_client"]
info = {"modules":{}, "env":{}}
for m in mods:
    try:
        mod = importlib.import_module(m)
        info["modules"][m] = getattr(mod,"__file__","<no-file>")
    except Exception as e:
        info["modules"][m] = f"<IMPORT-ERROR: {e}>"
for k in ["OLLAMA_URL","MODEL_NAME","OLLAMA_READ_TIMEOUT","OLLAMA_CONNECT_TIMEOUT"]:
    info["env"][k] = os.environ.get(k,"<unset>")
print(json.dumps(info, indent=2))
PY

echo "==> Ollama models"
docker exec -i ollama ollama list || true

# 4) Ensure /app/crs-multilang exists and try to find a runnable Python entrypoint
echo "==> Checking /app/crs-multilang in container"
if ! docker exec -i atlantis-webservice /bin/sh -lc 'test -d /app/crs-multilang'; then
  echo "WARN: /app/crs-multilang not found in container; will use API fallback"
  ENTRY=""
else
  echo "OK: /app/crs-multilang exists"
  ENTRY="$(docker exec -i atlantis-webservice /bin/sh -lc \
    'set -e; for n in main.py cli.py run.py __main__.py; do
       p=$(busybox find /app/crs-multilang -type f -name "$n" | head -n 1)
       if [ -n "$p" ]; then echo "$p"; break; fi
     done' || true)"
  if [[ -n "$ENTRY" ]]; then
    echo "Discovered entrypoint: $ENTRY"
  else
    echo "WARN: No obvious Python entrypoint found; will use API fallback"
  fi
fi

# Continue with the rest of the script...

# 5) Mount target into the container path /workspace/target for local runs
HOST_ABS="$(readlink -f "$TARGET")"
docker run --rm -v "$HOST_ABS":/target busybox sh -c 'ls -ld /target' >/dev/null 2>&1 || {
  echo "ERROR: cannot mount target path (check path/permissions): $HOST_ABS" >&2
  exit 4
}

# 6) If we have an entrypoint, run it inside the container
if [[ -n "${ENTRY:-}" ]]; then
  echo "==> Running crs-multilang entrypoint in container"
  # Make a temp output file inside container
  OUT_IN="/tmp/multilang_out_$$.json"
  # Try python invocation
  if ! docker exec -i atlantis-webservice /bin/sh -lc \
    "python \"$ENTRY\" --help >/dev/null 2>&1 || true"; then
    echo "WARN: Could not probe python entrypoint; attempting direct run"
  fi

  # Bind-mount target into the running container namespace (compose container already running)
  # We will copy the target into container /workspace/target_tmp to avoid volume constraints
  echo "==> Copying target into container"
  docker cp "$HOST_ABS" atlantis-webservice:/workspace/target_tmp 2>/dev/null || {
    # fallback: if target is a directory with many files, tar/stream
    if [ -d "$HOST_ABS" ]; then
      (cd "$HOST_ABS"/.. && tar cf - "$(basename "$HOST_ABS")") | docker exec -i atlantis-webservice tar xf - -C /workspace
    else
      # single file fallback
      BAS="$(basename "$HOST_ABS")"
      docker exec -i atlantis-webservice /bin/sh -lc "mkdir -p /workspace/target_tmp && cat > /workspace/target_tmp/$BAS" < "$HOST_ABS"
    fi
  }

  # Try common CLIs: --path/--repo/--input and output flags
  # If the module prints to stdout, we capture and write to OUT.
  echo "==> Executing: python \"$ENTRY\" (auto-arg detection)"
  RUN_OK=0
  for ARG in "--path" "--repo" "--input" "-i"; do
    if docker exec -i atlantis-webservice /bin/sh -lc \
      "python \"$ENTRY\" $ARG /workspace/target_tmp --output $OUT_IN 2>/tmp/multilang_stderr.txt || true; test -s $OUT_IN"; then
      RUN_OK=1; break
    fi
  done

  if [[ "$RUN_OK" -ne 1 ]]; then
    # Try stdout mode
    if docker exec -i atlantis-webservice /bin/sh -lc \
      "python \"$ENTRY\" /workspace/target_tmp > $OUT_IN 2>/tmp/multilang_stderr.txt || true; test -s $OUT_IN"; then
      RUN_OK=1
    fi
  fi

  if [[ "$RUN_OK" -eq 1 ]]; then
    docker cp atlantis-webservice:"$OUT_IN" "$OUT" 2>/dev/null || {
      docker exec -i atlantis-webservice cat "$OUT_IN" > "$OUT" || true
    }
    echo "WROTE $OUT"
    exit 0
  else
    echo "WARN: entrypoint did not produce output; showing last stderr:"
    docker exec -i atlantis-webservice /bin/sh -lc 'tail -n 80 /tmp/multilang_stderr.txt || true'
    echo "Falling back to API mode…"
  fi
fi

# 7) Fallback: call your web API with an explicit "multilang" intent
echo "==> API fallback: POST $ENDPOINT (mode=multilang)"
PYLOAD="$WORK/payload.json"
python3 - "$HOST_ABS" "$LLM_MAX_TOKENS" "$LLM_TEMPERATURE" > "$PYLOAD" <<'PY'
import sys, json, os
path = sys.argv[1]
max_toks = int(sys.argv[2]); temp = float(sys.argv[3])

def slurp(p):
    if os.path.isdir(p):
        # Small directory summary (filenames only); service should crawl if supported
        lst=[]
        for root,_,files in os.walk(p):
            for f in files[:100]: # cap
                lst.append(os.path.join(root,f))
                if len(lst)>=1000: break
            if len(lst)>=1000: break
        return "DIRECTORY TARGET:\n" + "\n".join(lst)
    else:
        try:
            with open(p,'r',encoding='utf-8',errors='ignore') as fh:
                return fh.read()
        except Exception as e:
            return f"<ERROR READING FILE: {e}>"

content = slurp(path)
sysmsg = "You are Atlantis-Multilang (language-agnostic). Return ONLY strict JSON array of concrete CWE findings; [] if none."
usr = {
  "mode": "multilang",
  "task": "vuln-scan",
  "target_path": path,
  "instructions": "Identify real vulnerabilities and map to CWE; include lines, snippet, evidence, fix. No prose."
}
payload = {
  "messages": [
    {"role":"system","content": sysmsg},
    {"role":"user","content": json.dumps(usr, ensure_ascii=False)},
    {"role":"user","content": content[:120000]}  # keep bounded
  ],
  "format": "json",
  "stream": False,
  "llm_max_tokens": max_toks,
  "llm_temperature": temp
}
print(json.dumps(payload))
PY

RESP="$WORK/resp.json"
HTTP="$WORK/http.txt"
curl -sS -w "\n%{http_code}\n" --max-time "$TIMEOUT" \
  -H "Content-Type: application/json" \
  -d @"$PYLOAD" "$ENDPOINT" \
  | tee "$WORK/body.withcode" >/dev/null

tail -n1 "$WORK/body.withcode" | tr -d '\r\n' > "$HTTP"
sed '$d' "$WORK/body.withcode" > "$RESP" || true
rm -f "$WORK/body.withcode"

CODE="$(cat "$HTTP" 2>/dev/null || echo "?")"
echo "HTTP: $CODE"

if [[ "$CODE" != "200" ]]; then
  echo "ERROR: non-200 from service; raw body follows"
  cat "$RESP"
  exit 5
fi

# Pretty JSON or salvage the last JSON array in body
python3 - "$RESP" "$OUT" <<'PY'
import sys, json, re
raw, outp = sys.argv[1], sys.argv[2]
s = open(raw,'r',errors='ignore').read()

def try_arr(x):
    try:
        j = json.loads(x)
        if isinstance(j, list): return j
        if isinstance(j, dict) and isinstance(j.get("findings"), list): return j["findings"]
    except: pass
    return None

arr = try_arr(s)
if arr is None:
    # fenced block?
    last=None
    for m in re.finditer(r"```json\s*([\s\S]*?)```", s, re.I): last=m.group(1)
    if last: arr = try_arr(last)
if arr is None:
    # last bracketed array
    start=None; depth=0; loc=None
    for i,ch in enumerate(s):
        if ch=='[':
            if depth==0: start=i
            depth+=1
        elif ch==']':
            if depth>0:
                depth-=1
                if depth==0 and start is not None: loc=(start,i+1)
    if loc: arr = try_arr(s[loc[0]:loc[1]])

# default to raw if nothing salvageable
open(outp,'w').write(json.dumps(arr, indent=2) if arr is not None else s)
PY

echo "WROTE $OUT"
echo "Logs in: $LOGDIR"
