import sys, json, re

REQUIRED = {"path","cwe_guess","severity","confidence","lines","snippet","evidence","reasoning","fix"}

def readall(p):
    return open(p,'r',errors='ignore').read() if p else sys.stdin.read()

def json_candidates(text):
    # 1) Direct top-level JSON
    try:
        obj=json.loads(text)
        yield obj
    except Exception:
        pass

    # 2) Common wrappers: {"message":{"content":"..."}}, {"output":"..."} etc.
    try:
        obj=json.loads(text)
        if isinstance(obj,dict):
            for k in ("message","output","response","content","text"):
                v=obj.get(k)
                if isinstance(v,dict) and "content" in v and isinstance(v["content"],str):
                    yield v["content"]
                elif isinstance(v,str):
                    yield v
    except Exception:
        pass

    # 3) Code fences ```json ... ```
    for m in re.finditer(r"```json\s*([\s\S]*?)```", text, re.IGNORECASE):
        yield m.group(1)

    # 4) Any {... "findings":[ ... ] ...}
    for m in re.finditer(r"\{[^{}]*\"findings\"\s*:\s*\[[\s\S]*?\][^{}]*\}", text):
        yield m.group(0)

    # 5) All balanced arrays: grab many, not just last
    #    This is lenient: collect up to, say, 40 arrays
    arrays=[]
    stack=[]
    for i,ch in enumerate(text):
        if ch=='[':
            stack.append(i)
        elif ch==']' and stack:
            start=stack.pop()
            arrays.append(text[start:i+1])
            if len(arrays) >= 40:
                break
    for frag in arrays:
        yield frag

def load_json(x):
    if isinstance(x,(dict,list)): return x
    try:
        return json.loads(x)
    except Exception:
        return None

def score_array(arr):
    # Prefer arrays of dicts with required keys
    if not isinstance(arr, list): return (-1,0)
    objs=[it for it in arr if isinstance(it,dict)]
    if not objs: return (0,0)
    ok=0
    for it in objs:
        if REQUIRED.issubset(it.keys()):
            # light type checks
            if isinstance(it.get("path"),str) and isinstance(it.get("cwe_guess"),str):
                if isinstance(it.get("severity"),str) and isinstance(it.get("confidence"),(int,float)):
                    if isinstance(it.get("lines"),list) and it.get("lines"):
                        ok += 1
    return (ok, len(objs))  # primary: how many valid findings, secondary: how many dicts

def best_findings(text):
    best=None; best_score=(-1,0)
    for cand in json_candidates(text):
        obj=load_json(cand)
        if isinstance(obj,dict) and isinstance(obj.get("findings"),list):
            arr=obj["findings"]
        else:
            arr=obj
        sc=score_array(arr)
        if sc > best_score:
            best_score=sc; best=arr
    # Only accept if at least 1 valid finding object was seen
    if best is not None and score_array(best)[0] > 0:
        # trim oversize snippets a bit
        out=[]
        for it in best:
            if isinstance(it,dict):
                sn=it.get("snippet")
                if isinstance(sn,str) and len(sn)>1600:
                    it=it.copy(); it["snippet"]=sn[:1600]+"…"
            out.append(it)
        return out
    return []

def main():
    s = readall(sys.argv[1] if len(sys.argv)>1 else None)
    arr = best_findings(s)
    print(json.dumps(arr, indent=2))
main()
