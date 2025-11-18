import sys, json, re

def readall(p):
    return open(p,'r',errors='ignore').read() if p else sys.stdin.read()

def last_array(text):
    start=None; depth=0; last=None
    for i,ch in enumerate(text):
        if ch=='[':
            if depth==0: start=i
            depth+=1
        elif ch==']':
            if depth>0:
                depth-=1
                if depth==0 and start is not None:
                    last=(start,i+1)
    if not last: return None
    frag=text[last[0]:last[1]]
    try:
        arr=json.loads(frag)
        return arr if isinstance(arr,list) else None
    except: return None

def try_message_content(s):
    try:
        obj=json.loads(s)
        if isinstance(obj,dict):
            msg=obj.get("message") or {}
            c=msg.get("content")
            if isinstance(c,str): return c
            # some backends: {"output": "..."} or {"response":"..."}
            for k in ("output","response","content","text"):
                v=obj.get(k)
                if isinstance(v,str): return v
    except: pass
    return None

def try_top_struct(s):
    try:
        obj=json.loads(s)
        if isinstance(obj,list): return obj
        if isinstance(obj,dict) and isinstance(obj.get("findings"),list):
            return obj["findings"]
    except: pass
    return None

def main():
    s = readall(sys.argv[1] if len(sys.argv)>1 else None)
    # direct
    arr = try_top_struct(s)
    if isinstance(arr,list):
        print(json.dumps(arr, indent=2)); return
    # from message/content or output wrapper
    inner = try_message_content(s)
    if inner:
        arr = try_top_struct(inner) or last_array(inner)
        if isinstance(arr,list):
            print(json.dumps(arr, indent=2)); return
    # last array anywhere
    arr = last_array(s)
    if isinstance(arr,list):
        print(json.dumps(arr, indent=2)); return
    # nothing found -> wrap as empty
    print("[]")
main()
