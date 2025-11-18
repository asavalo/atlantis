import os, httpx, base64, asyncio

CAPI_URL = os.getenv("CAPI_URL", "http://capi:8000")

async def asubmit_vd(commit_hash: str, input_blob: bytes, sanitizer_id: str, harness_id: str):
    payload = {
        "commit_hash": commit_hash,
        "pov": {
            "data": base64.b64encode(input_blob).decode("ascii"),
            "sanitizer_id": sanitizer_id,
            "harness_id": harness_id
        }
    }
    async with httpx.AsyncClient(timeout=None) as client:
        r = await client.post(f"{CAPI_URL}/api/v1/vd", json=payload)
        r.raise_for_status()
        return r.json()

async def asubmit_gp(cpv_uuid: str, patch_bytes: bytes):
    payload = {
        "cpv_uuid": cpv_uuid,
        "data": base64.b64encode(patch_bytes).decode("ascii")
    }
    async with httpx.AsyncClient(timeout=None) as client:
        r = await client.post(f"{CAPI_URL}/api/v1/gp", json=payload)
        r.raise_for_status()
        return r.json()

def submit_vd(*args, **kwargs):
    return asyncio.run(asubmit_vd(*args, **kwargs))

def submit_gp(*args, **kwargs):
    return asyncio.run(asubmit_gp(*args, **kwargs))
