import os
from fastapi import HTTPException

AUTH_MODE = os.getenv("AUTH_MODE", "disabled").lower()

def require_user():
    if AUTH_MODE == "disabled":
        return {"user":"local"}
    raise HTTPException(status_code=403, detail="Auth disabled or unsupported in local mode.")