import os

from fastapi import Header, HTTPException

async def verify_authorization_header(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Invalid or missing Authorization header"
        )
    token = authorization.split("Bearer ")[1]
    expected = os.getenv("TOKEN")
    if not expected or token != expected:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token
