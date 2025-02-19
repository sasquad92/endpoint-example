from fastapi import FastAPI, Request, HTTPException, Header, Response
import hashlib
import hmac
import json
import logging

app = FastAPI()
SECRET_KEY = b"secret"

logging.basicConfig(level=logging.INFO)

@app.post("/api/revoke")
async def revoke(
    request: Request,
    user_agent: str = Header(...),
    x_hub_signature_256: str = Header(...)
):
    headers = dict(request.headers)
    body = await request.body()
    logging.info(f"Received request with headers: {headers} and body: {body.decode('utf-8')}")
    
    if "Legimi-Webhook" not in user_agent:
        logging.error("Invalid User-Agent header")
        raise HTTPException(status_code=400, detail="Invalid User-Agent header")
    
    expected_signature = hmac.new(SECRET_KEY, body, hashlib.sha256).hexdigest()
    expected_signature = f"{expected_signature}"
    
    if not hmac.compare_digest(expected_signature, x_hub_signature_256):
        logging.error("Invalid signature")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        logging.error("Invalid JSON format")
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    if not isinstance(data, dict) or "code" not in data or not isinstance(data["code"], str):
        logging.error("Invalid payload format")
        raise HTTPException(status_code=400, detail="Invalid payload format")
    
    logging.info("Request successfully validated")
    return Response(status_code=200)