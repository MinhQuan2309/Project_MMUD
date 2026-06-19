import os
from typing import Optional

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST


APP_NAME = "resource-service"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

app = FastAPI(
    title="Resource Service",
    description="Dịch vụ tài nguyên có kiểm soát truy cập để chống BOLA/IDOR.",
    version="1.0.0",
)

REQUEST_COUNT = Counter(
    "resource_service_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "resource_service_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)

# Demo DB: mỗi resource có owner_id.
resources = {
    "r1": {
        "resource_id": "r1",
        "owner_id": "u-phuoc",
        "name": "Phuoc private report",
        "classification": "internal",
    },
    "r2": {
        "resource_id": "r2",
        "owner_id": "u-admin",
        "name": "Admin security note",
        "classification": "confidential",
    },
}


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    endpoint = request.url.path
    method = request.method
    with REQUEST_LATENCY.labels(method, endpoint).time():
        response = await call_next(request)
    REQUEST_COUNT.labels(method, endpoint, str(response.status_code)).inc()
    response.headers["X-Service-Name"] = APP_NAME
    return response


@app.get("/health")
def health():
    return {"service": APP_NAME, "status": "ok"}


@app.get("/metrics")
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def verify_jwt(authorization: Optional[str]) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization scheme")

    token = authorization.removeprefix("Bearer ").strip()

    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience="internal-api",
            issuer="cloud-api-security-project",
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def can_access_resource(user: dict, resource: dict) -> bool:
    # FIX BOLA/IDOR:
    # Không được chỉ tin resource_id do client gửi lên.
    # Phải kiểm resource.owner_id == user.sub hoặc user.role == admin.
    return user.get("role") == "admin" or resource.get("owner_id") == user.get("sub")


@app.get("/resources")
def list_my_resources(authorization: Optional[str] = Header(default=None)):
    user = verify_jwt(authorization)

    if user.get("role") == "admin":
        return {"items": list(resources.values())}

    own_items = [r for r in resources.values() if r["owner_id"] == user.get("sub")]
    return {"items": own_items}


@app.get("/resources/{resource_id}")
def get_resource(resource_id: str, authorization: Optional[str] = Header(default=None)):
    user = verify_jwt(authorization)

    resource = resources.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    if not can_access_resource(user, resource):
        raise HTTPException(status_code=403, detail="Access denied")

    return resource


@app.post("/resources/{resource_id}/transfer")
def transfer_resource(
    resource_id: str,
    new_owner_id: str,
    authorization: Optional[str] = Header(default=None),
):
    user = verify_jwt(authorization)

    resource = resources.get(resource_id)
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")

    # Chỉ admin mới được chuyển owner để tránh lạm dụng logic.
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can transfer resource")

    resource["owner_id"] = new_owner_id
    return {"message": "Resource owner updated", "resource": resource}
