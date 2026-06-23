import logging
import os
import uuid
from typing import Optional

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.security import get_secret_from_vault_or_file


# =====================================================================
# CONTEXT
# Employees/customers access resources through API Gateway.
# Risk: BOLA/IDOR - user guesses resource_id and reads another user's data.
# Goal: authorization by ownership and role after JWT authentication.
# =====================================================================

APP_NAME = "resource-service"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s",
)
logger = logging.getLogger(APP_NAME)


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        return True


logger.addFilter(RequestIdFilter())

JWT_SECRET = get_secret_from_vault_or_file("JWT_SECRET")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

app = FastAPI(
    title="Resource Service",
    description="Protected resource API with BOLA/IDOR defense.",
    version="2.0.0",
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

resources = {
    "r1": {
        "resource_id": "r1",
        "owner_id": "u-phuoc",
        "name": "Phuoc internal report",
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
async def request_context_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    endpoint = request.url.path
    method = request.method

    with REQUEST_LATENCY.labels(method, endpoint).time():
        response = await call_next(request)

    REQUEST_COUNT.labels(method, endpoint, str(response.status_code)).inc()
    response.headers["X-Service-Name"] = APP_NAME
    response.headers["X-Request-ID"] = request_id

    logger.info(
        "http_request method=%s path=%s status=%s client=%s",
        method,
        endpoint,
        response.status_code,
        request.client.host if request.client else "-",
        extra={"request_id": request_id},
    )
    return response


@app.get("/health")
def health():
    return {"service": APP_NAME, "status": "ok"}


@app.get("/metrics")
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def verify_jwt(authorization: Optional[str], request_id: str) -> dict:
    if not authorization:
        logger.warning("auth_failed reason=missing_authorization", extra={"request_id": request_id})
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.startswith("Bearer "):
        logger.warning("auth_failed reason=invalid_scheme", extra={"request_id": request_id})
        raise HTTPException(status_code=401, detail="Invalid Authorization scheme")

    token = authorization.removeprefix("Bearer ").strip()

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience="internal-api",
            issuer="cloud-api-security-project",
        )
        logger.info(
            "auth_success user_id=%s username=%s role=%s",
            payload.get("sub"),
            payload.get("username"),
            payload.get("role"),
            extra={"request_id": request_id},
        )
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("auth_failed reason=token_expired", extra={"request_id": request_id})
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        logger.warning("auth_failed reason=invalid_token", extra={"request_id": request_id})
        raise HTTPException(status_code=401, detail="Invalid token")


def can_access_resource(user: dict, resource: dict) -> bool:
    return user.get("role") == "admin" or resource.get("owner_id") == user.get("sub")


@app.get("/resources")
def list_my_resources(
    authorization: Optional[str] = Header(default=None),
    x_request_id: Optional[str] = Header(default="-"),
):
    user = verify_jwt(authorization, x_request_id)

    if user.get("role") == "admin":
        logger.info("list_resources_allowed scope=all role=admin", extra={"request_id": x_request_id})
        return {"items": list(resources.values())}

    own_items = [r for r in resources.values() if r["owner_id"] == user.get("sub")]
    logger.info(
        "list_resources_allowed scope=owner user_id=%s count=%d",
        user.get("sub"),
        len(own_items),
        extra={"request_id": x_request_id},
    )
    return {"items": own_items}


@app.get("/resources/{resource_id}")
def get_resource(
    resource_id: str,
    authorization: Optional[str] = Header(default=None),
    x_request_id: Optional[str] = Header(default="-"),
):
    user = verify_jwt(authorization, x_request_id)

    resource = resources.get(resource_id)
    if not resource:
        logger.warning(
            "resource_not_found user_id=%s resource_id=%s",
            user.get("sub"),
            resource_id,
            extra={"request_id": x_request_id},
        )
        raise HTTPException(status_code=404, detail="Resource not found")

    if not can_access_resource(user, resource):
        logger.warning(
            "bola_blocked user_id=%s username=%s role=%s resource_id=%s owner_id=%s",
            user.get("sub"),
            user.get("username"),
            user.get("role"),
            resource_id,
            resource.get("owner_id"),
            extra={"request_id": x_request_id},
        )
        raise HTTPException(status_code=403, detail="Access denied")

    logger.info(
        "resource_access_allowed user_id=%s username=%s role=%s resource_id=%s",
        user.get("sub"),
        user.get("username"),
        user.get("role"),
        resource_id,
        extra={"request_id": x_request_id},
    )
    return resource


@app.post("/resources/{resource_id}/transfer")
def transfer_resource(
    resource_id: str,
    new_owner_id: str,
    authorization: Optional[str] = Header(default=None),
    x_request_id: Optional[str] = Header(default="-"),
):
    user = verify_jwt(authorization, x_request_id)

    resource = resources.get(resource_id)
    if not resource:
        logger.warning("transfer_failed reason=not_found resource_id=%s", resource_id, extra={"request_id": x_request_id})
        raise HTTPException(status_code=404, detail="Resource not found")

    if user.get("role") != "admin":
        logger.warning(
            "transfer_blocked reason=not_admin user_id=%s resource_id=%s",
            user.get("sub"),
            resource_id,
            extra={"request_id": x_request_id},
        )
        raise HTTPException(status_code=403, detail="Only admin can transfer resource")

    old_owner = resource["owner_id"]
    resource["owner_id"] = new_owner_id

    logger.info(
        "transfer_success resource_id=%s old_owner=%s new_owner=%s admin_id=%s",
        resource_id,
        old_owner,
        new_owner_id,
        user.get("sub"),
        extra={"request_id": x_request_id},
    )

    return {"message": "Resource owner updated", "resource": resource}
