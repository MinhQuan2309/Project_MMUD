import logging
import os
import time
import uuid
from typing import Optional

import jwt
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.security import get_secret_from_vault_or_file


# =====================================================================
# CONTEXT
# Small company API system behind API Gateway.
# Risk: password leak, token forgery, weak auth, lack of audit log.
# Goal: authenticate user, hash password, issue signed JWT, avoid secret leak.
# =====================================================================

APP_NAME = "user-service"

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
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(
    title="User Service",
    description="Authentication service: register, login, issue JWT.",
    version="2.0.0",
)

REQUEST_COUNT = Counter(
    "user_service_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "user_service_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)

# Demo in-memory database.
# Production should replace this with a real database and migration/seed process.
users = {}


def seed_demo_users() -> None:
    if os.getenv("DEMO_USERS_ENABLED", "true").lower() != "true":
        return

    demo_phuoc_password = os.getenv("DEMO_PHUOC_PASSWORD", "Phuoc@123")
    demo_admin_password = os.getenv("DEMO_ADMIN_PASSWORD", "Admin@123")

    users["phuoc"] = {
        "user_id": "u-phuoc",
        "username": "phuoc",
        "password_hash": pwd_context.hash(demo_phuoc_password),
        "role": "user",
    }
    users["admin"] = {
        "user_id": "u-admin",
        "username": "admin",
        "password_hash": pwd_context.hash(demo_admin_password),
        "role": "admin",
    }

    logger.info(
        "demo_users_seeded users=phuoc,admin note=passwords_not_logged",
        extra={"request_id": "startup"},
    )


seed_demo_users()


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=72)
    role: str = Field(default="user", pattern="^(user|admin)$")


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=72)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


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


def create_token(user: dict) -> str:
    now = int(time.time())
    payload = {
        "sub": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + JWT_EXPIRE_SECONDS,
        "iss": "cloud-api-security-project",
        "aud": "internal-api",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, x_request_id: Optional[str] = Header(default="-")):
    username = req.username.lower().strip()

    logger.info(
        "register_request_received username=%s password_received=true password_length=%d",
        username,
        len(req.password),
        extra={"request_id": x_request_id},
    )

    if username in users:
        logger.warning(
            "register_failed username=%s reason=username_exists",
            username,
            extra={"request_id": x_request_id},
        )
        raise HTTPException(status_code=409, detail="Username already exists")

    password_hash = pwd_context.hash(req.password)

    users[username] = {
        "user_id": f"u-{username}",
        "username": username,
        "password_hash": password_hash,
        "role": req.role,
    }

    logger.info(
        "register_success username=%s user_id=%s role=%s hash_type=bcrypt hash_prefix=%s",
        username,
        users[username]["user_id"],
        req.role,
        password_hash[:7],
        extra={"request_id": x_request_id},
    )

    return {
        "message": "User created",
        "user_id": users[username]["user_id"],
        "username": username,
        "role": req.role,
    }


@app.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, x_request_id: Optional[str] = Header(default="-")):
    username = req.username.lower().strip()

    logger.info(
        "login_request_received username=%s password_received=true password_length=%d",
        username,
        len(req.password),
        extra={"request_id": x_request_id},
    )

    user = users.get(username)

    if not user or not pwd_context.verify(req.password, user["password_hash"]):
        logger.warning(
            "login_failed username=%s reason=invalid_credentials",
            username,
            extra={"request_id": x_request_id},
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(user)

    logger.info(
        "login_success username=%s user_id=%s role=%s token_issued=true token_value_logged=false",
        user["username"],
        user["user_id"],
        user["role"],
        extra={"request_id": x_request_id},
    )

    return TokenResponse(access_token=token, expires_in=JWT_EXPIRE_SECONDS)


@app.get("/me")
def me(
    authorization: Optional[str] = Header(default=None),
    x_request_id: Optional[str] = Header(default="-"),
):
    if not authorization:
        logger.warning("me_failed reason=missing_authorization", extra={"request_id": x_request_id})
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.startswith("Bearer "):
        logger.warning("me_failed reason=invalid_scheme", extra={"request_id": x_request_id})
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
    except jwt.ExpiredSignatureError:
        logger.warning("me_failed reason=token_expired", extra={"request_id": x_request_id})
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        logger.warning("me_failed reason=invalid_token", extra={"request_id": x_request_id})
        raise HTTPException(status_code=401, detail="Invalid token")

    logger.info(
        "me_success user_id=%s username=%s role=%s",
        payload.get("sub"),
        payload.get("username"),
        payload.get("role"),
        extra={"request_id": x_request_id},
    )

    return {"user": payload}
