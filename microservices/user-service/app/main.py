import os
import sys
import time
from typing import Optional

import hvac  # Thư viện gọi Vault (DevSecOps)
import jwt
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# =====================================================================
# HÀM KẾT NỐI HASHICORP VAULT (PHƯỚC & QUÂN PHỐI HỢP)
# =====================================================================
def get_jwt_secret_from_vault():
    print("🔒 Đang gõ cửa Két sắt Vault để lấy JWT_SECRET...")
    try:
        # Gọi sang container Vault trong cùng mạng Docker
        client = hvac.Client(url='http://vault:8200', token='root-token-mmud')
        
        if not client.is_authenticated():
            print("❌ Thẻ từ Vault không hợp lệ!")
            sys.exit(1)

        # Lấy dữ liệu từ két sắt tên là 'user-service'
        response = client.secrets.kv.v2.read_secret_version(path='user-service')
        secrets = response['data']['data']
        
        jwt_secret = secrets.get("JWT_SECRET")
        if not jwt_secret:
            print("❌ Vault mở thành công nhưng không tìm thấy biến JWT_SECRET bên trong!")
            sys.exit(1)
            
        print("✅ Đã lấy thành công JWT_SECRET từ Vault! Tuyệt đối an toàn.")
        return jwt_secret
        
    except Exception as e:
        # Fallback: Nếu Vault sập hoặc chưa chạy, báo lỗi và thoát app
        print(f"❌ Không kết nối được Vault. Lỗi: {e}")
        print("⚠️ Ứng dụng từ chối khởi động vì lý do bảo mật (Thiếu Secret)!")
        sys.exit(1)

# =====================================================================
# KHỞI TẠO BIẾN MÔI TRƯỜNG & APP
# =====================================================================
APP_NAME = "user-service"

# Gọi hàm lấy Secret thật từ Vault thay vì đọc file .env
JWT_SECRET = get_jwt_secret_from_vault()
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(
    title="User Service",
    description="Đăng ký, đăng nhập và cấp JWT cho hệ thống Cloud API Security Project.",
    version="1.0.0",
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

# Demo in-memory DB. Khi làm thật có thể thay bằng PostgreSQL.
users = {
    "phuoc": {
        "user_id": "u-phuoc",
        "username": "phuoc",
        "password_hash": pwd_context.hash("Phuoc@123"),
        "role": "user",
    },
    "admin": {
        "user_id": "u-admin",
        "username": "admin",
        "password_hash": pwd_context.hash("Admin@123"),
        "role": "admin",
    },
}

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="user", pattern="^(user|admin)$")

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int

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
def register(req: RegisterRequest):
    username = req.username.lower().strip()
    if username in users:
        raise HTTPException(status_code=409, detail="Username already exists")
    users[username] = {
        "user_id": f"u-{username}",
        "username": username,
        "password_hash": pwd_context.hash(req.password),
        "role": req.role,
    }
    return {
        "message": "User created",
        "user_id": users[username]["user_id"],
        "username": username,
        "role": req.role,
    }

@app.post("/login", response_model=TokenResponse)
def login(req: LoginRequest):
    username = req.username.lower().strip()
    user = users.get(username)
    if not user or not pwd_context.verify(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_token(user)
    return TokenResponse(access_token=token, expires_in=JWT_EXPIRE_SECONDS)

@app.get("/me")
def me(authorization: Optional[str] = Header(default=None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if not authorization.startswith("Bearer "):
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
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"user": payload}