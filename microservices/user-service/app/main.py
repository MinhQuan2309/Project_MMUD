import os
import sys
import time
import uuid # MỚI: Dùng để sinh ID ngẫu nhiên chống BOLA
from typing import Optional

import hvac  # Thư viện gọi Vault (DevSecOps)
import jwt
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

def get_jwt_secret_from_vault():
    print("🔒 Đang gõ cửa Két sắt Vault để lấy JWT_SECRET...")
    try:
        client = hvac.Client(url='http://vault:8200', token='root-token-mmud')
        
        if not client.is_authenticated():
            print("❌ Thẻ từ Vault không hợp lệ!")
            sys.exit(1)

        response = client.secrets.kv.v2.read_secret_version(path='user-service')
        secrets = response['data']['data']
        
        jwt_secret = secrets.get("JWT_SECRET")
        if not jwt_secret:
            print("❌ Vault mở thành công nhưng không tìm thấy biến JWT_SECRET bên trong!")
            sys.exit(1)
            
        print("✅ Đã lấy thành công JWT_SECRET từ Vault! Tuyệt đối an toàn.")
        return jwt_secret
        
    except Exception as e:
        print(f"❌ Không kết nối được Vault. Lỗi: {e}")
        print("⚠️ Ứng dụng từ chối khởi động vì lý do bảo mật (Thiếu Secret)!")
        sys.exit(1)


APP_NAME = "user-service"

JWT_SECRET = get_jwt_secret_from_vault()
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRE_SECONDS = int(os.getenv("JWT_EXPIRE_SECONDS", "3600"))

app = FastAPI(
    title="User Service",
    description="Cấp đổi Internal JWT (Token Exchange) cho hệ thống Cloud API Security Project.",
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

users = {}

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

# =====================================================================
# CHỨC NĂNG ĐỔI THẺ (TOKEN EXCHANGE) - THAY THẾ REGISTER/LOGIN
# =====================================================================
@app.post("/exchange", response_model=TokenResponse)
def exchange_token(authorization: Optional[str] = Header(default=None)):
    """
    Endpoint này nhận External JWT của Auth0 (đã được Kong xác thực).
    Trích xuất thông tin, tạo hồ sơ nội bộ, và trả về Internal JWT (HS256).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu thẻ Auth0")

    ext_token = authorization.removeprefix("Bearer ").strip()

    try:
        # Giải mã lấy thông tin Auth0 (Kong Gateway ở vòng ngoài đã verify chữ ký số rồi)
        ext_payload = jwt.decode(ext_token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Định dạng token Auth0 không hợp lệ")

    auth0_sub = ext_payload.get("sub")
    if not auth0_sub:
        raise HTTPException(status_code=400, detail="Auth0 Token thiếu trường 'sub'")

    # Đăng ký tự động (Upsert) vào hệ thống nội bộ nếu là user mới
    if auth0_sub not in users:
        users[auth0_sub] = {
            "user_id": str(uuid.uuid4()), # FIX BOLA: Cấp Opaque ID cực kỳ phức tạp
            "username": ext_payload.get("email", f"user_{auth0_sub[-5:]}"), 
            "role": "user"
        }

    user = users[auth0_sub]

    # In ra Thẻ từ nội bộ
    internal_token = create_token(user)
    return TokenResponse(access_token=internal_token, expires_in=JWT_EXPIRE_SECONDS)

# =====================================================================
# KIỂM TRA THẺ NỘI BỘ 
# =====================================================================
@app.get("/me")
def me(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu thẻ nội bộ")
    
    token = authorization.removeprefix("Bearer ").strip()
    try:
        # Giải mã và VERIFY chữ ký đối xứng của hệ thống nội bộ
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience="internal-api",
            issuer="cloud-api-security-project",
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Thẻ nội bộ không hợp lệ hoặc đã hết hạn")
    
    return {"user": payload}