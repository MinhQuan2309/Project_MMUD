import hashlib
import hmac
import json
import os
import sys
import time
from typing import Optional

import hvac
import jwt 
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

APP_NAME = "billing-service"

# =====================================================================
# HÀM KẾT NỐI HASHICORP VAULT
# =====================================================================
def get_secrets_from_vault():
    print("🔒 Đang gõ cửa Két sắt Vault để lấy Secret cho Billing...")
    try:
        client = hvac.Client(url='http://vault-server:8200', token='root-token-mmud')
        
        if not client.is_authenticated():
            print("❌ Thẻ từ Vault không hợp lệ!")
            sys.exit(1)

        # Lấy dữ liệu từ két sắt dành riêng cho billing-service
        response = client.secrets.kv.v2.read_secret_version(path='billing-service')
        secrets = response['data']['data']
        
        webhook_secret = secrets.get("WEBHOOK_SECRET")
        jwt_secret = secrets.get("JWT_SECRET") # Cần chìa khóa này để soi Thẻ Nội Bộ
        
        if not webhook_secret or not jwt_secret:
            print("❌ Vault mở thành công nhưng thiếu WEBHOOK_SECRET hoặc JWT_SECRET!")
            sys.exit(1)
            
        print("✅ Đã lấy thành công Secrets từ Vault! Tuyệt đối an toàn.")
        return webhook_secret, jwt_secret
        
    except Exception as e:
        print(f"❌ Không kết nối được Vault. Lỗi: {e}")
        sys.exit(1)

# =====================================================================
# KHỞI TẠO BIẾN MÔI TRƯỜNG & APP
# =====================================================================
# Lấy chìa khóa thật từ Vault
WEBHOOK_SECRET, JWT_SECRET = get_secrets_from_vault()
WEBHOOK_TOLERANCE_SECONDS = int(os.getenv("WEBHOOK_TOLERANCE_SECONDS", "300"))
JWT_ALG = os.getenv("JWT_ALG", "HS256")

app = FastAPI(
    title="Billing Service",
    description="Dịch vụ giả lập nhận webhook thanh toán có xác thực chữ ký HMAC và JWT.",
    version="1.0.0",
)

REQUEST_COUNT = Counter(
    "billing_service_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "billing_service_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)

processed_webhook_ids = set()
payments = []

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

def verify_webhook_signature(raw_body: bytes, timestamp: str, signature: str) -> None:
    try:
        ts = int(timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    now = int(time.time())
    if abs(now - ts) > WEBHOOK_TOLERANCE_SECONDS:
        raise HTTPException(status_code=401, detail="Webhook timestamp is outside tolerance")

    signed_payload = timestamp.encode("utf-8") + b"." + raw_body
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

@app.post("/webhooks/payment")
async def payment_webhook(
    request: Request,
    x_timestamp: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    x_webhook_id: Optional[str] = Header(default=None),
):
    """
    Endpoint này KHÔNG cần JWT vì nó nhận tín hiệu từ đối tác bên ngoài (VD: VNPay, Momo).
    Bảo mật bằng HMAC Signature.
    """
    if not x_timestamp or not x_signature or not x_webhook_id:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Timestamp, X-Signature or X-Webhook-Id header",
        )

    if x_webhook_id in processed_webhook_ids:
        raise HTTPException(status_code=409, detail="Duplicate webhook detected")

    raw_body = await request.body()
    verify_webhook_signature(raw_body, x_timestamp, x_signature)

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    required_fields = {"payment_id", "user_id", "amount", "status"}
    if not required_fields.issubset(payload.keys()):
        raise HTTPException(status_code=422, detail="Missing required payment fields")

    processed_webhook_ids.add(x_webhook_id)
    payments.append(payload)

    return {"message": "Payment webhook accepted", "payment": payload}

@app.get("/payments")
def list_payments(authorization: Optional[str] = Header(default=None)):
    """
    MỚI: Endpoint này chứa dữ liệu nhạy cảm, BẮT BUỘC phải có Thẻ Nội Bộ mới được xem.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Thiếu thẻ nội bộ")
    
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
        raise HTTPException(status_code=401, detail="Thẻ nội bộ không hợp lệ hoặc đã hết hạn")
        
    return {"items": payments, "requested_by_user_id": payload.get("sub")}