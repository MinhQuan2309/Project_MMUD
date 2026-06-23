import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from app.security import get_secret_from_vault_or_file


# =====================================================================
# CONTEXT
# Billing service receives payment webhook through API Gateway.
# Risk: webhook forgery, tampering, replay attack.
# Goal: authenticate webhook with HMAC, validate timestamp, block duplicates.
# =====================================================================

APP_NAME = "billing-service"

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

WEBHOOK_SECRET = get_secret_from_vault_or_file("WEBHOOK_SECRET")
WEBHOOK_TOLERANCE_SECONDS = int(os.getenv("WEBHOOK_TOLERANCE_SECONDS", "300"))

app = FastAPI(
    title="Billing Service",
    description="Payment webhook receiver with HMAC and replay defense.",
    version="2.0.0",
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


def verify_webhook_signature(raw_body: bytes, timestamp: str, signature: str, request_id: str) -> None:
    try:
        ts = int(timestamp)
    except ValueError:
        logger.warning("webhook_rejected reason=invalid_timestamp", extra={"request_id": request_id})
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    now = int(time.time())
    clock_skew = abs(now - ts)

    if clock_skew > WEBHOOK_TOLERANCE_SECONDS:
        logger.warning(
            "webhook_rejected reason=timestamp_outside_tolerance clock_skew=%d tolerance=%d",
            clock_skew,
            WEBHOOK_TOLERANCE_SECONDS,
            extra={"request_id": request_id},
        )
        raise HTTPException(status_code=401, detail="Webhook timestamp is outside tolerance")

    signed_payload = timestamp.encode("utf-8") + b"." + raw_body
    expected = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        logger.warning("webhook_rejected reason=invalid_signature", extra={"request_id": request_id})
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    logger.info("webhook_signature_valid", extra={"request_id": request_id})


@app.post("/webhooks/payment")
async def payment_webhook(
    request: Request,
    x_timestamp: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
    x_webhook_id: Optional[str] = Header(default=None),
    x_request_id: Optional[str] = Header(default="-"),
):
    if not x_timestamp or not x_signature or not x_webhook_id:
        logger.warning("webhook_rejected reason=missing_required_headers", extra={"request_id": x_request_id})
        raise HTTPException(
            status_code=400,
            detail="Missing X-Timestamp, X-Signature or X-Webhook-Id header",
        )

    if x_webhook_id in processed_webhook_ids:
        logger.warning(
            "webhook_rejected reason=duplicate_webhook webhook_id=%s",
            x_webhook_id,
            extra={"request_id": x_request_id},
        )
        raise HTTPException(status_code=409, detail="Duplicate webhook detected")

    raw_body = await request.body()
    verify_webhook_signature(raw_body, x_timestamp, x_signature, x_request_id)

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except json.JSONDecodeError:
        logger.warning("webhook_rejected reason=invalid_json", extra={"request_id": x_request_id})
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    required_fields = {"payment_id", "user_id", "amount", "status"}
    if not required_fields.issubset(payload.keys()):
        logger.warning("webhook_rejected reason=missing_fields", extra={"request_id": x_request_id})
        raise HTTPException(status_code=422, detail="Missing required payment fields")

    processed_webhook_ids.add(x_webhook_id)
    payments.append(payload)

    logger.info(
        "webhook_accepted webhook_id=%s payment_id=%s user_id=%s amount=%s status=%s",
        x_webhook_id,
        payload.get("payment_id"),
        payload.get("user_id"),
        payload.get("amount"),
        payload.get("status"),
        extra={"request_id": x_request_id},
    )

    return {"message": "Payment webhook accepted", "payment": payload}


@app.get("/payments")
def list_payments():
    return {"items": payments}
