# Kịch bản kiểm thử phần Phước

## 1. Login user thường

POST http://localhost:8001/login

```json
{
  "username": "phuoc",
  "password": "Phuoc@123"
}
```

Lưu `access_token`.

## 2. Gọi resource hợp lệ

GET http://localhost:8002/resources/r1

Header:

```text
Authorization: Bearer <access_token>
```

Kỳ vọng: `200 OK`.

## 3. Kiểm thử BOLA/IDOR

GET http://localhost:8002/resources/r2

Header:

```text
Authorization: Bearer <access_token-user-phuoc>
```

Kỳ vọng: `403 Access denied`.

## 4. Login admin

POST http://localhost:8001/login

```json
{
  "username": "admin",
  "password": "Admin@123"
}
```

Dùng token admin gọi:

GET http://localhost:8002/resources/r2

Kỳ vọng: `200 OK`.

## 5. Webhook hợp lệ

Tạo chữ ký theo công thức:

```text
signature = HMAC_SHA256(WEBHOOK_SECRET, timestamp + "." + raw_body)
```

POST http://localhost:8003/webhooks/payment

Headers:

```text
X-Timestamp: <unix_time>
X-Signature: <hex_hmac>
X-Webhook-Id: wh_001
Content-Type: application/json
```

Body:

```json
{
  "payment_id": "pay_001",
  "user_id": "u-phuoc",
  "amount": 100000,
  "status": "paid"
}
```

Kỳ vọng: `200 OK`.

## 6. Webhook giả mạo

Gửi cùng body nhưng sai `X-Signature`.

Kỳ vọng: `401 Invalid webhook signature`.

## 7. Replay webhook

Gửi lại đúng webhook `wh_001`.

Kỳ vọng: `409 Duplicate webhook detected`.
