# Phước - Context → Risks → Goals → Implementation

## 1. Ngữ cảnh ứng dụng

Một công ty nhỏ triển khai hệ thống API cho nhân viên và khách hàng. Client không gọi trực tiếp từng service mà đi qua API Gateway. Phía sau Gateway là các microservice:

- `user-service`: đăng ký, đăng nhập, cấp JWT.
- `resource-service`: cung cấp tài nguyên nội bộ.
- `billing-service`: nhận webhook thanh toán.

## 2. Rủi ro và mục tiêu bảo mật

| Ngữ cảnh | Rủi ro | Security goal | Phần Phước triển khai |
|---|---|---|---|
| User đăng nhập | Lộ mật khẩu, token giả | Authentication, confidentiality | bcrypt password hashing, JWT có exp/iss/aud |
| User xem tài nguyên | BOLA/IDOR | Authorization | Kiểm tra `owner_id == token.sub` hoặc admin |
| Payment webhook | Giả mạo webhook, sửa body | Authenticity, integrity | HMAC-SHA256 trên timestamp + raw body |
| Payment webhook | Replay webhook cũ | Anti-replay | Timestamp tolerance + `X-Webhook-Id` |
| Secret hệ thống | Lộ JWT_SECRET, WEBHOOK_SECRET | Secret confidentiality | Docker secret/Vault/env fallback cho demo |
| Vận hành | Không có bằng chứng khi bị tấn công | Auditability | Log login, auth fail, BOLA blocked, webhook rejected |

## 3. Demo results cần chụp

- `docker compose ps`: 3 service Up.
- `/health`: cả 3 service ok.
- Login user `phuoc`: nhận JWT.
- `phuoc` gọi `r1`: thành công.
- `phuoc` gọi `r2`: bị `403 Access denied`.
- `admin` gọi `r2`: thành công.
- Webhook đúng HMAC: thành công.
- Webhook replay: bị `409 Duplicate webhook detected`.
- Webhook sai chữ ký: bị `401 Invalid webhook signature`.
- Docker logs có `bola_blocked`, `webhook_rejected`, `login_success`.

## 4. Mô hình Docker gần thực tế

File `docker-compose.phuoc-realistic.yml` chỉ `expose` backend trong Docker network. Client nên đi qua API Gateway. Khi cần test trực tiếp phần Phước, dùng thêm file override `docker-compose.phuoc-debug.yml` để mở port 8001, 8002, 8003.
