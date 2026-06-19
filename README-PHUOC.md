# Cloud API Security Project - Phần Phước

## 1. Chạy nhanh local

```bash
cp .env.example .env
```

Sau đó copy nội dung trong `docker-compose.phuoc-snippet.yml` vào file `infrastructure/docker-compose.yml` của nhóm, hoặc chạy riêng nếu đã chỉnh đúng đường dẫn build.

## 2. Tài khoản demo

| Username | Password | Role |
|---|---|---|
| phuoc | Phuoc@123 | user |
| admin | Admin@123 | admin |

## 3. Port local gợi ý

| Service | Port |
|---|---|
| user-service | 8001 |
| resource-service | 8002 |
| billing-service | 8003 |

## 4. Luồng demo chính

1. Login user `phuoc`.
2. Dùng JWT gọi `GET /resources/r1` → thành công.
3. Dùng JWT gọi `GET /resources/r2` → bị chặn 403 để chứng minh chống BOLA.
4. Login `admin`.
5. Dùng JWT admin gọi `GET /resources/r2` → thành công.
6. Gửi webhook có chữ ký HMAC đúng → thành công.
7. Gửi webhook sai chữ ký hoặc replay `X-Webhook-Id` → bị chặn.
