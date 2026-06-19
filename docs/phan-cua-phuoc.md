# Phần triển khai của Huỳnh Duy Phước

## 1. Phạm vi phụ trách

Phước phụ trách phát triển các microservice backend và tích hợp các cơ chế AppSec ở tầng ứng dụng:

- `user-service`: đăng ký, đăng nhập và cấp JWT.
- `resource-service`: quản lý tài nguyên nội bộ, kiểm JWT và phân quyền theo chủ sở hữu để chống BOLA/IDOR.
- `billing-service`: giả lập nhận webhook thanh toán, xác thực HMAC để chống webhook forgery và replay attack.
- Dockerfile riêng cho từng service.
- Không hardcode secret trong code; service đọc cấu hình qua biến môi trường để sẵn sàng tích hợp Vault.
- Cung cấp endpoint `/health` và `/metrics` để Duy kéo Prometheus/Grafana.

## 2. Cơ chế bảo mật đã tích hợp

### 2.1 JWT Authentication

`user-service` cấp JWT sau khi đăng nhập thành công. Token có các claim quan trọng:

- `sub`: định danh người dùng.
- `role`: vai trò user/admin.
- `iat`: thời điểm phát hành.
- `exp`: thời điểm hết hạn.
- `iss`: định danh hệ thống phát hành token.
- `aud`: đối tượng sử dụng token.

`resource-service` không tự tin request từ client mà bắt buộc xác minh chữ ký, issuer, audience và thời hạn token.

### 2.2 Chống BOLA/IDOR

Lỗi BOLA xảy ra khi client đổi `resource_id` để truy cập tài nguyên của người khác. Cách xử lý trong `resource-service`:

- Mỗi tài nguyên có `owner_id`.
- Khi user gọi `/resources/{resource_id}`, hệ thống kiểm tra `resource.owner_id == token.sub`.
- Chỉ `admin` mới được xem toàn bộ tài nguyên.

Kịch bản demo: user `phuoc` truy cập `r1` thành công, nhưng truy cập `r2` bị chặn `403`.

### 2.3 Xác thực webhook bằng HMAC

`billing-service` yêu cầu ba header:

- `X-Timestamp`
- `X-Signature`
- `X-Webhook-Id`

Chữ ký được tính theo công thức:

```text
HMAC_SHA256(WEBHOOK_SECRET, timestamp + "." + raw_body)
```

Service dùng `hmac.compare_digest()` để so sánh chữ ký an toàn, kiểm tra timestamp trong giới hạn 5 phút và chặn gửi lại webhook bằng `X-Webhook-Id`.

## 3. Endpoint chính

| Service | Endpoint | Mục đích |
|---|---|---|
| user-service | `POST /register` | Tạo user mới |
| user-service | `POST /login` | Đăng nhập, nhận JWT |
| user-service | `GET /me` | Kiểm tra token |
| resource-service | `GET /resources` | Liệt kê tài nguyên được phép xem |
| resource-service | `GET /resources/{id}` | Xem tài nguyên cụ thể, có chống BOLA |
| resource-service | `POST /resources/{id}/transfer` | Admin chuyển chủ sở hữu |
| billing-service | `POST /webhooks/payment` | Nhận webhook thanh toán có HMAC |
| billing-service | `GET /payments` | Xem webhook đã nhận |
| tất cả | `GET /health` | Health check |
| tất cả | `GET /metrics` | Metrics cho Prometheus |

## 4. Tiêu chí nghiệm thu phần Phước

- Build Docker thành công cho cả 3 service.
- Đăng nhập user thường nhận JWT hợp lệ.
- User thường chỉ xem được tài nguyên của mình.
- User thường bị chặn khi truy cập tài nguyên người khác.
- Admin xem được toàn bộ tài nguyên.
- Webhook sai chữ ký bị chặn.
- Webhook gửi lại bị chặn.
- Không có secret thật trong source code.
- Prometheus có thể kéo `/metrics` từ từng service.
