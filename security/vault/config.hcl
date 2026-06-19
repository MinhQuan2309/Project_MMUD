# =========================================================================
# PROJECT_MMUD - HASHICORP VAULT PRODUCTION CONFIGURATION
# Hạ tầng lưu trữ Secret tập trung
# =========================================================================

# 1. Bật giao diện web UI để dễ quản lý trên trình duyệt
ui = true

# 2. Cấu hình Backend lưu trữ (Production dùng file để dữ liệu không mất khi restart)
storage "file" {
  path = "/vault/file"
}

# 3. Cấu hình cổng lắng nghe kết nối
listener "tcp" {
  address     = "0.0.0.0:8200"
  # Tắt TLS cho môi trường Lab nội bộ (Bảo mật bằng mTLS của mạng Docker)
  # Trên Production thực tế sẽ đổi thành "false" và trỏ tới file chứng chỉ
  tls_disable = 1 
}

# 4. Thời gian sống (TTL - Time To Live) của các Token/Secret
default_lease_ttl = "168h" # 7 ngày mặc định phải gia hạn token
max_lease_ttl     = "720h" # 30 ngày tối đa cho một phiên bản secret