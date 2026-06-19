#!/bin/bash
echo "Đang nạp chìa khóa vào Két sắt Vault..."
docker exec -e VAULT_TOKEN=root-token-mmud -e VAULT_ADDR='http://127.0.0.1:8200' vault-server vault kv put secret/user-service JWT_SECRET="super-secret-jwt-key-for-mmud-project-2026"

echo "Đánh thức Lễ tân (user-service)..."
docker compose restart user-service

echo "Đang nạp chìa khóa vào Két sắt Vault cho Billing..."
docker exec -e VAULT_TOKEN=root-token-mmud -e VAULT_ADDR='http://127.0.0.1:8200' vault-server vault kv put secret/billing-service WEBHOOK_SECRET="mmud-billing-webhook-hmac-secret-key-9999" JWT_SECRET="super-secret-jwt-key-for-mmud-project-2026"

echo "Đánh thức Phòng Thanh toán (billing-service)..."
docker compose restart billing-service

echo "Hệ thống đã sẵn sàng! Bây giờ bạn có thể gọi API."
