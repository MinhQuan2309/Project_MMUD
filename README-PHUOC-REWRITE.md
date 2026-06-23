# Phước rewrite package

## Chạy test trực tiếp phần Phước

```powershell
cd D:\ProjectMMUD\Project_MMUD
copy .env.example .env
docker compose -f docker-compose.phuoc-realistic.yml -f docker-compose.phuoc-debug.yml up -d --build
```

Test nhanh:

```powershell
.\testing\phuoc-context-test.ps1
```

Xem log:

```powershell
docker compose -f docker-compose.phuoc-realistic.yml -f docker-compose.phuoc-debug.yml logs -f user-service resource-service billing-service
```

## Chạy mô hình gần thực tế

Khi Quân route Gateway xong, chạy:

```powershell
docker compose -f docker-compose.phuoc-realistic.yml up -d --build
```

Khi đó backend không public port trực tiếp. Client phải đi qua Gateway.
