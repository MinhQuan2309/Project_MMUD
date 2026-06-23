$ErrorActionPreference = "Continue"

Write-Host "=== 1. Health checks ==="
Invoke-RestMethod http://localhost:8001/health
Invoke-RestMethod http://localhost:8002/health
Invoke-RestMethod http://localhost:8003/health

Write-Host "`n=== 2. Login as phuoc ==="
$login = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8001/login" `
  -ContentType "application/json" `
  -Headers @{"X-Request-ID"="demo-login-phuoc"} `
  -Body '{"username":"phuoc","password":"Phuoc@123"}'

$token = $login.access_token
Write-Host "JWT received: " $token.Substring(0, 30) "... token value hidden"

Write-Host "`n=== 3. Valid resource access: phuoc -> r1 ==="
Invoke-RestMethod -Method Get `
  -Uri "http://localhost:8002/resources/r1" `
  -Headers @{Authorization="Bearer $token"; "X-Request-ID"="demo-r1-allowed"}

Write-Host "`n=== 4. BOLA test: phuoc -> r2 should be blocked ==="
try {
  Invoke-RestMethod -Method Get `
    -Uri "http://localhost:8002/resources/r2" `
    -Headers @{Authorization="Bearer $token"; "X-Request-ID"="demo-bola-blocked"}
} catch {
  Write-Host "Expected status:" $_.Exception.Response.StatusCode.value__
  Write-Host "Expected body:" $_.ErrorDetails.Message
}

Write-Host "`n=== 5. Login as admin and access r2 ==="
$adminLogin = Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8001/login" `
  -ContentType "application/json" `
  -Headers @{"X-Request-ID"="demo-login-admin"} `
  -Body '{"username":"admin","password":"Admin@123"}'

$adminToken = $adminLogin.access_token

Invoke-RestMethod -Method Get `
  -Uri "http://localhost:8002/resources/r2" `
  -Headers @{Authorization="Bearer $adminToken"; "X-Request-ID"="demo-admin-r2-allowed"}

Write-Host "`n=== 6. Webhook HMAC valid ==="
$secret = "change-this-webhook-secret"
$body = '{"payment_id":"pay_001","user_id":"u-phuoc","amount":100000,"status":"paid"}'
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()

$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret)
$signedPayload = "$timestamp.$body"
$signature = ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($signedPayload)) | ForEach-Object { $_.ToString("x2") }) -join ""

Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8003/webhooks/payment" `
  -ContentType "application/json" `
  -Headers @{
    "X-Timestamp"=$timestamp
    "X-Signature"=$signature
    "X-Webhook-Id"="wh_001"
    "X-Request-ID"="demo-webhook-valid"
  } `
  -Body $body

Write-Host "`n=== 7. Webhook replay should be blocked ==="
try {
  Invoke-RestMethod -Method Post `
    -Uri "http://localhost:8003/webhooks/payment" `
    -ContentType "application/json" `
    -Headers @{
      "X-Timestamp"=$timestamp
      "X-Signature"=$signature
      "X-Webhook-Id"="wh_001"
      "X-Request-ID"="demo-webhook-replay"
    } `
    -Body $body
} catch {
  Write-Host "Expected status:" $_.Exception.Response.StatusCode.value__
  Write-Host "Expected body:" $_.ErrorDetails.Message
}

Write-Host "`n=== 8. Webhook fake signature should be blocked ==="
try {
  Invoke-RestMethod -Method Post `
    -Uri "http://localhost:8003/webhooks/payment" `
    -ContentType "application/json" `
    -Headers @{
      "X-Timestamp"=$timestamp
      "X-Signature"="fake-signature"
      "X-Webhook-Id"="wh_fake"
      "X-Request-ID"="demo-webhook-fake-signature"
    } `
    -Body $body
} catch {
  Write-Host "Expected status:" $_.Exception.Response.StatusCode.value__
  Write-Host "Expected body:" $_.ErrorDetails.Message
}
