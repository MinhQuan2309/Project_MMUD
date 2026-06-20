Write-Host "Starting ZAP Scan..."

docker run -v "${PWD}\zap-output:/zap/wrk" -t ghcr.io/zaproxy/zaproxy `
  zap-baseline.py `
  -t http://host.docker.internal:8000 `
  -r zap-report.html

Write-Host "Scan completed. Report generated: zap-report.html"
