import hashlib
import hmac
import os
import sys
import time

secret = os.getenv("WEBHOOK_SECRET", "change-this-webhook-secret")
timestamp = str(int(time.time()))
raw_body = sys.stdin.buffer.read()

signed_payload = timestamp.encode("utf-8") + b"." + raw_body
signature = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()

print("X-Timestamp:", timestamp)
print("X-Signature:", signature)
