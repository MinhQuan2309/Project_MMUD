#!/usr/bin/env bash
set -e

CERT_DIR="./security/certs/generated"

mkdir -p "$CERT_DIR"

echo "[1/4] Generate local CA key and certificate..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096

openssl req -x509 -new -nodes \
  -key "$CERT_DIR/ca.key" \
  -sha256 \
  -days 3650 \
  -out "$CERT_DIR/ca.crt" \
  -subj "/C=VN/ST=HCM/L=HCM/O=ProjectMMUD/OU=Security/CN=ProjectMMUD-Local-CA"

generate_service_cert() {
  SERVICE_NAME=$1

  echo "Generating certificate for $SERVICE_NAME..."

  openssl genrsa -out "$CERT_DIR/$SERVICE_NAME.key" 2048

  openssl req -new \
    -key "$CERT_DIR/$SERVICE_NAME.key" \
    -out "$CERT_DIR/$SERVICE_NAME.csr" \
    -subj "/C=VN/ST=HCM/L=HCM/O=ProjectMMUD/OU=Microservices/CN=$SERVICE_NAME"

  cat > "$CERT_DIR/$SERVICE_NAME.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=$SERVICE_NAME
DNS.2=localhost
IP.1=127.0.0.1
EOF

  openssl x509 -req \
    -in "$CERT_DIR/$SERVICE_NAME.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/$SERVICE_NAME.crt" \
    -days 365 \
    -sha256 \
    -extfile "$CERT_DIR/$SERVICE_NAME.ext"

  rm "$CERT_DIR/$SERVICE_NAME.csr" "$CERT_DIR/$SERVICE_NAME.ext"
}

echo "[2/4] Generate service certificates..."
generate_service_cert "user-service"
generate_service_cert "resource-service"
generate_service_cert "billing-service"
generate_service_cert "kong"

echo "[3/4] List generated files..."
ls -la "$CERT_DIR"

echo "[4/4] Done."
echo "Generated CA and service certificates in $CERT_DIR"