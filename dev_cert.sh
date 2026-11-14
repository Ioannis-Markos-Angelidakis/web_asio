#!/usr/bin/env bash
# Generate a self-signed development certificate for the TLS / HTTP/2 demo.
#
#   ./dev_cert.sh                      # SANs: localhost, 127.0.0.1, ::1
#                                      #        + every local interface IP
#   ./dev_cert.sh 192.168.0.13 b.example.org   # ... plus extra names/IPs
#
# Then run and test:
#   ./webfw --port 8443 --tls-cert cert.pem --tls-key key.pem
#   curl -k --http2 https://localhost:8443/api/info          # ALPN h2
#   curl --http2-prior-knowledge http://localhost:8443/api/info   # h2c (works!)
#   curl --cacert cert.pem --http2 https://<LAN-IP>:8443/api/info # no -k needed
set -euo pipefail

DAYS="${FW_CERT_DAYS:-825}"   # ~2 years (macOS/iOS cap for server certs)

SANs="DNS:localhost,IP:127.0.0.1,IP:::1"

# Auto-include every non-link-local address of this machine so the cert
# validates for the LAN IP too (e.g. https://192.168.0.13:8443).
if command -v ip >/dev/null 2>&1; then
  for addr in $(ip -o addr show scope global 2>/dev/null \
                | awk '{print $4}' | cut -d/ -f1); do
    SANs+=",IP:${addr}"   # openssl accepts IPv4 and IPv6 here
  done
elif command -v ifconfig >/dev/null 2>&1; then
  # macOS fallback: best-effort grep of inet addresses
  for addr in $(ifconfig 2>/dev/null | grep 'inet ' | awk '{print $2}'); do
    [[ "$addr" == "127.0.0.1" ]] && continue
    SANs+=",IP:${addr}"
  done
fi

# Extra names / IPs from the command line.
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SANs+=",IP:${extra}"
  else
    SANs+=",DNS:${extra}"
  fi
done

openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS" -nodes \
  -keyout key.pem -out cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=${SANs}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

echo "wrote cert.pem / key.pem"
echo "  SANs: ${SANs}"
echo "run with:"
echo "  ./webfw --port 8443 --tls-cert cert.pem --tls-key key.pem"
echo "test with:"
echo "  curl -k --http2 https://localhost:8443/api/info"
echo "  curl --http2-prior-knowledge http://localhost:8443/api/info"
