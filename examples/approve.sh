#!/usr/bin/env sh
API_KEY="admin"
PASS_HOST="http://localhost:8080"

# Request a secret from the server
REQ_ID="$1"

echo "Request ID: $REQ_ID"

curl -s -H "Content-Type: application/json" \
  -H 'Authorization: Bearer '"$API_KEY"'' \
  "${PASS_HOST}/admin/approve/${REQ_ID}"