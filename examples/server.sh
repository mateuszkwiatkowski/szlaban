#!/usr/bin/env sh
API_KEY="server"
PASS_HOST="http://localhost:8080"
SERVER_ID="darkstar"

# Request a secret from the server
req() {
  curl -s -X POST \
    -d '{"server_id":"'"$SERVER_ID"'", "req_id": "'"${REQ_ID:-nil}"'"}' \
    -H "Content-Type: application/json" \
    -H 'Authorization: Bearer '"$API_KEY"'' \
    $PASS_HOST/server/$1
}

REQ_ID=$(req request-key | jq -r '.request_id')

echo "Request ID: $REQ_ID"
echo "Waiting for request to be approved..."
echo "Approve with ./approve.sh $REQ_ID"

# trying to get the secret from the server for 5 minutes then exit
while true; do
    RESPONSE=$(req get-key)
    KEY=$(echo $RESPONSE | jq -r '.key')
    
    if [ "$KEY" != "null" ]; then
        echo "$KEY"
        break
    fi
    printf "."

    sleep 1
done