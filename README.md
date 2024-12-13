# Szlaban

Szlaban is a secure key management server that implements a request-approval workflow for accessing decryption keys. It provides a secure way to manage access to sensitive keys through a time-limited approval process.

## Features

- 🔐 Secure request-approval workflow
- ⏱️ Time-limited requests (5 minutes expiration)
- 🎲 Cryptographically secure request IDs (UUIDs)
- 🔑 Protected approval endpoints
- 🧹 Automatic cleanup of expired requests
- 🔒 Constant-time comparison for secure key validation

## Installation

```bash
# Clone the repository
git clone https://github.com/mateuszkwiatkowski/szlaban.git
cd szlaban

# Install dependencies
go mod download

# Run the server
go run main.go
```

## API Endpoints

### Create Key Request
```http
POST /server/request-key
Content-Type: application/json

{
    "server_id": "server123"
}
```
Response:
```json
{
    "message": "Request received. Awaiting approval. Request will expire in 5 minutes.",
    "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Approve Request (Protected)
```http
GET /admin/approve/:request_id
Authorization: Bearer your-super-secret-key-change-in-production
```

### Deny Request (Protected)
```http
GET /admin/deny/:request_id
Authorization: Bearer your-super-secret-key-change-in-production
```

### Get Decryption Key
```http
POST /server/get-key
Content-Type: application/json

{
    "req_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Example Scripts

The project includes helper scripts in the `examples/` directory to demonstrate the workflow:

### server.sh
A client script that:
1. Requests a new key
2. Displays the request ID
3. Polls for approval status
4. Retrieves the key once approved

Usage:
```bash
./examples/server.sh
```

### approve.sh
An admin script to approve pending requests.

Usage:
```bash
./examples/approve.sh <request_id>
```

## Security Features

1. **Request Expiration**: All requests expire after 5 minutes for security.
2. **Protected Endpoints**: Approval and denial endpoints require a secret key.
3. **Secure Request IDs**: Uses UUIDs to prevent guessing or enumeration attacks.
4. **Authorization**: Bearer token authentication for protected endpoints.
5. **Timing Attack Prevention**: Uses constant-time comparison for secret key validation.

## Configuration

The following constants can be configured in `main.go` (in production, these should be environment variables):

- `requestTimeout`: Duration before requests expire (default: 300 seconds)
- `secretKey`: Secret key for protected endpoints

## Development

```bash
# Run tests
go test ./...

# Run server in development mode
go run main.go
```

## Production Considerations / TODO

1. Use environment variables for configuration:
   - Secret key
   - Request timeout duration
   - Server port

2. Implement proper logging and monitoring
3. Use HTTPS in production
4. Implement rate limiting
5. Consider adding request validation and sanitization
6. Adjust API keys in example scripts for production use

## Dependencies

- [Gin Web Framework](https://github.com/gin-gonic/gin) - HTTP web framework
- [Google UUID](https://github.com/google/uuid) - UUID generation
- `jq` - Required for example scripts to parse JSON responses

## License

This project is licensed under the MIT License - see the LICENSE file for details.