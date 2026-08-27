# API Authentication Quick Reference

## Enable Authentication

### Option 1: Command-line flag
```bash
sudo ./nl6 -api-key "your-secret-key" [other-flags...]
```

### Option 2: Environment variable
```bash
export NL6_API_KEY="your-secret-key"
sudo ./nl6 [flags...]
```

### Option 3: Docker/Kubernetes
```yaml
environment:
  - NL6_API_KEY=your-secret-key
```

## Generate a Strong API Key
```bash
openssl rand -base64 32
```

## Use the API with Authentication

### With curl
```bash
curl -H "X-API-Key: your-secret-key" http://localhost:8080/api/v1/devices
```

### With Python requests
```python
import requests
headers = {"X-API-Key": "your-secret-key"}
response = requests.get("http://localhost:8080/api/v1/devices", headers=headers)
```

### With JavaScript fetch
```javascript
fetch('http://localhost:8080/api/v1/devices', {
  headers: {'X-API-Key': 'your-secret-key'}
})
```

## Error Responses

### Missing API Key (when auth is enabled)
```json
HTTP/1.1 401 Unauthorized
{"success":false,"message":"Missing X-API-Key header"}
```

### Invalid API Key
```json
HTTP/1.1 401 Unauthorized
{"success":false,"message":"Invalid API key"}
```

## Unauthenticated Endpoints

These endpoints work without authentication even when it's enabled:
- `GET /health` - Health check
- `GET /` - Web UI home
- `GET /ui` - Web UI
- `GET /web/*` - Static assets

## Check Authentication Status

Look for these log messages at startup:

**Authentication enabled:**
```
API authentication enabled via -api-key flag
```
or
```
API authentication enabled via NL6_API_KEY environment variable
```

**Authentication disabled (INSECURE):**
```
WARNING: API authentication is DISABLED. The /api/v1 administrative control plane is exposed without authentication.
         Set -api-key flag or NL6_API_KEY environment variable to enable authentication.
         This is INSECURE for network-exposed deployments (Docker, Kubernetes, etc.).
```

## Security Best Practices

1. ✅ Always enable authentication for network-exposed deployments
2. ✅ Use strong, randomly-generated API keys (32+ characters)
3. ✅ Store API keys in secrets management systems (not in code)
4. ✅ Use HTTPS/TLS in production (reverse proxy recommended)
5. ✅ Rotate API keys regularly
6. ✅ Restrict network access with firewalls/security groups
