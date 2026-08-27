# Security Configuration

## API Authentication

The nl6 simulator exposes an administrative HTTP API on `/api/v1` that provides control over the entire fleet, including:
- Creating and deleting devices
- Modifying topology and interface states
- Controlling fidelity mode
- Injecting traps and syslog messages
- Managing load-test scenarios

### Enabling Authentication

**IMPORTANT**: By default, authentication is **DISABLED** for backward compatibility. This is **INSECURE** for network-exposed deployments (Docker, Kubernetes, etc.).

To enable API key authentication, use one of the following methods:

#### Method 1: Command-line flag (recommended for local development)

```bash
sudo ./nl6 -api-key "your-secret-api-key-here" [other flags...]
```

#### Method 2: Environment variable (recommended for production/containers)

```bash
export NL6_API_KEY="your-secret-api-key-here"
sudo ./nl6 [flags...]
```

#### Method 3: Docker/Kubernetes deployment

**Docker Compose:**
```yaml
services:
  nl6:
    image: nl6:latest
    environment:
      - NL6_API_KEY=your-secret-api-key-here
    ports:
      - "8080:8080"
```

**Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: nl6-api-key
type: Opaque
stringData:
  api-key: your-secret-api-key-here
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nl6
spec:
  template:
    spec:
      containers:
      - name: nl6
        image: nl6:latest
        env:
        - name: NL6_API_KEY
          valueFrom:
            secretKeyRef:
              name: nl6-api-key
              key: api-key
```

### Using the API with Authentication

When authentication is enabled, all requests to `/api/v1/*` endpoints must include the `X-API-Key` header:

```bash
# Create devices
curl -X POST http://localhost:8080/api/v1/devices \
  -H "X-API-Key: your-secret-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"10.0.0.1","device_count":5}'

# List devices
curl http://localhost:8080/api/v1/devices \
  -H "X-API-Key: your-secret-api-key-here"

# Delete a device
curl -X DELETE http://localhost:8080/api/v1/devices/10.0.0.1 \
  -H "X-API-Key: your-secret-api-key-here"
```

### Unauthenticated Endpoints

The following endpoints remain accessible without authentication:
- `/health` - Health check endpoint for monitoring and orchestration
- `/` and `/ui` - Web UI (static HTML/CSS/JS assets)
- `/web/*` - Static web assets

**Note**: The Web UI itself is unauthenticated, but any API calls it makes to `/api/v1` will require authentication when enabled.

### Authentication Errors

When authentication is enabled:

- **401 Unauthorized** with `{"success":false,"message":"Missing X-API-Key header"}` - Request did not include the `X-API-Key` header
- **401 Unauthorized** with `{"success":false,"message":"Invalid API key"}` - The provided API key does not match the configured key

### Best Practices

1. **Always enable authentication** for network-exposed deployments
2. **Use strong, randomly-generated API keys** (minimum 32 characters, cryptographically random)
3. **Store API keys securely** using secrets management (Kubernetes Secrets, Docker Secrets, HashiCorp Vault, etc.)
4. **Rotate API keys regularly** as part of your security hygiene
5. **Use HTTPS/TLS** in production to protect the API key in transit (consider a reverse proxy like nginx or Traefik)
6. **Restrict network access** using firewalls, security groups, or network policies to limit who can reach the API port

### Generating a Strong API Key

```bash
# Linux/macOS
openssl rand -base64 32

# Or using /dev/urandom
head -c 32 /dev/urandom | base64
```

### Migration from Unauthenticated Deployments

Existing deployments without authentication will continue to work without changes. To enable authentication:

1. Generate a strong API key
2. Set the `NL6_API_KEY` environment variable or `-api-key` flag
3. Restart the simulator
4. Update all API clients to include the `X-API-Key` header

### Security Considerations

- The API key is compared using constant-time comparison to prevent timing attacks
- The API key is never logged or exposed in error messages
- Authentication is applied at the middleware level, protecting all `/api/v1` routes uniformly
- The health check endpoint remains unauthenticated to support monitoring systems that may not support custom headers
