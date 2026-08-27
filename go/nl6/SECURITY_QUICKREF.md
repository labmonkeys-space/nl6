# Quick Security Reference

## Enable Authentication

```bash
# Generate a secure API key
export NL6_API_KEY=$(openssl rand -base64 32)

# Start simulator with authentication
sudo -E ./nl6 -auto-start-ip 10.42.0.1 -auto-count 10
```

## Make Authenticated Requests

```bash
# Set your API key
export NL6_API_KEY="your-api-key-here"

# Create devices (requires auth)
curl -H "Authorization: Bearer $NL6_API_KEY" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8080/api/v1/devices \
     -d '{"start_ip":"10.42.0.1","device_count":10}'

# List devices (no auth required)
curl http://localhost:8080/api/v1/devices
```

## Allowed IP Ranges

✅ **Allowed** (RFC 1918 private):
- `10.0.0.0/8` → `10.0.0.1` to `10.255.255.254`
- `172.16.0.0/12` → `172.16.0.1` to `172.31.255.254`
- `192.168.0.0/16` → `192.168.0.1` to `192.168.255.254`

❌ **Rejected**:
- Public IPs (e.g., `8.8.8.8`, `1.1.1.1`)
- Localhost (`127.0.0.0/8`)
- Link-local (`169.254.0.0/16`)
- Multicast (`224.0.0.0/4`)

## Error Messages

| Error | Cause | Fix |
|-------|-------|-----|
| `Missing Authorization header` | No auth header when `NL6_API_KEY` is set | Add `-H "Authorization: Bearer $NL6_API_KEY"` |
| `Invalid API key` | Wrong API key | Check `NL6_API_KEY` value |
| `outside allowed simulator ranges` | Public IP address | Use RFC 1918 private IP (10.x, 172.16-31.x, 192.168.x) |
| `localhost range` | Used 127.x.x.x | Use private IP instead |
| `network address` | Used x.x.x.0 with /24 | Use host address (e.g., x.x.x.1) |

## Docker Compose

```yaml
services:
  nl6:
    image: nl6:latest
    environment:
      - NL6_API_KEY=${NL6_API_KEY}
    ports:
      - "8080:8080"
```

```bash
# .env file
NL6_API_KEY=your-secret-key-here
```

## Backward Compatibility

**Without `NL6_API_KEY`**: Simulator works as before (no authentication)
**With `NL6_API_KEY`**: Mutating endpoints require authentication

Read-only endpoints (GET) never require authentication.

## Security Checklist

- [ ] Set `NL6_API_KEY` for production deployments
- [ ] Use strong, randomly-generated API key (32+ characters)
- [ ] Store API key securely (environment variable, secrets manager)
- [ ] Use HTTPS/TLS via reverse proxy
- [ ] Implement network-level access controls
- [ ] Monitor authentication failures
- [ ] Rotate API keys periodically

## Support

For detailed documentation, see:
- `SECURITY.md` - Full security configuration guide
- `PATCH_NOTES.md` - Technical details of the security patch
