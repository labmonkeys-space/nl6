# Security Configuration

## API Authentication

The nl6 simulator supports optional API authentication to protect sensitive endpoints from unauthorized access. This is particularly important when the API is exposed beyond localhost.

### Enabling Authentication

Set the `NL6_API_KEY` environment variable to enable authentication:

```bash
export NL6_API_KEY="your-secret-api-key-here"
sudo -E ./nl6 [flags]
```

When `NL6_API_KEY` is set, all mutating endpoints (POST, DELETE) require authentication. Read-only endpoints (GET) remain accessible without authentication for backward compatibility.

### Making Authenticated Requests

Include the API key in the `Authorization` header:

```bash
# Using Bearer token format
curl -H "Authorization: Bearer your-secret-api-key-here" \
  -X POST http://localhost:8080/api/v1/devices \
  -d '{"start_ip":"10.42.0.1","device_count":10}'

# Or plain token format
curl -H "Authorization: your-secret-api-key-here" \
  -X POST http://localhost:8080/api/v1/devices \
  -d '{"start_ip":"10.42.0.1","device_count":10}'
```

### Backward Compatibility

When `NL6_API_KEY` is **not** set, the simulator operates without authentication (legacy behavior). This allows existing deployments to continue working without changes while enabling security for production environments.

## IP Range Validation

The device provisioning endpoint (`POST /api/v1/devices`) validates that requested IP addresses fall within allowed simulator ranges. This prevents unauthorized control of host networking via arbitrary address ranges.

### Allowed IP Ranges

Only RFC 1918 private address spaces are permitted:

- `10.0.0.0/8` (Class A private)
- `172.16.0.0/12` (Class B private)
- `192.168.0.0/16` (Class C private)

### Rejected IP Ranges

The following ranges are explicitly rejected:

- **Public IP addresses**: Any address outside RFC 1918 private ranges
- **Localhost**: `127.0.0.0/8`
- **Link-local**: `169.254.0.0/16`
- **Multicast**: `224.0.0.0/4`
- **Network/broadcast addresses**: For `/24` networks, addresses ending in `.0` or `.255`

### Example Validation Errors

```bash
# Public IP - rejected
curl -X POST http://localhost:8080/api/v1/devices \
  -d '{"start_ip":"8.8.8.8","device_count":10}'
# Error: IP address 8.8.8.8 is outside allowed simulator ranges

# Localhost - rejected
curl -X POST http://localhost:8080/api/v1/devices \
  -d '{"start_ip":"127.0.0.1","device_count":10}'
# Error: IP address 127.0.0.1 is in the localhost range

# Valid private IP - accepted
curl -X POST http://localhost:8080/api/v1/devices \
  -d '{"start_ip":"10.42.0.1","device_count":10}'
# Success
```

## Protected Endpoints

The following endpoints require authentication when `NL6_API_KEY` is set:

### Device Management
- `POST /api/v1/devices` - Create devices
- `DELETE /api/v1/devices/{id}` - Delete device
- `DELETE /api/v1/devices` - Delete all devices

### Device Control
- `POST /api/v1/devices/{ip}/trap` - Fire SNMP trap
- `POST /api/v1/devices/{ip}/syslog` - Fire syslog message
- `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/oper-status` - Set interface operational status
- `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status` - Set interface admin status
- `POST /api/v1/devices/{ip}/optical/{component}/degrade` - Degrade optical component

### Topology Management
- `POST /api/v1/topology` - Create topology
- `DELETE /api/v1/topology` - Delete topology

### Scenario Management
- `POST /api/v1/scenarios` - Create scenario
- `POST /api/v1/scenarios/{id}/arm` - Arm scenario
- `POST /api/v1/scenarios/{id}/start` - Start scenario
- `POST /api/v1/scenarios/{id}/stop` - Stop scenario
- `DELETE /api/v1/scenarios/{id}` - Delete scenario

### System Control
- `POST /api/v1/fidelity` - Toggle fidelity mode
- `GET /api/v1/debug/pprof-memory` - Memory profiling
- `GET /api/v1/debug/cpu-profile` - CPU profiling

## Deployment Recommendations

### Production Deployments

1. **Always set `NL6_API_KEY`** when exposing the API beyond localhost
2. **Use a strong, randomly-generated API key** (minimum 32 characters)
3. **Bind to specific interfaces** if possible (though the default `0.0.0.0:8080` is common)
4. **Use TLS/HTTPS** via a reverse proxy (nginx, Traefik, etc.) for encrypted communication
5. **Implement network-level access controls** (firewall rules, security groups)

### Development/Testing

For local development, authentication can be disabled by not setting `NL6_API_KEY`. This maintains backward compatibility with existing scripts and workflows.

## Security Considerations

### Why IP Range Validation?

The simulator creates TUN interfaces and modifies host routing tables (in namespace mode). Without IP range validation, an attacker could:

1. Request arbitrary public IP ranges, potentially affecting host routing
2. Target reserved address spaces (localhost, link-local, multicast)
3. Cause conflicts with existing network infrastructure

By restricting to RFC 1918 private ranges, the simulator ensures it operates only within address spaces designated for private use.

### Why Optional Authentication?

The authentication is optional (via environment variable) to maintain backward compatibility with existing deployments while providing a security mechanism for production environments. This follows the principle of "secure by default when configured, compatible by default when not."

### Defense in Depth

This patch implements multiple layers of defense:

1. **Authentication**: Prevents unauthorized API access
2. **IP Range Validation**: Prevents misuse of privileged network operations
3. **Input Validation**: Existing validation for netmask, device count, etc.
4. **Privilege Requirements**: Root/network capabilities still required for TUN operations

## Migration Guide

### Existing Deployments

If you have existing deployments that should remain unauthenticated:

- No changes required - the simulator works as before when `NL6_API_KEY` is not set

### Securing Existing Deployments

To add authentication to an existing deployment:

1. Generate a strong API key:
   ```bash
   openssl rand -base64 32
   ```

2. Set the environment variable:
   ```bash
   export NL6_API_KEY="<generated-key>"
   ```

3. Update client scripts to include the Authorization header:
   ```bash
   curl -H "Authorization: Bearer $NL6_API_KEY" ...
   ```

4. Restart the simulator with the environment variable

### Docker/Compose Deployments

Update your `docker-compose.yml`:

```yaml
services:
  nl6:
    environment:
      - NL6_API_KEY=${NL6_API_KEY}
    # ... other configuration
```

Then set the key in your environment or `.env` file:

```bash
NL6_API_KEY=your-secret-key-here
```
