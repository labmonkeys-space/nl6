# Security Patch Summary

## Issue
Unauthenticated device provisioning controls host networking for arbitrary address ranges (CVE-TBD)

## Root Cause
The `POST /api/v1/devices` endpoint was:
1. Accessible without authentication
2. Accepting arbitrary IPv4 addresses without range validation
3. Using those addresses to configure TUN interfaces and modify host routing tables

## Impact
A network-reachable attacker could:
- Submit requests to create devices with arbitrary IP addresses
- Affect host routing tables (in namespace mode via `ip route replace`)
- Configure TUN interfaces in the host network namespace (in `-no-namespace` mode)
- Target reserved/special-use address spaces

## Fix Components

### 1. Authentication Middleware (`authMiddleware`)
- Reads API key from `NL6_API_KEY` environment variable
- When set, requires `Authorization` header on mutating endpoints
- Supports both `Bearer <token>` and plain token formats
- Backward compatible: when `NL6_API_KEY` is not set, operates without authentication

### 2. IP Range Validation (`validateIPRange`)
- Restricts device IPs to RFC 1918 private address spaces:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
- Rejects reserved/special-use ranges:
  - Localhost (127.0.0.0/8)
  - Link-local (169.254.0.0/16)
  - Multicast (224.0.0.0/4)
  - Network/broadcast addresses for /24 networks
- Returns descriptive error messages for rejected ranges

### 3. Route Protection
- Applied authentication to all mutating endpoints:
  - Device creation/deletion
  - Interface state changes
  - Topology modifications
  - Scenario control
  - Debug endpoints
- Read-only endpoints remain unauthenticated for backward compatibility

## Files Modified

### go/nl6/web.go
- Added `authMiddleware` function for API key validation
- Added `validateIPRange` function for IP address validation
- Modified `createDevicesHandler` to call `validateIPRange` before device creation
- Restructured `setupRoutes` to separate authenticated and unauthenticated endpoints

### go/nl6/SECURITY.md (new)
- Comprehensive security documentation
- Configuration guide for authentication
- IP range validation details
- Deployment recommendations
- Migration guide for existing deployments

### go/nl6/web_security_test.go (new)
- Unit tests for `validateIPRange` function
- Covers valid private IPs, invalid public IPs, reserved ranges, edge cases

## Backward Compatibility

The patch maintains full backward compatibility:
- When `NL6_API_KEY` is not set, the simulator operates without authentication
- Existing scripts and deployments continue to work unchanged
- Authentication is opt-in via environment variable

## Security Properties

### Defense in Depth
1. **Authentication**: Prevents unauthorized API access (when enabled)
2. **IP Range Validation**: Prevents misuse of privileged network operations
3. **Input Validation**: Existing validation for netmask, device count, etc.
4. **Privilege Requirements**: Root/network capabilities still required for TUN operations

### Fail-Safe Defaults
- IP validation is always active (cannot be disabled)
- Authentication is optional but recommended for production
- Descriptive error messages guide operators to correct usage

## Testing

### Manual Testing
```bash
# Test IP validation (always active)
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"8.8.8.8","device_count":1}'
# Expected: 400 Bad Request with "outside allowed simulator ranges"

curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"10.42.0.1","device_count":1}'
# Expected: 201 Created (if no auth) or 401 Unauthorized (if auth enabled)

# Test authentication (when NL6_API_KEY is set)
export NL6_API_KEY="test-key-12345"
# Restart simulator with environment variable

curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"10.42.0.1","device_count":1}'
# Expected: 401 Unauthorized

curl -X POST http://localhost:8080/api/v1/devices \
  -H "Authorization: Bearer test-key-12345" \
  -H "Content-Type: application/json" \
  -d '{"start_ip":"10.42.0.1","device_count":1}'
# Expected: 201 Created
```

### Unit Testing
```bash
cd go/nl6
go test -v -run TestValidateIPRange
```

## Deployment Recommendations

### Production
1. Set `NL6_API_KEY` to a strong, randomly-generated value
2. Use TLS/HTTPS via reverse proxy
3. Implement network-level access controls
4. Monitor for authentication failures

### Development
- Authentication can remain disabled for local testing
- IP validation is always active to prevent misconfigurations

## References
- RFC 1918: Address Allocation for Private Internets
- OWASP API Security Top 10
- CWE-306: Missing Authentication for Critical Function
- CWE-20: Improper Input Validation
