# Security Patch: API Authentication Implementation

## Overview
This patch addresses the security vulnerability where the `/api/v1` administrative API was exposed without authentication or authorization, allowing any network-reachable client to perform destructive operations.

## Changes Made

### 1. Authentication Middleware (`go/nl6/web.go`)

**Added:**
- `apiKeyAuth` global variable to store the configured API key
- `authMiddleware()` function that validates API key for all `/api/v1` requests
- Uses constant-time comparison (`crypto/subtle.ConstantTimeCompare`) to prevent timing attacks
- Returns 401 Unauthorized with descriptive JSON error messages for missing or invalid keys

**Modified:**
- `setupRoutes()` function now applies `authMiddleware` to the entire `/api/v1` subrouter using `api.Use(authMiddleware)`
- Added comments clarifying that `/health`, `/`, `/ui`, and `/web/*` endpoints remain unauthenticated

### 2. Configuration Support (`go/nl6/simulator.go`)

**Added:**
- `-api-key` command-line flag for setting the API key
- Support for `NL6_API_KEY` environment variable
- Priority order: `-api-key` flag > `NL6_API_KEY` env var > disabled (backward compatible)
- Startup logging that clearly indicates authentication status:
  - When enabled: logs the configuration source (flag or env var)
  - When disabled: logs a WARNING about the security risk

### 3. Documentation (`go/nl6/SECURITY.md`)

**Created comprehensive security documentation covering:**
- Why authentication is needed
- How to enable authentication (3 methods: CLI flag, env var, container deployment)
- Usage examples with curl
- List of unauthenticated endpoints
- Authentication error responses
- Best practices for production deployments
- API key generation instructions
- Migration guide for existing deployments

### 4. Test Coverage (`go/nl6/auth_test.go`)

**Created comprehensive test suite:**
- `TestAuthMiddleware_Disabled` - Verifies backward compatibility when auth is disabled
- `TestAuthMiddleware_MissingKey` - Verifies 401 response when X-API-Key header is missing
- `TestAuthMiddleware_InvalidKey` - Verifies 401 response for incorrect API keys
- `TestAuthMiddleware_ValidKey` - Verifies successful authentication with correct key
- `TestAuthMiddleware_HealthCheckExempt` - Verifies /health remains unauthenticated
- `TestAuthMiddleware_WebUIExempt` - Verifies Web UI remains unauthenticated
- `TestAuthMiddleware_AllAPIEndpointsProtected` - Verifies all /api/v1 endpoints are protected

## Security Properties

1. **Defense in Depth**: Authentication is applied at the middleware level, protecting all current and future `/api/v1` routes uniformly
2. **Timing Attack Resistance**: Uses `crypto/subtle.ConstantTimeCompare` for API key comparison
3. **Clear Error Messages**: Returns descriptive JSON errors without leaking sensitive information
4. **Backward Compatible**: Disabled by default to avoid breaking existing deployments
5. **Flexible Configuration**: Supports both CLI flags and environment variables for different deployment scenarios
6. **Monitoring-Friendly**: Health check endpoint remains unauthenticated for orchestration systems

## Protected Endpoints

All `/api/v1/*` endpoints are now protected, including:
- Device management (create, delete, list)
- Topology control (create, modify, delete)
- Fidelity mode control
- Interface state manipulation
- Trap and syslog injection
- Scenario management
- Debug endpoints (pprof, CPU profiling)

## Unprotected Endpoints

The following endpoints remain accessible without authentication:
- `/health` - For monitoring and orchestration
- `/`, `/ui` - Web UI static pages
- `/web/*` - Static web assets (CSS, JS)

## Deployment Recommendations

1. **Always enable authentication** for network-exposed deployments (Docker, Kubernetes, cloud)
2. **Use strong API keys** (minimum 32 characters, cryptographically random)
3. **Store keys securely** using secrets management systems
4. **Use HTTPS/TLS** in production (consider a reverse proxy)
5. **Restrict network access** using firewalls or network policies

## Testing

All existing tests continue to pass because:
- Authentication is disabled by default (`apiKeyAuth = ""`)
- Tests that call handlers directly bypass middleware
- Tests that call `setupRoutes()` work with disabled authentication

New tests verify:
- Authentication enforcement when enabled
- Proper error responses for missing/invalid keys
- Exemption of health check and Web UI endpoints
- Uniform protection across all API endpoints

## Backward Compatibility

This patch maintains full backward compatibility:
- Default behavior (no authentication) is unchanged
- Existing deployments continue to work without modification
- Operators can opt-in to authentication by setting `-api-key` or `NL6_API_KEY`
- Clear warnings are logged when authentication is disabled

## Migration Path

For existing deployments:
1. Generate a strong API key: `openssl rand -base64 32`
2. Set `NL6_API_KEY` environment variable or use `-api-key` flag
3. Restart the simulator
4. Update API clients to include `X-API-Key` header
5. Verify authentication is working via logs and test requests
