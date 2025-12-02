# Penetration Test Report: forestadmin-metabase-mcp

**Date**: November 21, 2025
**Tester**: Security Assessment Team
**Target**: https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com
**Test Type**: Black Box + White Box Security Assessment
**Status**: **PASS WITH RECOMMENDATIONS**

---

## Executive Summary

The MCP server has been successfully secured with proper authentication mechanisms. The penetration test confirmed that all critical security measures are working as intended. However, several **medium and low priority** vulnerabilities were identified that should be addressed to achieve a hardened security posture.

### Overall Security Rating: 7.5/10

**Risk Level**: MEDIUM (was CRITICAL before authentication implementation)

---

## Scope of Testing

### In Scope:
- Authentication and authorization mechanisms
- API endpoint security
- Input validation and injection attacks
- Information disclosure vulnerabilities
- Rate limiting and DoS protection
- CORS and HTTP security headers
- Configuration security

### Out of Scope:
- Social engineering attacks
- Physical security
- Client-side applications
- Underlying Heroku infrastructure
- Metabase application security (separate system)

---

## Test Methodology

1. **Reconnaissance**: Information gathering and endpoint discovery
2. **Authentication Testing**: Token validation and bypass attempts
3. **Authorization Testing**: Access control verification
4. **Injection Testing**: SQL, XSS, Path Traversal, Command Injection
5. **Configuration Review**: Security misconfigurations
6. **Code Review**: White box analysis of security implementations
7. **Documentation Review**: Existing security audit assessment

---

## Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 0 | ✅ None Found |
| High | 1 | ⚠️ Found |
| Medium | 3 | ⚠️ Found |
| Low | 2 | ℹ️ Found |
| Info | 3 | ℹ️ Found |

---

## Detailed Findings

### 🔴 HIGH SEVERITY

#### H-1: Publicly Exposed API Documentation

**CVSS Score**: 7.5 (High)
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**:
The FastAPI OpenAPI documentation is publicly accessible at `/docs` and `/openapi.json` without authentication. This exposes the complete API structure, including endpoint details, parameter schemas, and security requirements.

**Evidence**:
```bash
$ curl https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/docs
HTTP/1.1 200 OK
# Returns full Swagger UI interface

$ curl https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/openapi.json
HTTP/1.1 200 OK
{
  "openapi": "3.1.0",
  "paths": {
    "/": {"get": {...}, "post": {...}},
    "/health": {"get": {...}},
    "/sse": {"get": {...}, "post": {...}}
  },
  "components": {
    "securitySchemes": {
      "HTTPBearer": {"type": "http", "scheme": "bearer"}
    }
  }
}
```

**Impact**:
- Attackers gain complete knowledge of API structure
- Security schemes are disclosed (Bearer token authentication)
- Endpoint parameters and schemas are revealed
- Reduces reconnaissance effort for attackers
- May reveal business logic and application architecture

**Recommendation**:
```python
# In server_sse.py
app = FastAPI(
    title="Forest Admin Metabase MCP Server",
    description="MCP server for Metabase with SSE transport for Dust.tt",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,        # Disable /docs
    redoc_url=None,       # Disable /redoc
    openapi_url=None      # Disable /openapi.json
)
```

**Alternative**: Protect with authentication:
```python
from fastapi import Depends

@app.get("/docs", include_in_schema=False)
async def custom_docs(token: str = Depends(verify_mcp_token)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="docs")

@app.get("/openapi.json", include_in_schema=False)
async def custom_openapi(token: str = Depends(verify_mcp_token)):
    return app.openapi()
```

---

### 🟡 MEDIUM SEVERITY

#### M-1: No Rate Limiting Implemented

**CVSS Score**: 5.3 (Medium)
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Description**:
The server does not implement rate limiting on authentication endpoints, allowing unlimited authentication attempts. This enables brute force attacks on the Bearer token.

**Evidence**:
- Sent 100+ consecutive authentication requests
- No rate limiting or throttling observed
- No IP-based blocking mechanism
- All requests processed without delay

**Attack Scenario**:
```bash
# Brute force attack (not executed, but possible)
for i in {1..10000}; do
  curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
    -H "Authorization: Bearer token_$i" \
    -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
done
```

**Impact**:
- Token brute force attacks possible (mitigated by 256-bit entropy)
- Denial of service through resource exhaustion
- No automated threat detection
- Log flooding possible

**Current Mitigations**:
- ✅ Token has 256-bit entropy (2^256 possible values)
- ✅ Failed attempts are logged
- ❌ No rate limiting
- ❌ No IP-based blocking

**Recommendation**:
```python
# Install slowapi
pip install slowapi

# In server_sse.py
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Apply to authentication endpoints
@app.post("/")
@limiter.limit("10/minute")
async def root_post(request: Request, token: str = Depends(verify_mcp_token)):
    ...

# Add stricter limits for failed auth
@app.exception_handler(HTTPException)
async def auth_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code in [401, 403]:
        # Track failed attempts per IP
        # Consider temporary IP blocks after N failures
        pass
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
```

**Priority**: HIGH

---

#### M-2: SQL Injection Protection Using Blacklist

**CVSS Score**: 4.9 (Medium)
**CWE**: CWE-89 (SQL Injection)

**Description**:
The server uses a keyword blacklist approach for SQL injection protection instead of parameterized queries or allowlisting. While currently preventing write operations, this approach is brittle and can be bypassed.

**Code Review**:
```python
# In metabase_client.py:191
forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE"]
for keyword in forbidden:
    if query_upper.startswith(keyword) or f" {keyword} " in f" {query_upper} ":
        raise ValueError(f"Forbidden keyword: {keyword}")
```

**Known Bypass Techniques** (theoretical):
1. **Case variations**: `InSeRt` (mitigated by `.upper()`)
2. **Comment injection**: `SELECT * FROM users; --INSERT malicious`
3. **Encoded keywords**: Using URL encoding or hex encoding
4. **Subqueries**: `SELECT * FROM (SELECT * FROM users)`
5. **Unicode alternatives**: Using Unicode lookalikes

**Current Limitations**:
- Only checks for specific keywords at start or with spaces
- Doesn't prevent: `SELECT * FROM users;DELETE FROM logs`
- Doesn't validate query structure
- No parameterization of user input

**Impact**:
- Potential for bypass if blacklist is incomplete
- Read-only queries can still expose sensitive data
- No protection against UNION-based injection
- Difficult to maintain as SQL features evolve

**Recommendation**:
```python
# Option 1: Use Metabase's parameterized queries
async def execute_query(
    self,
    database_id: int,
    query: str,
    parameters: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Execute query with parameterization."""

    # Define query template with parameters
    template_tags = {}
    if parameters:
        for key, value in parameters.items():
            template_tags[key] = {
                "type": "text",  # or "number", "date", etc.
                "required": True,
                "default": None
            }

    payload = {
        "database": database_id,
        "type": "native",
        "native": {
            "query": query,
            "template-tags": template_tags
        },
        "parameters": [
            {"type": k, "target": ["variable", ["template-tag", k]], "value": v}
            for k, v in (parameters or {}).items()
        ]
    }

    # Metabase handles parameterization safely
    ...

# Option 2: Use allowlist approach
ALLOWED_SQL_COMMANDS = ["SELECT", "WITH"]
ALLOWED_SQL_FUNCTIONS = ["COUNT", "SUM", "AVG", "MAX", "MIN", "GROUP BY", "ORDER BY"]

def validate_read_only_query(query: str) -> bool:
    query_upper = query.strip().upper()

    # Must start with allowed command
    if not any(query_upper.startswith(cmd) for cmd in ALLOWED_SQL_COMMANDS):
        return False

    # Check for forbidden operations
    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
                 "TRUNCATE", "GRANT", "REVOKE", "EXEC", "EXECUTE",
                 "INTO", "INFORMATION_SCHEMA", "PG_"]

    for keyword in forbidden:
        if keyword in query_upper:
            return False

    return True
```

**Priority**: MEDIUM

---

#### M-3: No Request Size Limits

**CVSS Score**: 4.3 (Medium)
**CWE**: CWE-400 (Uncontrolled Resource Consumption)

**Description**:
The server does not enforce request body size limits, potentially allowing memory exhaustion attacks through large payloads.

**Evidence**:
```bash
# Attempted to send large Content-Length header
$ curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -H "Content-Length: 999999999" \
  -d '{"jsonrpc":"2.0"}'
# Request hung for 60+ seconds before timing out
```

**Impact**:
- Memory exhaustion attacks
- Denial of service
- Slowloris-style attacks
- Resource waste

**Recommendation**:
```python
# Add middleware for request size limits
from starlette.middleware.base import BaseHTTPMiddleware

class LimitUploadSize(BaseHTTPMiddleware):
    def __init__(self, app, max_upload_size: int):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.max_upload_size:
                return Response(
                    content="Request too large",
                    status_code=413
                )
        return await call_next(request)

# Apply middleware
app.add_middleware(LimitUploadSize, max_upload_size=1_000_000)  # 1MB limit
```

**Priority**: MEDIUM

---

### 🔵 LOW SEVERITY

#### L-1: Verbose Error Messages in Logs

**CVSS Score**: 3.1 (Low)
**CWE**: CWE-209 (Generation of Error Message Containing Sensitive Information)

**Description**:
The server logs the first 10 characters of invalid tokens, which could aid attackers in token analysis.

**Code Reference**:
```python
# In server_sse.py:64
logger.warning(f"Invalid authentication attempt from token: {credentials.credentials[:10]}...")
```

**Impact**:
- Token prefix disclosure in logs
- Pattern analysis possible if logs are compromised
- Minimal risk due to token entropy

**Recommendation**:
```python
# Option 1: Hash the token before logging
import hashlib

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()[:16]

logger.warning(f"Invalid authentication attempt, token hash: {hash_token(credentials.credentials)}")

# Option 2: Just log that an invalid attempt occurred
logger.warning("Invalid authentication attempt from IP: {request.client.host}")
```

**Priority**: LOW

---

#### L-2: Missing Security Headers

**CVSS Score**: 3.7 (Low)
**CWE**: CWE-693 (Protection Mechanism Failure)

**Description**:
The server does not set recommended HTTP security headers.

**Missing Headers**:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Content-Security-Policy`
- `Referrer-Policy: no-referrer`

**Evidence**:
```bash
$ curl -I https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/
# No security headers present except Heroku defaults
```

**Impact**:
- Potential for clickjacking (mitigated by JSON API)
- MIME sniffing vulnerabilities
- XSS in certain scenarios

**Recommendation**:
```python
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"

    # HSTS is handled by Heroku, but can be added
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response
```

**Priority**: LOW

---

### ℹ️ INFORMATIONAL

#### I-1: Metabase URL Disclosure

**Severity**: Informational
**Description**: The health endpoint reveals the Metabase backend URL (`https://forestadmin-bi.herokuapp.com`).

**Evidence**:
```bash
$ curl https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/health
{"status":"healthy","metabase_client":"initialized","metabase_url":"https://forestadmin-bi.herokuapp.com"}
```

**Impact**: Minimal - backend URL is likely already known or easily discoverable.

**Recommendation**: Consider removing URL from public endpoint or requiring authentication.

---

#### I-2: Server Fingerprinting

**Severity**: Informational
**Description**: Server headers reveal technology stack.

**Evidence**:
```
Server: Heroku
Via: 1.1 heroku-router
```

**Impact**: Minimal - standard Heroku configuration.

**Recommendation**: No action required unless stealth is critical.

---

#### I-3: No CORS Configuration

**Severity**: Informational
**Description**: No CORS headers are configured (default deny).

**Evidence**: No `Access-Control-Allow-Origin` headers present.

**Impact**: Positive - restricts cross-origin requests by default.

**Recommendation**: Keep current configuration unless browser-based access is needed.

---

## Positive Security Controls Verified

### ✅ Authentication & Authorization
- **Bearer Token Authentication**: Working correctly on all protected endpoints
- **401 Unauthorized**: Properly returned when token is missing
- **403 Forbidden**: Properly returned when token is invalid
- **Token Validation**: Constant-time comparison (no timing attacks)
- **Public Endpoints**: Correctly exempt from authentication (`/health`, `/` GET without SSE)

### ✅ Endpoint Security
- **SSE Endpoint Protection**: Both GET and POST `/sse` require authentication
- **Root Endpoint Protection**: POST requests require authentication
- **Health Check**: Accessible without authentication (by design)
- **Method Restrictions**: OPTIONS returns 405 Method Not Allowed

### ✅ Input Validation
- **JSON-RPC Validation**: Malformed requests handled gracefully
- **SQL Keyword Blacklist**: Prevents obvious write operations
- **Query Validation**: Basic checks in place

### ✅ Configuration Security
- **Token Storage**: Stored in environment variables (not hardcoded)
- **Token Entropy**: 256-bit random token (64 hex characters)
- **HTTPS**: Enforced by Heroku
- **No Git Secrets**: `.env` properly gitignored

### ✅ Logging & Monitoring
- **Authentication Attempts**: Logged with appropriate detail
- **Failed Auth**: Logged with partial token (first 10 chars)
- **Request Metadata**: Captured by Heroku router

---

## Attack Scenarios Tested

### ❌ Failed Attack Attempts (Security Working)

1. **Authentication Bypass**
   - Empty Bearer token: ❌ Blocked
   - Invalid token: ❌ Blocked
   - Basic auth instead of Bearer: ❌ Blocked
   - X-API-KEY header: ❌ Blocked
   - SQL injection in token: ❌ Blocked

2. **Path Traversal**
   - `../../../etc/passwd` in method field: ❌ Blocked (auth required first)

3. **XSS Attempts**
   - Script tags in method field: ❌ Blocked (auth required first)

4. **JSON-RPC Injection**
   - SQL injection in ID field: ❌ Blocked (auth required first)

5. **Unauthorized Access**
   - All authenticated endpoints: ❌ Blocked without valid token
   - SSE streaming: ❌ Blocked without valid token

---

## Recommendations Summary

### 🔴 Critical Priority (Implement Immediately)
1. **Disable or Protect API Documentation** (`/docs`, `/openapi.json`)
   - Est. Time: 5 minutes
   - Risk Reduction: Significant

### 🟡 High Priority (Implement Within 1 Week)
2. **Implement Rate Limiting**
   - Est. Time: 2-4 hours
   - Risk Reduction: High
   - Tools: `slowapi` library

### 🟢 Medium Priority (Implement Within 1 Month)
3. **Replace SQL Blacklist with Parameterized Queries**
   - Est. Time: 4-8 hours
   - Risk Reduction: Medium
   - Requires: Metabase API changes

4. **Add Request Size Limits**
   - Est. Time: 1-2 hours
   - Risk Reduction: Medium
   - Max size: 1MB recommended

5. **Improve Token Logging**
   - Est. Time: 1 hour
   - Risk Reduction: Low
   - Use hashing instead of prefixes

### 🔵 Low Priority (Nice to Have)
6. **Add Security Headers**
   - Est. Time: 1 hour
   - Risk Reduction: Low
   - Defense in depth

7. **Remove URL from Health Endpoint**
   - Est. Time: 15 minutes
   - Risk Reduction: Minimal

---

## Compliance Assessment

### OWASP Top 10 (2021)
- ✅ A01: Broken Access Control - **PROTECTED**
- ✅ A02: Cryptographic Failures - **PROTECTED** (HTTPS, token storage)
- ⚠️ A03: Injection - **PARTIALLY PROTECTED** (blacklist approach)
- ✅ A04: Insecure Design - **GOOD** (authentication model sound)
- ⚠️ A05: Security Misconfiguration - **NEEDS IMPROVEMENT** (public docs)
- ✅ A06: Vulnerable Components - **PROTECTED** (dependencies up-to-date)
- ✅ A07: Authentication Failures - **PROTECTED** (strong token auth)
- ⚠️ A08: Software & Data Integrity - **PARTIAL** (no integrity checks)
- ⚠️ A09: Logging Failures - **PARTIAL** (no alerting)
- ✅ A10: SSRF - **NOT APPLICABLE** (no user-controlled URLs)

---

## Comparison to Previous Audit

### Before Security Fix (Commit: pre-503c1e7)
- **Status**: 🔴 CRITICAL
- **Authentication**: ❌ None
- **Public Access**: ❌ All endpoints exposed
- **Data Exposure**: ❌ Complete

### After Security Fix (Commit: 503c1e7)
- **Status**: ✅ SECURE
- **Authentication**: ✅ Bearer token on all endpoints
- **Public Access**: ✅ Only health and info endpoints
- **Data Exposure**: ✅ Protected

### Current Assessment (Pentest Results)
- **Status**: ⚠️ SECURE WITH RECOMMENDATIONS
- **Authentication**: ✅ Working correctly
- **Rate Limiting**: ❌ Missing
- **API Documentation**: ⚠️ Publicly exposed
- **SQL Protection**: ⚠️ Blacklist approach

---

## Remediation Code Examples

### 1. Disable API Documentation (CRITICAL)
```python
# server_sse.py
app = FastAPI(
    title="Forest Admin Metabase MCP Server",
    description="MCP server for Metabase with SSE transport for Dust.tt",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,        # ADD THIS
    redoc_url=None,       # ADD THIS
    openapi_url=None      # ADD THIS
)
```

### 2. Add Rate Limiting (HIGH)
```bash
# requirements.txt
slowapi==0.1.9
```

```python
# server_sse.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/")
@limiter.limit("20/minute")  # 20 requests per minute
async def root_post(request: Request, token: str = Depends(verify_mcp_token)):
    ...

@app.post("/sse")
@limiter.limit("20/minute")
async def handle_sse_post(request: Request, token: str = Depends(verify_mcp_token)):
    ...
```

### 3. Add Request Size Limits (MEDIUM)
```python
# server_sse.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class LimitUploadSize(BaseHTTPMiddleware):
    def __init__(self, app, max_upload_size: int):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            if "content-length" in request.headers:
                content_length = int(request.headers["content-length"])
                if content_length > self.max_upload_size:
                    return Response("Payload too large", status_code=413)
        return await call_next(request)

app.add_middleware(LimitUploadSize, max_upload_size=1_000_000)  # 1MB
```

### 4. Add Security Headers (LOW)
```python
# server_sse.py
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
```

---

## Testing Evidence

### Successful Authentication Tests
```bash
# Test 1: No authentication
$ curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -d '{"jsonrpc":"2.0","method":"tools/list"}'
Response: 401 Unauthorized ✅

# Test 2: Invalid token
$ curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -H "Authorization: Bearer invalid_token" \
  -d '{"jsonrpc":"2.0","method":"tools/list"}'
Response: 403 Forbidden ✅

# Test 3: Empty token
$ curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -H "Authorization: Bearer " \
  -d '{"jsonrpc":"2.0","method":"tools/list"}'
Response: 401 Unauthorized ✅

# Test 4: SSE endpoint without auth
$ curl -X GET https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/sse
Response: 401 Unauthorized ✅

# Test 5: Health check (public)
$ curl -X GET https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/health
Response: 200 OK ✅
```

---

## Conclusion

The Forest Admin Metabase MCP Server has **successfully implemented critical security controls** and is **suitable for production use** after addressing the HIGH priority finding (API documentation exposure).

### Key Strengths:
- ✅ Strong authentication mechanism (256-bit Bearer token)
- ✅ Proper authorization on all sensitive endpoints
- ✅ Good separation of public and protected endpoints
- ✅ Secure token storage (environment variables)
- ✅ HTTPS enforcement
- ✅ Comprehensive logging

### Key Improvements Needed:
- ⚠️ Disable or protect API documentation (CRITICAL)
- ⚠️ Implement rate limiting (HIGH)
- ⚠️ Replace SQL blacklist with parameterized queries (MEDIUM)
- ⚠️ Add request size limits (MEDIUM)

### Security Posture:
**PASS** - The server is secure enough for production deployment after addressing the publicly exposed API documentation. The authentication mechanism is robust and working correctly.

---

**Report Prepared By**: Security Assessment Team
**Report Date**: November 21, 2025
**Next Review**: Recommended after implementing HIGH priority fixes
**Classification**: Internal Use Only

---

## Appendix A: Token Entropy Analysis

**Current Token**: `<redacted>`
- **Length**: 64 hex characters
- **Bits of Entropy**: 256 bits (64 × 4)
- **Possible Values**: 2^256 = 1.16 × 10^77
- **Brute Force Time** (at 1 billion attempts/second): 3.67 × 10^60 years

**Conclusion**: Token entropy is excellent and brute force attacks are computationally infeasible.

---

## Appendix B: Test Request Logs

All test requests were non-destructive and authorized as part of this security assessment. Log samples available upon request.

---

## Appendix C: References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- CWE Top 25: https://cwe.mitre.org/top25/
- CVSS v3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- FastAPI Security Best Practices: https://fastapi.tiangolo.com/tutorial/security/
- NIST Password Guidelines: https://pages.nist.gov/800-63-3/

---

**END OF REPORT**
