# MEDUSA Tools Integration

This directory contains documentation for all integrated security tools used in MEDUSA for reconnaissance, enumeration, and exploitation.

## Tool Categories

### Reconnaissance Tools
- **Amass** - Subdomain enumeration and discovery
- **httpx** - Web server validation and detection

### Initial Access Tools  
- **Kerbrute** - Kerberos user enumeration and authentication attacks
- **SQLMap** - SQL injection detection and exploitation

### Scanning Tools
- **Nmap** - Network reconnaissance and service detection
- **Web Scanner** - Web application scanning

## Quick Reference

| Tool | Purpose | Risk | Approval | Status |
|------|---------|------|----------|--------|
| Amass | Subdomain enumeration | LOW | Auto | ✅ Ready |
| httpx | Web server validation | LOW | Auto | ✅ Ready |
| Kerbrute (enum) | User enumeration | MEDIUM | Required | ✅ Ready |
| Kerbrute (spray) | Password testing | HIGH | Required | ✅ Ready |
| SQLMap (level 1-2) | SQLi detection | MEDIUM | Required | ✅ Ready |
| SQLMap (level 3+) | SQLi exploitation | HIGH | Required | ✅ Ready |
| Nmap | Port scanning | LOW | Auto | ✅ Ready |

## Recommended Workflow

### Stage 1: Passive Reconnaissance
```
1. Amass (passive) → Discovers subdomains
2. httpx → Validates which are live
3. LLM prioritizes targets
```

### Stage 2: Active Reconnaissance  
```
4. Nmap → Deep port scans on live targets
5. Web Scanner → Application discovery
```

### Stage 3: Initial Access
```
6. Kerbrute (userenum) → Discover valid users
7. SQLMap (level 1-2) → Test for SQLi
8. Kerbrute (passwordspray) → Attempt authentication
```

## Integration Points

All tools are integrated through the `MedusaClient` which provides:

- **Automatic installation checks** - Verifies tools are available
- **Standardized output** - All tools return consistent JSON structures
- **Error handling** - Graceful degradation if tools fail
- **Approval gates** - Risk-based approval for dangerous operations
- **Logging** - Full audit trail of all operations

## Configuration

### Environment Variables

```bash
# LLM Configuration
export GEMINI_API_KEY="your-api-key"
export MEDUSA_LLM_MODEL="mistral:7b-instruct"

# Ollama (for local LLM)
export OLLAMA_URL="http://localhost:11434"
```

### Via MedusaClient

```python
from medusa.client import MedusaClient

client = MedusaClient(
    base_url="http://localhost:5000",
    api_key="your-api-key",
    llm_config={
        "model": "gemini-pro",
        "temperature": 0.7,
        "mock_mode": False
    }
)
```

## Next Steps

- [Amass Documentation](./AMASS.md)
- [httpx Documentation](./HTTPX.md)  
- [Kerbrute Documentation](./KERBRUTE.md)
- [SQLMap Documentation](./SQLMAP.md)
- [Installation Guide](./INSTALLATION.md)

