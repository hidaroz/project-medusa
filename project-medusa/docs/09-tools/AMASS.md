# Amass Integration

## Overview

Amass is a comprehensive subdomain enumeration tool used in the reconnaissance phase. It discovers subdomains through passive and active DNS enumeration, certificate transparency logs, and other data sources.

**Purpose**: Build comprehensive target list before active scanning  
**Phase**: Reconnaissance (Stage 1)  
**Risk Level**: LOW (Passive mode default)  
**Approval**: Automatic

## How Amass Works in MEDUSA

### Passive Enumeration (Default)
- Queries public DNS records
- Searches Certificate Transparency logs
- Uses public data sources only
- No direct network traffic to target
- Slower but detection-resistant

### Active Enumeration
- Performs DNS zone transfers
- Brute-forces common subdomains
- More aggressive scanning
- Higher detection risk
- Faster results

## Usage

### Basic Subdomain Enumeration

```python
from medusa.client import MedusaClient

client = MedusaClient(...)

# Passive enumeration (safe default)
result = await client.perform_subdomain_enumeration(
    domain="example.com",
    passive=True
)

# Check results
print(f"Found {result['findings_count']} subdomains")
for finding in result['findings']:
    print(f"  {finding['subdomain']} -> {finding['ip_addresses']}")
```

### Direct Tool Usage

```python
from medusa.tools.amass import AmassScanner

scanner = AmassScanner(timeout=300, passive=True)

# Quick passive enumeration
result = await scanner.quick_enum("example.com")

# Deep active enumeration (risky)
result = await scanner.deep_enum("example.com")

# Custom configuration
result = await scanner.enumerate_subdomains(
    domain="example.com",
    passive=False,  # Active enumeration
    sources=["dns", "certs"],  # Specific sources
    rate_limit=50  # Requests per second
)
```

## Configuration Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `domain` | string | Required | Target domain |
| `passive` | bool | True | Passive enumeration only |
| `timeout` | int | 300 | Max execution time (seconds) |
| `rate_limit` | int | 100 | Requests per second limit |
| `sources` | list | All | Specific data sources to use |

### Available Data Sources

- `dns` - DNS queries and DNS-over-HTTPS
- `certs` - Certificate Transparency logs
- `archive` - Internet Archive (Wayback Machine)
- `shodan` - Shodan.io database
- `censys` - Censys.io database

## Output Format

```json
{
  "success": true,
  "tool": "amass",
  "findings_count": 42,
  "findings": [
    {
      "type": "subdomain_enumeration",
      "subdomain": "api.example.com",
      "domain": "example.com",
      "ip_addresses": ["1.2.3.4", "1.2.3.5"],
      "sources": ["DNS", "Certificate"],
      "confidence": "high",
      "severity": "low"
    }
  ],
  "duration_seconds": 120,
  "metadata": {
    "enumeration_mode": "passive",
    "unique_ips": ["1.2.3.4", "1.2.3.5"],
    "data_sources": ["DNS", "Certificate"]
  }
}
```

## Command Line Usage

### Passive Enumeration

```bash
amass enum -d example.com -passive -json -o results.json
```

### Active Enumeration with Rate Limiting

```bash
amass enum -d example.com \
  -rate-limit 50 \
  -json -o results.json
```

### Specific Data Sources

```bash
amass enum -d example.com \
  -passive \
  -src dns,certs \
  -json -o results.json
```

## Integration with Other Tools

### Step 1: Amass Enumeration
```python
amass_results = await client.perform_subdomain_enumeration("example.com")
```

### Step 2: LLM Prioritization
```python
prioritized = await client.prioritize_reconnaissance_targets(amass_results['findings'])
```

### Step 3: httpx Validation
```python
targets = [f['subdomain'] for f in prioritized['prioritized_targets']]
validated = await client.validate_web_targets(targets)
```

### Step 4: Nmap Deep Scanning
```python
for target in validated['findings']:
    nmap_results = await client.nmap.execute(target['url'])
```

## Safety Considerations

### Passive Mode (Recommended)
✅ No direct network traffic to target  
✅ Cannot trigger IDS/IPS  
✅ Uses public data only  
✅ No false IP associations  
✗ Takes longer

### Active Mode (Risky)
✗ Sends queries directly to target infrastructure  
✗ Can trigger IDS/IPS alerts  
✗ May cause DNS cache poisoning  
✓ Faster results  
⚠️ Requires explicit approval

## Troubleshooting

### No Subdomains Found

```python
# Check if Amass is installed
scanner = AmassScanner()
if not scanner.is_available():
    print("Amass not installed")

# Try with specific sources
result = await scanner.enumerate_subdomains(
    domain="example.com",
    sources=["dns"]  # Use DNS only
)
```

### Timeout Errors

```python
# Increase timeout for large domains
scanner = AmassScanner(timeout=600)  # 10 minutes

# Limit scope with rate limiting
result = await scanner.enumerate_subdomains(
    domain="example.com",
    rate_limit=200  # Very conservative
)
```

### Low Confidence Results

Amass confidence levels help identify reliable subdomains:

- `high` - Multiple sources confirmed
- `medium` - Single or weak confirmation
- `low` - Speculative discovery

Filter by confidence:

```python
high_confidence = [
    f for f in results['findings']
    if f['confidence'] == 'high'
]
```

## Security Best Practices

1. **Use passive mode by default** - No need for active scanning in reconnaissance
2. **Filter results by confidence** - Only trust multi-source findings
3. **Check for IP consistency** - Same subdomain shouldn't resolve to many different IPs
4. **Combine with httpx** - Validate discovered subdomains have actual services
5. **Monitor execution time** - Unusually long times may indicate network issues

## Performance Tips

### For Large Domains
```python
# Use specific sources to speed up
result = await scanner.enumerate_subdomains(
    domain="very-large-domain.com",
    sources=["dns"],  # Only DNS, skip certs
    rate_limit=200  # Conservative
)
```

### For Speed
```python
# Increase rate limit
result = await scanner.enumerate_subdomains(
    domain="example.com",
    rate_limit=50  # More aggressive
)
```

## Installation

### Linux/macOS
```bash
# Debian/Ubuntu
sudo apt install amass

# macOS
brew install amass
```

### Docker
```bash
docker run -v /path/to/config:/etc/amass \
  caffix/amass:latest enum -d example.com
```

### From Source
```bash
go install -v github.com/OWASP/Amass/v4/cmd/amass@latest
```

## References

- [Amass GitHub](https://github.com/OWASP/Amass)
- [Amass Documentation](https://owasp.org/www-project-amass/)
- [MITRE ATT&CK T1590.002](https://attack.mitre.org/techniques/T1590/002/)

