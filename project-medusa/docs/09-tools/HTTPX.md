# httpx Integration

## Overview

httpx is a fast HTTP toolkit for probing web services. It validates which discovered subdomains have live HTTP/HTTPS services and gathers web server information.

**Purpose**: Validate live targets and gather web server fingerprints  
**Phase**: Reconnaissance (Stage 1)  
**Risk Level**: LOW (Passive HTTP probes)  
**Approval**: Automatic

## How httpx Works in MEDUSA

After Amass discovers subdomains, httpx:
1. Makes HTTP/HTTPS requests to each target
2. Checks HTTP status codes (200-299 = live)
3. Gathers web server headers and technologies
4. Filters to only active web servers
5. Passes validated targets to Nmap for deeper scanning

## Usage

### Basic Web Server Validation

```python
from medusa.client import MedusaClient

client = MedusaClient(...)

targets = [
    "https://admin.example.com",
    "https://api.example.com",
    "https://internal.example.com"
]

result = await client.validate_web_targets(targets)

for finding in result['findings']:
    print(f"{finding['url']}: {finding['status_code']} - {finding['web_server']}")
```

### Direct Tool Usage

```python
from medusa.tools.httpx_scanner import HttpxScanner

scanner = HttpxScanner(timeout=120, threads=50)

# Quick validation
result = await scanner.quick_validate(targets)

# Deep probing with redirects
result = await scanner.deep_probe(targets)

# Custom configuration
result = await scanner.validate_servers(
    targets=targets,
    threads=25,
    follow_redirects=True,
    timeout_per_request=10,
    status_codes=list(range(200, 300))
)
```

## Configuration Options

| Option | Values | Default | Description |
|--------|--------|---------|-------------|
| `targets` | list | Required | URLs or domains to probe |
| `threads` | int | 50 | Concurrent requests |
| `timeout_per_request` | int | 5 | Timeout per request (seconds) |
| `follow_redirects` | bool | False | Follow HTTP redirects |
| `status_codes` | list | 200-299 | Codes to consider "live" |

## Output Format

```json
{
  "success": true,
  "tool": "httpx",
  "findings_count": 3,
  "findings": [
    {
      "type": "web_server_detection",
      "url": "https://api.example.com",
      "status_code": 200,
      "status_text": "OK",
      "web_server": "nginx/1.21.0",
      "content_type": "application/json",
      "content_length": 1234,
      "title": "API Documentation",
      "technologies": ["Node.js", "Express"],
      "ssl": true,
      "severity": "medium",
      "confidence": "high"
    }
  ],
  "duration_seconds": 8.5,
  "metadata": {
    "targets_checked": 10,
    "live_servers": 3,
    "threads_used": 50
  }
}
```

## Command Line Usage

### Basic Probing

```bash
httpx -l targets.txt -json -o results.json
```

### With Threading

```bash
httpx -l targets.txt \
  -threads 100 \
  -timeout 10 \
  -json -o results.json
```

### Follow Redirects

```bash
httpx -l targets.txt \
  -follow-redirects \
  -json -o results.json
```

## Integration Workflow

### Complete Reconnaissance Chain

```python
# Step 1: Amass discovers subdomains
subdomains = await client.perform_subdomain_enumeration("example.com")

# Step 2: LLM prioritizes targets
prioritized = await client.prioritize_reconnaissance_targets(subdomains['findings'])

# Step 3: httpx validates which are live
targets = [f['target'] for f in prioritized['prioritized_targets']]
live_servers = await client.validate_web_targets(targets)

# Step 4: Nmap scans live targets
for server in live_servers['findings']:
    nmap_results = await client.nmap.execute(server['url'])
```

## Common HTTP Status Codes

| Code | Meaning | Action |
|------|---------|--------|
| 200 | OK | ✅ Live server, process normally |
| 301/302 | Redirect | ⏩ Follow if configured |
| 401 | Unauthorized | ⚠️ Service exists, needs auth |
| 403 | Forbidden | ⚠️ Service exists, restricted |
| 404 | Not Found | ❌ No service on this path |
| 500 | Server Error | ⚠️ Service exists but broken |
| Timeout | No response | ❌ Not reachable |

## Web Server Fingerprinting

httpx identifies technologies from headers:

```json
{
  "web_server": "nginx/1.21.0",
  "technologies": ["PHP", "MySQL", "Bootstrap"],
  "content_type": "text/html; charset=UTF-8",
  "title": "Admin Dashboard"
}
```

Use this for:
- Known vulnerability matching (old nginx = potential exploit)
- Technology stack understanding
- API endpoint detection (application/json type)
- Default page identification

## Performance Optimization

### For Many Targets

```python
# Increase threads
result = await scanner.validate_servers(
    targets=many_targets,
    threads=200,  # More threads
    timeout_per_request=5
)
```

### For Quality Over Speed

```python
# Fewer threads, more careful probing
result = await scanner.validate_servers(
    targets=targets,
    threads=10,
    follow_redirects=True,  # Don't miss redirected services
    timeout_per_request=15
)
```

## Troubleshooting

### Getting Timeouts

```python
# Increase timeout
result = await scanner.validate_servers(
    targets=targets,
    timeout_per_request=30
)
```

### Low Server Detection Rate

```python
# Enable redirect following
result = await scanner.validate_servers(
    targets=targets,
    follow_redirects=True
)

# Lower status code threshold
result = await scanner.validate_servers(
    targets=targets,
    status_codes=[200, 301, 302, 400, 401, 403]
)
```

### SSL Certificate Issues

httpx handles HTTPS gracefully:
- Accepts self-signed certificates
- Handles expired certificates
- Detects plaintext vs SSL

Use technology detection to find services:

```python
services = {
    "http": [f for f in results if f['ssl'] is False],
    "https": [f for f in results if f['ssl'] is True],
    "self_signed": [f for f in results if f['ssl_error']],
}
```

## Security Considerations

### Safe Practices
✅ Makes standard HTTP requests  
✅ Respects robots.txt (if configured)  
✅ Doesn't attempt exploitation  
✅ No payloads sent  

### Detection Risks
⚠️ Easily visible in web logs  
⚠️ Multiple requests from same source  
⚠️ User-Agent strings are identifiable  
⚠️ Can trigger rate limiting

### Mitigation
- Use reasonable thread counts (50-100, not 1000)
- Add delays between requests if needed
- Use legitimate User-Agent strings
- Respect target rate limiting

## Installation

### Linux
```bash
# Go binary
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Ubuntu/Debian
apt install httpx-toolkit
```

### macOS
```bash
brew install httpx
```

### Docker
```bash
docker run projectdiscovery/httpx:latest
```

## Advanced Usage

### Custom Headers

```python
# Via MedusaClient (if supported)
result = await scanner.validate_servers(
    targets=targets,
    headers={"Authorization": "Bearer token"}
)
```

### Proxy Support

```bash
# Via command line
httpx -l targets.txt -proxy "http://proxy:8080"
```

## Tips & Tricks

1. **Combine with Amass output directly**
   ```bash
   amass enum -d example.com -json | \
   jq -r '.name' | \
   httpx -json -o results.json
   ```

2. **Filter high-value targets**
   ```python
   api_servers = [f for f in results if 'api' in f['title'].lower()]
   admin_servers = [f for f in results if 'admin' in f['title'].lower()]
   ```

3. **Track technology trends**
   ```python
   tech_counts = {}
   for finding in results:
       for tech in finding['technologies']:
           tech_counts[tech] = tech_counts.get(tech, 0) + 1
   ```

## References

- [httpx GitHub](https://github.com/projectdiscovery/httpx)
- [httpx Documentation](https://github.com/projectdiscovery/httpx#usage)
- [MITRE ATT&CK T1592.004](https://attack.mitre.org/techniques/T1592/004/)

