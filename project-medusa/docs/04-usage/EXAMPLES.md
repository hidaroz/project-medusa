# MEDUSA Command Examples

Real-world examples for common penetration testing scenarios.

## Table of Contents

1. [Web Application Testing](#web-application-testing)
2. [Network Scanning](#network-scanning)
3. [API Security Testing](#api-security-testing)
4. [Interactive Mode Examples](#interactive-mode-examples)
5. [Report Generation](#report-generation)
6. [Advanced Usage](#advanced-usage)

---

## Web Application Testing

### Example 1: Basic Web App Scan

**Scenario:** Test a web application for common vulnerabilities

```bash
# Full automated scan
medusa run \
  --target https://webapp.example.com \
  --mode auto \
  --risk-tolerance medium
```

**What it does:**
1. Port scan (80, 443)
2. Technology detection (WordPress, PHP, etc.)
3. Directory enumeration (/admin, /api, /backup)
4. SQL injection testing
5. XSS testing
6. Misconfiguration checks

**Expected findings:**
- Exposed admin panels
- SQL injection vulnerabilities
- Missing security headers
- Outdated software versions

**Duration:** 5-15 minutes

---

### Example 2: WordPress Site Assessment

**Scenario:** Security audit of WordPress website

```bash
# Targeted WordPress scan
medusa run \
  --target https://blog.example.com \
  --mode auto \
  --target-type wordpress \
  --check-plugins
```

**Checks for:**
- WordPress version vulnerabilities
- Plugin vulnerabilities
- Theme vulnerabilities
- wp-admin exposure
- xmlrpc.php abuse potential
- Weak password policies

**Duration:** 10-20 minutes

---

### Example 3: Safe Production Testing

**Scenario:** Test production app without exploitation

```bash
# Step 1: Reconnaissance only
medusa observe https://production-app.com

# Step 2: Review findings
medusa reports --latest

# Step 3: If approved, controlled testing
medusa shell
MEDUSA> set target https://production-app.com
MEDUSA> scan vulnerability --level 1 --no-exploit
MEDUSA> show findings
```

**Benefits:**
- Non-intrusive testing
- No risk of disruption
- Easy to review before going deeper
- Can be run on production safely

---

## Network Scanning

### Example 4: Internal Network Discovery

**Scenario:** Discover hosts and services on internal network

```bash
# Scan entire subnet
medusa run \
  --target 192.168.1.0/24 \
  --mode network \
  --timeout 300
```

**Discovers:**
- Live hosts
- Open ports per host
- Running services
- OS fingerprints
- Service versions

**Duration:** 5-30 minutes (depending on network size)

---

### Example 5: Single Host Deep Scan

**Scenario:** Comprehensive scan of single target

```bash
# Deep port scan + service detection
medusa run \
  --target 192.168.1.100 \
  --ports 1-65535 \
  --scan-type aggressive \
  --service-detection
```

**Finds:**
- All open ports (not just common ones)
- Detailed service versions
- OS detection
- Traceroute information
- Service banners

**Duration:** 30-60 minutes (full port scan)

---

### Example 6: Quick Network Sweep

**Scenario:** Fast initial reconnaissance of network

```bash
# Quick scan (common ports only)
medusa run \
  --target 192.168.1.0/24 \
  --mode network \
  --quick
```

**Covers:**
- Common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443
- Service identification
- Basic OS detection

**Duration:** 5-10 minutes

---

## API Security Testing

### Example 7: REST API Testing

**Scenario:** Test REST API for vulnerabilities

```bash
# API-focused scan
medusa run \
  --target https://api.example.com \
  --mode api \
  --check-auth \
  --check-rate-limiting \
  --check-injection
```

**Tests for:**
- Broken authentication
- Missing rate limiting
- SQL/NoSQL injection
- Mass assignment vulnerabilities
- IDOR (Insecure Direct Object Reference)
- Missing input validation

**Duration:** 10-20 minutes

---

### Example 8: GraphQL API Testing

**Scenario:** Test GraphQL endpoint security

```bash
# GraphQL-specific tests
medusa run \
  --target https://api.example.com/graphql \
  --mode graphql \
  --check-introspection \
  --check-batching \
  --check-depth-limit
```

**Tests for:**
- Introspection enabled (information disclosure)
- Query batching attacks
- Query depth attacks
- Field suggestions exposure
- Authentication bypass

**Duration:** 10-15 minutes

---

### Example 9: API Rate Limiting Test

**Scenario:** Test if API enforces rate limiting

```bash
# Slow, careful rate limit testing
medusa run \
  --target https://api.example.com \
  --mode api \
  --rate-limit 10 \      # Max 10 requests/second
  --check-rate-limit
```

**Tests:**
- Request rate limits
- IP-based rate limiting
- User-based rate limiting
- Time-window calculations

---

## Interactive Mode Examples

### Example 10: Guided Web App Test

```bash
medusa shell
```

**Session transcript:**

```
MEDUSA> set target https://testapp.local
✓ Target set to https://testapp.local

MEDUSA> scan network
⚡ Scanning ports 1-1000...
✓ Found 2 open ports:
  • 80/tcp - HTTP (nginx 1.21.0)
  • 443/tcp - HTTPS

MEDUSA> enumerate web
⚡ Enumerating web paths...
✓ Found 15 paths:
  [HIGH] /admin - Admin panel (no auth)
  [MEDIUM] /api - API documentation exposed
  [LOW] /.git - Git directory exposed

MEDUSA> test sqli /api/search?q=
⚡ Testing SQL injection...
✓ Found SQL injection:
  [CRITICAL] /api/search?q= - Boolean-based blind SQLi

MEDUSA> suggestions
💡 Based on findings, you might:
  1. exploit sqli /api/search - Extract database
  2. check admin panel - Test default credentials
  3. enumerate api endpoints - Find more attack surface

MEDUSA> exploit sqli /api/search
⚠️  This action requires approval (HIGH risk)

    Impact: Database access, data exfiltration

    Approve? (yes/no): yes

⚡ Exploiting SQL injection...
✓ Database accessed: mysql_testapp
✓ Extracted 3 tables:
  • users (1,234 rows)
  • orders (5,678 rows)
  • payments (2,345 rows)

MEDUSA> report
📝 Generating report...
✓ Report saved: /Users/you/.medusa/reports/report-20251106_143022.html

MEDUSA> exit
```

---

## Report Generation

### Example 11: Executive Summary Report

**Scenario:** Create executive-friendly report

```bash
# Create executive summary
medusa generate-report \
  --latest \
  --format exec \
  --output exec-summary.pdf
```

**Includes:**
- High-level risk summary
- Business impact assessment
- Prioritized remediation roadmap
- Compliance impact (PCI-DSS, HIPAA, GDPR, etc.)
- 1-page executive overview

**Perfect for:** Management, clients, C-level

---

### Example 12: Technical Deep Dive Report

**Scenario:** Detailed technical report for developers

```bash
# Detailed technical report
medusa generate-report \
  --latest \
  --format technical \
  --include-raw-output \
  --include-screenshots
```

**Includes:**
- Detailed vulnerability descriptions
- Proof-of-concept exploits
- Raw tool output
- Screenshots of findings
- Remediation code examples
- CVSS scores and references

**Perfect for:** Developers, security teams

---

### Example 13: Compliance Report

**Scenario:** Report for compliance audits

```bash
# Compliance-focused report
medusa generate-report \
  --latest \
  --format compliance \
  --include-standards "PCI-DSS,OWASP,HIPAA"
```

**Maps findings to:**
- PCI-DSS requirements
- OWASP Top 10
- HIPAA security rules
- CIS benchmarks
- Industry best practices

---

## Advanced Usage

### Example 14: Multi-Target Batch Scan

**Scenario:** Scan multiple targets from file

```bash
# Create targets file
cat > targets.txt << EOF
https://app1.example.com
https://app2.example.com
192.168.1.100
EOF

# Run batch scan
medusa run \
  --targets-file targets.txt \
  --mode auto \
  --parallel 3 \
  --output-dir ./scan-results/
```

**Features:**
- Scans all targets in parallel (3 at a time)
- Creates separate report for each target
- Aggregates results in output directory

---

### Example 15: Continuous Security Monitoring

**Scenario:** Daily automated scans with alerting

```bash
#!/bin/bash
# daily-scan.sh

# Run scan
medusa run \
  --target https://production-app.com \
  --mode observe \
  --quiet \
  --output-format json \
  > scan-results.json

# Check for new high-severity findings
HIGH_COUNT=$(jq '[.findings[] | select(.severity=="HIGH" or .severity=="CRITICAL")] | length' scan-results.json)

if [ "$HIGH_COUNT" -gt 0 ]; then
    # Send alert
    echo "ALERT: $HIGH_COUNT high-severity findings" | mail -s "MEDUSA Alert" security@company.com
    
    # Generate report
    medusa generate-report --latest --format exec
fi
```

**Setup cron:**

```bash
# Run daily at 2 AM
0 2 * * * /path/to/daily-scan.sh
```

---

### Example 16: Custom Wordlist

**Scenario:** Use custom directory wordlist

```bash
# Use custom wordlist for directory enumeration
medusa run \
  --target https://webapp.com \
  --mode auto \
  --wordlist /path/to/custom-wordlist.txt \
  --extensions php,asp,aspx,jsp
```

**Checks for:**
- Paths in custom wordlist
- With specified file extensions
- Custom discovery patterns

---

### Example 17: Rate-Limited Testing

**Scenario:** Test without triggering rate limits or WAF

```bash
# Slow, stealthy scan
medusa run \
  --target https://api.example.com \
  --mode api \
  --rate-limit 10 \      # Max 10 requests/second
  --delay 100 \          # 100ms delay between requests
  --threads 1            # Single-threaded
```

**Useful for:**
- Production environments
- Rate-limited APIs
- Avoiding detection/WAF triggering
- Careful testing

**Duration:** 2-3x longer than normal, but stealthier

---

### Example 18: Targeted Vulnerability Scan

**Scenario:** Focus on specific vulnerability types

```bash
# Only test for SQL injection
medusa run \
  --target https://webapp.com \
  --mode auto \
  --vulnerability-types "sql-injection" \
  --intensity high

# Only test for XSS
medusa run \
  --target https://webapp.com \
  --mode auto \
  --vulnerability-types "xss,dom-xss"

# Multiple types
medusa run \
  --target https://webapp.com \
  --mode auto \
  --vulnerability-types "sql-injection,xss,csrf,xxe"
```

**Benefit:** Faster scans when you know what to look for

---

### Example 19: Integration with CI/CD

**Scenario:** Run security scan in GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - pip install -e ./medusa-cli
    - medusa run 
        --target http://staging-app.com 
        --mode auto 
        --ci-mode 
        --quiet 
        --output-format json 
        > scan-results.json
    - |
      CRITICAL=$(jq '[.findings[] | select(.severity=="CRITICAL")] | length' scan-results.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Found $CRITICAL critical vulnerabilities!"
        exit 1
      fi
  artifacts:
    reports:
      sast: scan-results.json
```

---

### Example 20: Scope Limiting

**Scenario:** Avoid scanning certain paths/domains

```bash
# Exclude paths
medusa run \
  --target https://webapp.com \
  --exclude-paths "/logout,/admin,/test" \
  --mode auto

# Only scan specific path
medusa run \
  --target https://webapp.com/api \
  --scope-path /api \
  --mode auto
```

**Prevents:**
- Accidentally logging out
- Testing admin-only areas
- Triggering security alerts
- Wasting time on excluded areas

---

## Best Practices

### 1. Start with Observe Mode

Always start new targets with observe mode:

```bash
medusa observe new-target.com
```

### 2. Incremental Testing

Build up from safe to risky:

```bash
# Step 1: Reconnaissance
medusa observe target.com

# Step 2: Light testing
medusa run --target target.com --risk low

# Step 3: If approved, deeper testing
medusa run --target target.com --risk medium
```

### 3. Use Interactive Mode for Learning

Interactive mode helps understand what's happening:

```bash
medusa shell
MEDUSA> help
MEDUSA> suggestions  # Get AI-powered recommendations
```

### 4. Save Command Output

Save results for later analysis:

```bash
medusa run --target target.com | tee scan-output.log
```

### 5. Compare Scans Over Time

Track security posture changes:

```bash
# Baseline scan
medusa run --target target.com --output baseline.json

# Follow-up scan
medusa run --target target.com --output followup.json

# Compare
diff <(jq -S . baseline.json) <(jq -S . followup.json)
```

### 6. Document Your Tests

```bash
# Save test parameters for reproducibility
medusa run \
  --target target.com \
  --mode auto \
  --intensity high \
  --threads 10 \
  --timeout 600 \
  2>&1 | tee test-$(date +%Y%m%d_%H%M%S).log
```

---

## Troubleshooting Examples

### Example: Timeouts on Slow Network

```bash
# Increase timeout
medusa run --target target.com --timeout 600
```

### Example: Too Many Results

```bash
# More specific scan
medusa run --target target.com --scope-path /api --mode auto
```

### Example: Scan Too Slow

```bash
# Increase parallelism
medusa run --target target.com --threads 20 --mode auto
```

---

For more information, see:
- [QUICKSTART.md](../00-getting-started/quick-start-dashboard.md)
- [Full Documentation](../README.md)
- [Troubleshooting](../00-getting-started/troubleshooting.md)

