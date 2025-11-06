# MEDUSA Report Features

Complete guide to MEDUSA's professional reporting system.

---

## Overview

MEDUSA automatically generates **multiple report formats** after each penetration test, providing comprehensive documentation for different audiences:

| Report Type | Audience | Format | Auto-Generated |
|-------------|----------|--------|----------------|
| **Technical Report** | Security professionals, developers | HTML | ✅ Yes |
| **Executive Summary** | Management, stakeholders | HTML | ✅ Yes |
| **Markdown Report** | Documentation, wikis | Markdown | ✅ Yes |
| **JSON Log** | Automation, integration | JSON | ✅ Yes |
| **PDF Report** | Printable, archival | PDF | ⚠️ Manual |

---

## Report Types

### 1. Technical HTML Report

**Purpose:** Detailed technical analysis for security teams

**Features:**
- 🎨 Professional dark theme matching MEDUSA branding
- 🔒 Complete vulnerability details with CVSS scores
- 🎯 MITRE ATT&CK technique mapping with badges
- 📊 Findings organized by severity (Critical → High → Medium → Low)
- 🔍 Affected endpoints and components
- 💡 Technical remediation recommendations
- ⏱️ Operation phases and timeline
- 📈 Summary cards with risk metrics

**Best For:**
- Security engineers
- Penetration testers
- DevSecOps teams
- Incident responders

**Access:**
```bash
# View latest
medusa reports --type html --open

# Generate from log
medusa generate-report --type technical
```

---

### 2. Executive Summary

**Purpose:** Business-focused report for non-technical stakeholders

**Features:**
- 📋 Formal business document layout
- 💼 Risk rating and business impact analysis
- 📊 High-level findings without technical jargon
- 🎯 Strategic recommendations
- 📅 Remediation timeline (immediate, short-term, long-term)
- 💰 Resource and budget implications
- ⚖️ Regulatory compliance considerations

**Best For:**
- C-suite executives (CEO, CTO, CISO)
- Board members
- Business stakeholders
- Compliance officers

**Access:**
```bash
# View latest
medusa reports --type exec --open

# Generate from log
medusa generate-report --type executive
```

---

### 3. Markdown Report

**Purpose:** Documentation integration and version control

**Features:**
- 📝 Clean markdown format
- 🔄 Git-friendly (easy to diff and track changes)
- 🔗 Integration with GitHub, GitLab, Confluence
- 📚 Can be converted to other formats
- 🤖 Automation and CI/CD pipeline friendly
- 🔍 Full technical details preserved

**Best For:**
- Documentation systems
- Team wikis
- CI/CD pipelines
- Version control
- Automated reporting workflows

**Access:**
```bash
# View latest
medusa reports --type md

# Generate from log
medusa generate-report --type markdown

# Read in terminal
cat ~/.medusa/reports/report-*.md
```

---

### 4. JSON Log

**Purpose:** Machine-readable structured data

**Features:**
- 🤖 Complete structured data
- 🔧 Programmatic access
- 🔗 API integration ready
- 📊 Custom analytics and dashboards
- 🗄️ Database import compatible
- ⚡ Automated processing

**Best For:**
- Automation scripts
- Security orchestration (SOAR)
- Custom dashboards
- Data warehousing
- Integration with other tools

**Access:**
```bash
# View logs
medusa logs

# View latest
medusa logs --latest

# Parse programmatically
python -c "import json; print(json.load(open('~/.medusa/logs/run-*.json')))"
```

---

### 5. PDF Report (Optional)

**Purpose:** Printable and archival format

**Features:**
- 📄 Print-ready professional document
- 📧 Easy to email and share
- 🗄️ Long-term archival
- 🔒 Can be digitally signed
- 📱 Universal format (no browser needed)

**Requirements:**
```bash
pip install weasyprint
```

**Best For:**
- Physical documentation
- Email distribution
- Archival purposes
- Audit compliance
- Client deliverables

**Access:**
```bash
# Generate PDF
medusa generate-report --type pdf
```

---

## CLI Commands

### List Reports

```bash
# List all reports
medusa reports

# Filter by type
medusa reports --type html     # Technical reports
medusa reports --type exec     # Executive summaries
medusa reports --type md       # Markdown reports
medusa reports --type pdf      # PDF reports
```

### Open Reports

```bash
# Open latest technical report
medusa reports --open

# Open latest executive summary
medusa reports --type exec --open

# Open markdown report (shows path)
medusa reports --type md --open
```

### Generate Reports from Logs

```bash
# Generate all report types from latest log
medusa generate-report --type all

# Generate specific type
medusa generate-report --type technical
medusa generate-report --type executive
medusa generate-report --type markdown
medusa generate-report --type pdf

# Generate from specific log
medusa generate-report --log ~/.medusa/logs/run-*.json --type all

# Custom output directory
medusa generate-report --type all --output /path/to/reports
```

---

## Report Content

### What's Included

All reports include:

1. **Executive Summary**
   - Overall risk rating
   - Finding counts by severity
   - Key metrics

2. **Security Findings**
   - Detailed vulnerability information
   - CVSS scores
   - Affected components
   - Exploitation impact
   - Remediation steps

3. **MITRE ATT&CK Coverage**
   - Techniques employed
   - Tactics used
   - Attack phases

4. **Operation Phases**
   - Reconnaissance
   - Enumeration
   - Vulnerability scanning
   - Exploitation
   - Post-exploitation

5. **Recommendations**
   - Prioritized action items
   - Remediation guidance
   - Best practices

### Severity Classification

| Severity | CVSS Range | Color | Description |
|----------|------------|-------|-------------|
| **CRITICAL** | 9.0-10.0 | 🔴 Red | Immediate action required |
| **HIGH** | 7.0-8.9 | 🟠 Orange | Urgent attention needed |
| **MEDIUM** | 4.0-6.9 | 🟡 Yellow | Should be addressed soon |
| **LOW** | 0.1-3.9 | 🔵 Blue | Minor issues |
| **INFO** | 0.0 | ⚪ Gray | Informational only |

---

## Automated Generation

After each scan, MEDUSA automatically generates:

```
✅ JSON log                  (always)
✅ Technical HTML report     (always)
✅ Executive summary         (always)
✅ Markdown report           (always)
```

Example output:
```
📝 Generating Reports...

✅ JSON log: run-20240129_143022-auto_001.json
✅ Technical report: report-20240129_143022-auto_001.html
✅ Executive summary: executive-summary-20240129_143022-auto_001.html
✅ Markdown report: report-20240129_143022-auto_001.md

Reports location: /Users/you/.medusa/reports
```

---

## Customization

### Template Customization

Templates are located in:
```
src/medusa/templates/
├── technical_report.html      # Technical HTML template
├── executive_summary.html     # Executive summary template
└── report.md                  # Markdown template
```

You can customize these templates using Jinja2 syntax.

### Report Data Structure

The report data structure includes:

```python
{
    "target": "example.com",
    "duration_seconds": 247,
    "operation_id": "auto_001",
    "summary": {
        "total_findings": 12,
        "critical": 2,
        "high": 4,
        "medium": 5,
        "low": 1,
        "techniques_used": 15,
        "success_rate": 0.92
    },
    "findings": [
        {
            "severity": "critical",
            "title": "SQL Injection",
            "description": "...",
            "cvss_score": 9.8,
            "affected_endpoints": [...],
            "recommendation": "..."
        }
    ],
    "mitre_coverage": [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "status": "executed"
        }
    ],
    "phases": [...]
}
```

---

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run MEDUSA
        run: |
          medusa observe --target ${{ env.TARGET_URL }}
          medusa generate-report --type markdown --output ./security-reports

      - name: Upload Reports
        uses: actions/upload-artifact@v2
        with:
          name: security-reports
          path: ./security-reports/*.md
```

### Python Integration

```python
from medusa.reporter import ReportGenerator
import json

# Load assessment results
with open('assessment.json') as f:
    data = json.load(f)

# Generate reports
reporter = ReportGenerator()
html_path = reporter.generate_html_report(data, 'custom-001')
exec_path = reporter.generate_executive_summary(data, 'custom-001')
md_path = reporter.generate_markdown_report(data, 'custom-001')

print(f"Reports generated:")
print(f"  Technical: {html_path}")
print(f"  Executive: {exec_path}")
print(f"  Markdown: {md_path}")
```

### API Integration

```python
import requests

# Get latest report
reports_dir = Path.home() / ".medusa" / "reports"
latest_report = sorted(reports_dir.glob("*.json"))[-1]

# Send to SIEM or ticketing system
with open(latest_report) as f:
    data = json.load(f)

requests.post('https://siem.company.com/api/ingest', json=data)
```

---

## Best Practices

### 1. Regular Generation

Generate fresh reports when:
- Vulnerabilities are fixed and you want to verify
- Management requests an update
- Different audiences need tailored reports
- Exporting for compliance audit

### 2. Version Control

Store markdown reports in Git:
```bash
# After assessment
medusa generate-report --type markdown
cp ~/.medusa/reports/report-*.md ./docs/security/
git add docs/security/
git commit -m "Add latest security assessment"
```

### 3. Audience-Appropriate Reports

- **For developers:** Technical HTML + Markdown
- **For management:** Executive Summary
- **For auditors:** PDF + JSON logs
- **For documentation:** Markdown

### 4. Report Organization

```bash
# Organize by date and target
mkdir -p reports/2024-01/target.com/
medusa generate-report --output reports/2024-01/target.com/ --type all
```

---

## Troubleshooting

### Reports Not Generated

**Issue:** Reports not appearing after scan

**Solution:**
```bash
# Check reports directory
ls -la ~/.medusa/reports/

# Check permissions
chmod 755 ~/.medusa/reports/

# Regenerate from log
medusa generate-report --type all
```

### PDF Generation Fails

**Issue:** `weasyprint` not installed

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install python3-dev python3-pip libcairo2 libpango-1.0-0

# macOS
brew install cairo pango gdk-pixbuf libffi

# Install weasyprint
pip install weasyprint
```

### Template Errors

**Issue:** Jinja2 template errors

**Solution:**
```bash
# Verify templates exist
ls -la src/medusa/templates/

# Reinstall package
pip install -e .
```

---

## FAQ

**Q: Can I customize report templates?**
A: Yes! Templates are in `src/medusa/templates/`. Edit them using Jinja2 syntax.

**Q: How long are reports kept?**
A: Forever (until you delete them). MEDUSA never automatically deletes reports.

**Q: Can I export to other formats?**
A: Markdown can be converted using Pandoc: `pandoc report.md -o report.docx`

**Q: How do I share reports securely?**
A: Use encrypted email, secure file transfer, or password-protect PDFs.

**Q: Can reports be automatically emailed?**
A: Yes! Use a script to call `medusa generate-report` and email the output.

**Q: Do reports contain sensitive data?**
A: Yes! Reports include vulnerabilities and potentially sensitive findings. Handle with care.

---

## Additional Resources

- [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) - Practical examples
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development guide
- [README.md](README.md) - Project overview

---

**Last Updated:** 2025-11-05
**MEDUSA Version:** 1.0.0
