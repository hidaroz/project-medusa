# MEDUSA Interactive Shell Guide

## Overview

MEDUSA's Interactive Shell Mode provides a natural language interface for penetration testing. The AI-powered shell understands your commands and guides you through security assessments.

## Getting Started

### Starting the Interactive Shell

```bash
# Start with a target
medusa shell --target http://localhost:8080

# Start without a target (set later)
medusa shell
```

## Features

### 🤖 Natural Language Commands

The shell understands natural language, so you can type commands as you would speak:

```bash
medusa> scan for open ports
🤔 AI Understanding: Port Scan (confidence: 85%)
⚡ Scanning network...
✓ Scan complete! Found 3 open ports

medusa> what vulnerabilities did we find?
🤔 AI Understanding: Show Findings (confidence: 90%)
Found 2 vulnerabilities:
  - SQL Injection (HIGH)
  - XSS (MEDIUM)

medusa> what should I do next?
💭 Analyzing current situation...
AI Recommendations:
1. Exploit Sql Injection (confidence: 85%)
   Reasoning: High-confidence SQL injection detected
   Risk: MEDIUM
```

### ⌨️ Tab Completion

Press TAB to auto-complete commands:

```bash
medusa> scan   [TAB]
scan for open ports    scan the target    scan network

medusa> enumer [TAB]
enumerate services    enumerate API endpoints    enumerate databases
```

### 🔖 Command Aliases

Use shortcuts for common commands:

**Built-in Aliases:**
- `s` → scan for open ports
- `e` → enumerate services
- `f` → find vulnerabilities
- `sqli` → test for SQL injection
- `xss` → test for XSS
- `next` → what should I do next?

**Custom Aliases:**
```bash
# Create an alias
medusa> alias myscan port scan with version detection
✓ Created alias: myscan → port scan with version detection

# Use your alias
medusa> myscan
→ port scan with version detection
🤔 AI Understanding: Port Scan...

# List all aliases
medusa> show aliases

# Remove an alias
medusa> unalias myscan
✓ Removed alias: myscan
```

### 💾 Session Management

Your session is automatically tracked and saved:

```bash
# View session context
medusa> show context
Session Context:
  Target: localhost:8080
  Duration: 125.3s
  Commands Executed: 8
  Total Findings: 12
  Critical: 0
  High: 3
  Medium: 5

# View command history
medusa> show history
#  Time      Command                    Phase
1  14:30:22  scan for open ports        reconnaissance
2  14:31:05  enumerate services         enumeration
3  14:32:18  what should I do next?     enumeration

# View findings
medusa> show findings
```

### 📊 Session Export

Export your session to various formats:

```bash
# Export to HTML (beautiful interactive report)
medusa> export html
✓ Exported to HTML: medusa_report_20250511_143022.html
Open medusa_report_20250511_143022.html in your browser

# Export to JSON (full session data)
medusa> export json my_session.json
✓ Exported to JSON: my_session.json

# Export to CSV (findings only)
medusa> export csv findings.csv
✓ Exported findings to CSV: findings.csv

# Export to Markdown (GitHub-compatible)
medusa> export markdown report.md
✓ Exported to Markdown: report.md
```

### 💡 Context-Aware Suggestions

Get smart suggestions based on your current progress:

```bash
medusa> suggestions
💡 Suggested Commands:
  1. enumerate API endpoints
  2. test SQL injection vulnerability
  3. analyze API for vulnerabilities
  4. show findings

💭 You have 12 findings. Consider moving to vulnerability_scan phase.
```

## Available Commands

### Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show help message |
| `suggestions` | Show context-aware command suggestions |
| `set target <url>` | Set the target URL |
| `show context` | Display session context |
| `show findings` | Display discovered findings |
| `show history` | Display command history |
| `show aliases` | Display command aliases |
| `alias <name> <cmd>` | Create a command alias |
| `unalias <name>` | Remove an alias |
| `export <format> [file]` | Export session |
| `clear` | Clear the screen |
| `exit` / `quit` | Exit the shell |

### Natural Language Commands (Examples)

**Reconnaissance:**
- scan for open ports
- scan the target
- scan network
- enumerate services
- enumerate API endpoints

**Vulnerability Assessment:**
- find vulnerabilities
- test for SQL injection
- test for XSS
- test authentication
- check for common vulnerabilities

**Exploitation:**
- exploit SQL injection
- exploit vulnerability
- attempt privilege escalation

**Data Extraction:**
- exfiltrate data
- extract sensitive data

**Analysis:**
- what should I do next?
- show me high severity findings
- show me critical findings
- show vulnerabilities

## Workflow Examples

### Example 1: Basic Web Application Assessment

```bash
medusa> scan for open ports
✓ Found 2 open ports: 80, 443

medusa> enumerate API endpoints
✓ Found 5 endpoints

medusa> find vulnerabilities
Found 3 vulnerabilities:
  - SQL Injection (HIGH)
  - XSS (MEDIUM)
  - CORS Misconfiguration (LOW)

medusa> what should I do next?
💡 Recommend testing SQL injection vulnerability

medusa> test for SQL injection
✓ Confirmed SQL injection in /api/search

medusa> export html
✓ Report saved
```

### Example 2: Using Aliases for Speed

```bash
medusa> alias fast scan + enumerate + find vulns

medusa> fast
→ scan + enumerate + find vulns
🤔 Running multi-step workflow...

medusa> show findings
[All findings displayed]

medusa> sqli
→ test for SQL injection
✓ Testing...
```

### Example 3: Session Export

```bash
medusa> e
→ enumerate services
✓ Done

medusa> f
→ find vulnerabilities
✓ Found 5 vulnerabilities

medusa> export html my_pentest.html
✓ Beautiful HTML report created

# Open in browser to see:
# - Executive summary
# - Severity breakdown with charts
# - Detailed findings
# - Command history
# - Professional formatting
```

## Tips and Tricks

### 1. Use Natural Language

Don't worry about exact command syntax. The AI will understand:
- "scan for ports" ✓
- "check open ports" ✓
- "find what ports are open" ✓

### 2. Ask for Guidance

When unsure, just ask:
```bash
medusa> what should I do next?
medusa> suggest next steps
medusa> help me continue
```

### 3. Save Time with Aliases

Create aliases for your common workflows:
```bash
medusa> alias quick scan + enum + vulns
medusa> alias deep scan + enum + vulns + test sql + test xss
medusa> alias report show findings + export html
```

### 4. Review Before Acting

Check what the AI understood:
```bash
medusa> exploit the database
🤔 AI Understanding: Exploit (confidence: 82%)
[Shows what it will do before executing]
```

### 5. Export Early and Often

Export your findings as you go:
```bash
# After each major phase
medusa> export json backup_recon.json
medusa> export html checkpoint_enum.html
```

## Session Persistence

Sessions are automatically saved when you exit:

```bash
medusa> exit
Session saved to: ./sessions/session_20250511_143022.json
```

To load a previous session (future feature):
```bash
medusa shell --session session_20250511_143022.json
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `TAB` | Auto-complete command |
| `↑` | Previous command |
| `↓` | Next command |
| `Ctrl+C` | Cancel (won't exit) |
| `Ctrl+D` | Exit shell |
| `Ctrl+L` | Clear screen |

## Troubleshooting

### Command Not Recognized

If the AI doesn't understand your command:
1. Try rephrasing with simpler words
2. Use a built-in alias if available
3. Type `help` to see examples
4. Check confidence score - if < 50%, try again

### Low Confidence Warnings

```bash
medusa> do something weird
⚠ Command unclear (confidence: 30%)
Please rephrase or type 'help' for examples
```

### Session Not Saving

- Check write permissions in ./sessions/
- Use `export` to manually save progress
- Check disk space

## Advanced Features

### Multi-Step Commands (Future)

```bash
medusa> scan then enumerate then find vulns
[AI breaks down into steps and executes]
```

### Conditional Execution (Future)

```bash
medusa> if high severity found, test exploitation
```

### Custom Scripts (Future)

```bash
medusa> run my_custom_workflow.yaml
```

## Best Practices

1. **Start with Reconnaissance**
   - Always begin with scanning
   - Build context before deeper testing

2. **Review Findings Regularly**
   - Use `show findings` frequently
   - Export reports at key milestones

3. **Use Suggestions**
   - Type `suggestions` when unsure
   - Let AI guide your workflow

4. **Document with Exports**
   - Export HTML for stakeholders
   - Export JSON for analysis
   - Export CSV for spreadsheets

5. **Create Custom Aliases**
   - Build aliases for your workflow
   - Share aliases with your team

## Getting Help

- Type `help` in the shell
- Type `suggestions` for context-aware hints
- Ask "what should I do next?"
- Check the main MEDUSA documentation

## See Also

- [Autonomous Mode Guide](./AUTONOMOUS_MODE_GUIDE.md)
- [Observe Mode Guide](./OBSERVE_MODE_GUIDE.md)
- [API Documentation](./API_DOCS.md)
