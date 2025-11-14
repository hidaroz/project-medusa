# 🚀 MEDUSA CLI - Quick Start Guide

Get up and running with MEDUSA in 5 minutes.

---

## Step 1: Install

### Option A: From Source (Recommended for Development)

```bash
cd medusa-cli
pip install -e .
```

### Option B: From PyPI (When Published)

```bash
pip install medusa-pentest
```

### Option C: Use Test Script

```bash
cd medusa-cli
./test_install.sh
source .venv/bin/activate
```

---

## Step 2: Setup

Run the interactive setup wizard:

```bash
medusa setup
```

You'll be asked to choose your **LLM Provider**:

1. **Local (Ollama)** - Free, private, unlimited (recommended for learning)
   - No API key required
   - Requires Ollama installation

2. **AWS Bedrock (Claude 3.5)** - Enterprise-grade, smart routing (~$0.25/scan)
   - Requires AWS account
   - See [Bedrock Setup Guide](bedrock-setup.md) for detailed instructions

3. **Cloud (OpenAI/Anthropic)** - Direct API access
   - Get API key from [OpenAI](https://platform.openai.com/) or [Anthropic](https://console.anthropic.com/)

Then configure:

- **Target Environment** - Choose "Local Docker" for learning
- **Risk Tolerance** - Recommended: LOW=yes, MEDIUM=no, HIGH=no
- **Docker Setup** - Auto-configures test environment

**That's it!** Configuration saved to `~/.medusa/config.yaml`

---

## Step 3: Verify

Check that everything is configured:

```bash
medusa status
```

Expected output:
```
Configuration:
  Version: 1.0.0
  Config Path: /Users/you/.medusa/config.yaml
  Target: http://localhost:3001
  API Key: Configured ✓
```

---

## Step 4: Your First Test

### Option 1: Safe Reconnaissance (Recommended First)

```bash
medusa observe --target http://localhost:3001
```

This will:
- ✅ Perform reconnaissance
- ✅ Find vulnerabilities
- ✅ Generate attack plan
- ❌ NOT exploit anything

View the report:
```bash
medusa reports --open
```

### Option 2: Full Autonomous Test

```bash
medusa run --target http://localhost:3001 --autonomous
```

The agent will:
1. Scan the target
2. Find vulnerabilities
3. **Ask for approval** before exploiting
4. Generate comprehensive report

### Option 3: Interactive Shell

```bash
medusa shell
```

Then type commands:
```
MEDUSA> scan network
MEDUSA> show findings
MEDUSA> exit
```

---

## Common Commands Cheat Sheet

| Command | What It Does |
|---------|-------------|
| `medusa setup` | Configure MEDUSA |
| `medusa status` | Show current config |
| `medusa observe -t <url>` | Safe recon only |
| `medusa run -t <url> -a` | Full autonomous test |
| `medusa shell` | Interactive mode |
| `medusa reports --open` | View latest report |
| `medusa logs --latest` | Show latest log |
| `medusa --help` | Show all commands |

---

## Understanding Approval Gates

When running autonomous mode, you'll see prompts like:

```
⚠️  MEDIUM RISK ACTION

Technique: T1190 (Exploit Public-Facing Application)
Command: sqlmap -u http://target/api --dbs
Impact: Attempt SQL injection to enumerate databases

Approve? [y/n/s/a/all]:
```

Your options:
- **y** (yes) - Approve this action
- **n** (no) - Deny this action
- **s** (skip) - Skip this step, continue to next
- **a** (abort) - Stop entire operation
- **all** - Approve all remaining actions

---

## Example Workflow

### Scenario: Testing a Web App

```bash
# 1. Safe reconnaissance
medusa observe --target http://my-test-app.com

# 2. Review findings
medusa reports --open

# 3. If comfortable, run full test
medusa run --target http://my-test-app.com --autonomous

# 4. When prompted, approve or deny each action
# 5. Review final report
medusa reports --open
```

---

## Configuration Tips

### Change Risk Tolerance

Edit `~/.medusa/config.yaml`:

```yaml
risk_tolerance:
  auto_approve_low: true      # Recon always runs
  auto_approve_medium: false  # Change to true for faster testing
  auto_approve_high: false    # Keep false for safety
```

### Change Default Target

Edit `~/.medusa/config.yaml`:

```yaml
target:
  type: custom
  url: http://my-default-target.com
```

Then you can run:
```bash
medusa run --autonomous  # Uses configured target
```

---

## Troubleshooting

### "MEDUSA is not configured"

```bash
medusa setup
```

### "No API key found"

1. Get key from [Google AI Studio](https://ai.google.dev/gemini-api/docs/quickstart)
2. Run `medusa setup --force`
3. Enter your API key when prompted

### "Target not reachable"

```bash
# Check if target is running
curl http://localhost:3001/health

# For Docker environment
docker ps
```

### Command not found: medusa

```bash
# Reinstall
pip install -e .

# Or check installation
pip list | grep medusa
```

### AWS Bedrock Issues

**"AccessDeniedException"**
- Enable model access in AWS Console → Bedrock → Model access
- Enable: Anthropic Claude 3.5 Sonnet and Haiku

**"Invalid AWS credentials"**
```bash
# Verify credentials
aws sts get-caller-identity

# Reconfigure if needed
aws configure
```

**Need help with Bedrock setup?**
- See detailed guide: [bedrock-setup.md](bedrock-setup.md)
- Includes step-by-step AWS configuration
- IAM policy setup
- Cost optimization tips

---

## What's Next?

### Learn More
- 📖 Full documentation: [README.md](README.md)
- 📝 Detailed examples: [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)
- 🎯 Project overview: [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)

### Try Different Modes

**Observe Mode** (safest):
```bash
medusa observe --target http://target.com
```

**Interactive Mode** (full control):
```bash
medusa shell
```

**Autonomous Mode** (automated):
```bash
medusa run --target http://target.com --autonomous
```

### View Reports

```bash
# List all reports
medusa reports

# Open latest in browser
medusa reports --open

# View logs
medusa logs --latest
```

---

## Safety Reminders

1. ⚠️ **Only test systems you own or have permission to test**
2. 🛡️ Start with `observe` mode for new targets
3. 🚨 Press `Ctrl+C` to abort at any time
4. 📝 Review reports to understand what was done
5. 🔒 Never use on production systems without approval

---

## Getting Help

- 📚 Read the [README](README.md)
- 🐛 Report issues: [GitHub Issues](https://github.com/hidaroz/project-medusa/issues)
- 💬 Ask questions: [GitHub Discussions](https://github.com/hidaroz/project-medusa/discussions)
- 📖 Documentation: [docs.medusa.dev](https://docs.medusa.dev)

---

## Quick Test Checklist

- [ ] Install MEDUSA
- [ ] Run `medusa setup`
- [ ] Run `medusa status` to verify
- [ ] Try `medusa observe --target http://localhost:3001`
- [ ] View report with `medusa reports --open`
- [ ] Try interactive mode: `medusa shell`

**You're ready to go! Happy (ethical) hacking! 🔴**

