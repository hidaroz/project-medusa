# MEDUSA Demo - 10 Minute Quick Reference

## ⏱️ Timeline (10 minutes)

| Time | Phase | Command | Duration |
|------|-------|---------|----------|
| 0:00-1:00 | Introduction | Setup check | 1 min |
| 1:00-3:00 | Observe Mode | `medusa observe --target http://localhost:3001` | 2 min |
| 3:00-6:00 | Autonomous Mode | `medusa run --target http://localhost:8080 --autonomous` | 3 min |
| 6:00-8:00 | Interactive Mode | `medusa shell --target http://localhost:3001` | 2 min |
| 8:00-10:00 | Reporting | `medusa reports --open` | 2 min |

---

## 🎯 Four Commands to Run

### 1. Observe Mode (Safe Recon)
```bash
medusa observe --target http://localhost:3001
```
**Show:** Network scan, vulnerability identification, attack plan (not executed)

### 2. Autonomous Mode (AI-Driven)
```bash
medusa run --target http://localhost:8080 --autonomous
```
**Show:** AI planning, approval gates, SQL injection exploitation

### 3. Interactive Mode (Natural Language)
```bash
medusa shell --target http://localhost:3001
MEDUSA> scan network
MEDUSA> show findings
MEDUSA> exit
```
**Show:** Natural language commands, real-time feedback

### 4. Reports (Results)
```bash
medusa reports --open
```
**Show:** HTML report with MITRE ATT&CK mapping, findings, remediation

---

## 📚 All Commands Reference

**Full Documentation:** `docs/04-usage/complete-mode-reference.md`

### Setup & Info
- `medusa setup` - Configure MEDUSA
- `medusa status` - Show configuration
- `medusa version` - Show version

### Three Operating Modes
- `medusa observe --target <url>` - Safe reconnaissance
- `medusa run --target <url> --autonomous` - AI-driven attack
- `medusa shell --target <url>` - Interactive mode

### Reports & Logs
- `medusa reports` - List reports
- `medusa reports --open` - Open latest report
- `medusa logs --latest` - Show latest log
- `medusa generate-report --type all` - Generate all formats

---

## 🎤 One-Liner Talking Points

**Attacker 1:** "MEDUSA uses AI to plan attacks with approval gates for safety"

**Attacker 2:** "Natural language commands make penetration testing accessible"

**Defender:** "These vulnerabilities are common in healthcare and could lead to HIPAA violations"

---

## ⚠️ Pre-Demo (Do Before)

```bash
cd lab-environment && docker-compose up -d
curl http://localhost:8080
curl http://localhost:3001/api/health
medusa status
```

---

## 🚨 Emergency

- **Ctrl+C** - Abort any command
- **Type 'a'** - Abort when prompted for approval
- **Skip slow parts** - Explain what's happening instead of waiting

---

**Reference:** `DEMO_10MIN.md` for full script | `docs/04-usage/complete-mode-reference.md` for all commands

