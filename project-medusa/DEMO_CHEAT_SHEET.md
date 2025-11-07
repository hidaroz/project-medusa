# MEDUSA Demo - One Page Cheat Sheet

**10 min demo + 5 min Q&A | Reference: `docs/04-usage/complete-mode-reference.md`**

---

## ⚡ Pre-Demo (2 min before)

```bash
cd lab-environment && docker-compose up -d
curl http://localhost:8080 && curl http://localhost:3001/api/health
medusa status
```

---

## 🎬 Demo Flow (10 minutes)

### 1. Introduction (1 min)
**Defender:** "MEDUSA is AI-powered penetration testing. 3 modes: Observe, Autonomous, Interactive. Testing vulnerable EHR system."

### 2. Observe Mode (2 min)
```bash
medusa observe --target http://localhost:3001
```
**Attacker 1:** "Safe reconnaissance - finds vulnerabilities but doesn't exploit."

### 3. Autonomous Mode (5 min)
```bash
medusa run --target http://localhost:8080 --autonomous
```
**Attacker 1:** 
- "AI plans attack chain"
- "Approval gates for risky actions"
- Approve prompts with `y`
- "Shows complete attack: SQL injection → credential access → data exfiltration"

### 4. Interactive Mode (1 min)
```bash
medusa shell --target http://localhost:3001
MEDUSA> scan network
MEDUSA> show findings
MEDUSA> exit
```
**Attacker 2:** "Natural language commands, full control."

### 5. Reports (1 min)
```bash
medusa reports --open
```
**Attacker 1:** "Comprehensive reports with MITRE ATT&CK mapping, CVSS scores, remediation steps."

---

## 📋 All Commands

| Command | What It Does |
|---------|--------------|
| `medusa observe --target <url>` | Safe reconnaissance only |
| `medusa run --target <url> --autonomous` | AI-driven attack with approval |
| `medusa shell` | Interactive natural language mode |
| `medusa reports --open` | View latest report |
| `medusa status` | Show configuration |
| `medusa logs --latest` | Show latest log |

**Full list:** `docs/04-usage/complete-mode-reference.md`

---

## 🎤 Key Talking Points

**Attacker 1:** "AI-powered decision making", "Approval gates ensure control", "Adapts based on vulnerabilities"

**Attacker 2:** "Natural language interface", "Full user control", "Safe reconnaissance"

**Defender:** "Common healthcare vulnerabilities", "SQL injection → HIPAA violation", "Weak credentials critical"

---

## ❓ Q&A Quick Answers

**Q: How does AI make decisions?**  
A: Uses Gemini/LLM to analyze vulnerabilities, recommends attacks based on MITRE ATT&CK.

**Q: Is it safe?**  
A: Yes - approval gates, risk classification. LOW auto-approved, MEDIUM/HIGH require approval.

**Q: What makes it different?**  
A: AI-powered planning, natural language, approval gates, MITRE ATT&CK reporting.

**Q: Three modes?**  
A: Observe (safe recon), Autonomous (AI with approval), Interactive (manual control).

---

## 🚨 Emergency

**Services down:** `docker-compose restart`  
**MEDUSA fails:** Show command, explain what it does  
**Out of time:** Skip Interactive, focus on Autonomous + Reports

---

## ✅ Checklist

- [ ] Lab running (`docker-compose ps`)
- [ ] Services accessible
- [ ] MEDUSA configured
- [ ] Browser ready
- [ ] Team ready

**Time: 10 min demo + 5 min Q&A**

