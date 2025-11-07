# MEDUSA Demo - 10 Minute Presentation
## AI-Powered Penetration Testing on Vulnerable EHR System

**Duration:** 10 minutes demo + 5 minutes Q&A  
**Team:** 2 attackers (MEDUSA users) + 1 defender (EHR narrator)  
**Reference Doc:** `docs/04-usage/complete-mode-reference.md` (all commands & modes)

---

## ⏱️ Timeline Breakdown

- **0:00-1:00** - Introduction & Setup (1 min)
- **1:00-3:00** - Observe Mode Demo (2 min)
- **3:00-6:00** - Autonomous Mode Demo (3 min)
- **6:00-8:00** - Interactive Mode Demo (2 min)
- **8:00-10:00** - Reporting & Summary (2 min)
- **10:00-15:00** - Q&A (5 min)

---

## 🎬 10-Minute Demo Script

### **Phase 1: Introduction** (1 minute)

#### Defender Introduction

**Defender:** "Welcome! Today we'll demonstrate MEDUSA - an AI-powered penetration testing framework. We'll attack a vulnerable healthcare EHR system with 8 intentionally vulnerable services. This is a controlled, isolated environment."

**Key Points:**
- EHR Web Portal (port 8080) - SQL injection, XSS
- EHR API (port 3001) - Missing authentication
- MySQL Database (port 3306) - Weak credentials
- SSH Server (port 2222) - Weak passwords

**Attacker 1:** "MEDUSA has three modes: Observe (safe recon), Autonomous (AI-driven with approval), and Interactive (full control). Let's start!"

---

### **Phase 2: Observe Mode** (2 minutes)

#### Attacker 1: Safe Reconnaissance

**Attacker 1:** "Observe mode performs safe reconnaissance without exploitation - perfect for initial assessment."

```bash
# Command 1: Safe reconnaissance
medusa observe --target http://localhost:3001
```

**While running, explain:**
- "MEDUSA is scanning the network and discovering services"
- "It's identifying vulnerabilities but NOT exploiting them"
- "This generates an attack plan without any risk"

**Expected Output (summarize quickly):**
- Network scan complete
- 4 services discovered
- 5 vulnerabilities identified
- Attack plan generated (not executed)

**Attacker 1:** "Observe mode found SQL injection, missing authentication, and weak credentials. Now let's see autonomous mode execute an attack."

**Time Check:** 3 minutes

---

### **Phase 3: Autonomous Mode** (3 minutes)

#### Attacker 1: AI-Driven Attack with Approval Gates

**Attacker 1:** "Autonomous mode uses AI to plan and execute attacks, but requires approval for risky actions."

```bash
# Command 2: Autonomous mode
medusa run --target http://localhost:8080 --autonomous
```

**Explain as it runs:**
- "Phase 1: Reconnaissance - Auto-approved (LOW risk)"
- "Phase 2: Enumeration - Auto-approved (LOW risk)"
- "Phase 3: Exploitation - Requires approval (MEDIUM risk)"

**When approval prompt appears:**

```
⚠️  MEDIUM RISK ACTION

Technique: T1190 (Exploit Public-Facing Application)
Action: SQL Injection Exploitation
Target: http://localhost:8080/search.php
Impact: Extract database information

Approve? [y/n/s/a/all]: y
```

**Attacker 1:** "This approval gate ensures we maintain control. MEDUSA classified this as MEDIUM risk and stopped for approval."

**After approval:**
- SQL injection executed
- Database enumerated
- Credentials extracted

**Attacker 1:** "MEDUSA successfully exploited SQL injection and extracted database credentials. The AI adapts its strategy based on discovered vulnerabilities."

**Time Check:** 6 minutes

---

### **Phase 4: Interactive Mode** (2 minutes)

#### Attacker 2: Natural Language Commands

**Attacker 2:** "Interactive mode gives full control with natural language commands."

```bash
# Command 3: Interactive shell
medusa shell --target http://localhost:3001

# In the shell:
MEDUSA> scan network
MEDUSA> enumerate API endpoints
MEDUSA> show findings
MEDUSA> exit
```

**Explain:**
- "I can use natural language - 'scan network' instead of complex commands"
- "MEDUSA's AI understands context and suggests actions"
- "Full control over each step with real-time feedback"

**Show findings:**
```
🟠 HIGH - Unauthenticated API Access
🟠 HIGH - SQL Injection Vulnerability
🟡 MEDIUM - Weak JWT Secret
```

**Attacker 2:** "Interactive mode is perfect for learning and exploring targets step-by-step."

**Time Check:** 8 minutes

---

### **Phase 5: Reporting & Summary** (2 minutes)

#### Attacker 1: Comprehensive Reports

**Attacker 1:** "MEDUSA automatically generates comprehensive reports."

```bash
# Command 4: View reports
medusa reports --open
```

**Show in browser:**
- Executive summary
- Technical findings
- MITRE ATT&CK mapping
- Risk ratings
- Remediation recommendations

**Attacker 1:** "Reports include MITRE ATT&CK mapping, CVSS scores, and actionable remediation steps."

**Quick Summary:**

**Attacker 1:** "We demonstrated three modes:"
- ✅ **Observe** - Safe reconnaissance
- ✅ **Autonomous** - AI-driven with approval gates
- ✅ **Interactive** - Natural language control

**Defender:** "MEDUSA discovered critical vulnerabilities: SQL injection, missing authentication, and weak credentials - common issues in healthcare systems that could lead to HIPAA violations."

**Time Check:** 10 minutes - Demo Complete!

---

## 📊 Key Commands Reference

### All MEDUSA Commands (from `docs/04-usage/complete-mode-reference.md`)

| Command | Purpose | Mode |
|---------|---------|------|
| `medusa setup` | Configure MEDUSA | Setup |
| `medusa status` | Show configuration | Info |
| `medusa run --target <url> --autonomous` | Full automated test | Autonomous |
| `medusa run --target <url> --mode autonomous` | Same as above | Autonomous |
| `medusa run --target <url> --mode interactive` | Interactive mode | Interactive |
| `medusa run --target <url> --mode observe` | Observe mode | Observe |
| `medusa shell` | Start interactive REPL | Interactive |
| `medusa shell --target <url>` | Interactive with target | Interactive |
| `medusa observe --target <url>` | Reconnaissance only | Observe |
| `medusa reports` | List all reports | Reports |
| `medusa reports --open` | Open latest report | Reports |
| `medusa logs --latest` | Show latest log | Logs |
| `medusa generate-report --type all` | Generate reports | Reports |
| `medusa version` | Show version | Info |

### Three Operating Modes

1. **Observe Mode** (`medusa observe`)
   - Safe reconnaissance only
   - No exploitation
   - Generates attack plan

2. **Autonomous Mode** (`medusa run --autonomous`)
   - AI-driven attack chain
   - Approval gates for risky actions
   - Comprehensive reporting

3. **Interactive Mode** (`medusa shell`)
   - Natural language commands
   - Full user control
   - Real-time feedback

---

## 🎤 Talking Points (Quick Reference)

### Attacker 1 (Primary)
- "MEDUSA uses AI to intelligently plan attacks"
- "Approval gates ensure we maintain control"
- "The system adapts based on discovered vulnerabilities"

### Attacker 2 (Secondary)
- "MEDUSA can run multiple assessments in parallel"
- "Observe mode provides safe reconnaissance"
- "Natural language makes it accessible"

### Defender (Narrator)
- "These vulnerabilities are common in healthcare systems"
- "SQL injection can lead to HIPAA violations"
- "Weak credentials are a critical security issue"

---

## ⚠️ Pre-Demo Checklist (Do Before Presentation)

```bash
# 1. Start lab environment
cd lab-environment
docker-compose up -d

# 2. Verify services
docker-compose ps
curl http://localhost:8080
curl http://localhost:3001/api/health

# 3. Check MEDUSA
medusa status

# 4. Pre-run observe mode (so it's fast)
medusa observe --target http://localhost:3001
```

---

## 🎯 Key Demo Points

### What to Emphasize

1. **AI-Powered Decision Making**
   - Natural language understanding
   - Context-aware vulnerability assessment
   - Intelligent attack planning

2. **Safety Features**
   - Approval gates for risky actions
   - Risk-based classification
   - Emergency abort capability

3. **Comprehensive Capabilities**
   - Network scanning
   - Vulnerability identification
   - Exploitation with approval
   - Detailed reporting

4. **Multiple Modes**
   - Observe (safe)
   - Autonomous (AI-driven)
   - Interactive (full control)

---

## 📝 Q&A Preparation

### Common Questions

**Q: How does MEDUSA's AI make decisions?**  
A: MEDUSA uses LLM (local Mistral or Google Gemini) to analyze vulnerabilities and recommend attack strategies based on MITRE ATT&CK framework.

**Q: Is MEDUSA safe to use?**  
A: Yes, with approval gates and risk classification. Always use in authorized environments only.

**Q: Can MEDUSA be used for real penetration testing?**  
A: Yes, but ensure proper authorization. MEDUSA is designed for authorized security testing.

**Q: What makes MEDUSA different?**  
A: AI-powered decision making, natural language interface, approval gates, and comprehensive reporting with MITRE ATT&CK mapping.

**Q: What are the hardware requirements?**  
A: 8GB+ RAM recommended, Docker Desktop, Python 3.9+. Can use local LLM (Ollama) or Google Gemini API.

---

## 🚀 Quick Start Commands

```bash
# Verify setup
./scripts/verify-demo-setup.sh

# Start lab
cd lab-environment && docker-compose up -d

# Demo commands (in order)
medusa observe --target http://localhost:3001
medusa run --target http://localhost:8080 --autonomous
medusa shell --target http://localhost:3001
medusa reports --open
```

---

## ⏱️ Time Management Tips

1. **Keep it moving** - Don't wait for every scan to complete
2. **Explain while running** - Talk during execution
3. **Skip verbose output** - Summarize findings quickly
4. **Have backup plan** - If commands fail, explain what would happen
5. **Practice timing** - Run through once before presentation

---

**Good luck with your 10-minute demo! 🚀**

**Reference:** Full command documentation in `docs/04-usage/complete-mode-reference.md`
