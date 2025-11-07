# MEDUSA Demo Presentation - Complete Guide

## 📋 Overview

This guide provides everything you need to run a successful MEDUSA demo presentation showcasing AI-powered penetration testing against a vulnerable EHR system.

**Duration:** 30-45 minutes  
**Team:** 3 people (2 attackers using MEDUSA + 1 defender explaining EHR system)  
**Audience:** Technical audience interested in AI-powered security testing

---

## 📁 Files in This Demo Package

### For 10-Minute Demo (Current)
1. **DEMO_10MIN.md** - Condensed 10-minute demo script ⭐ **USE THIS**
2. **DEMO_10MIN_QUICK_REF.md** - Quick reference for 10-minute demo
3. **docs/04-usage/complete-mode-reference.md** - Complete commands & modes reference ⭐ **ALL COMMANDS HERE**

### For Extended Demo (30-45 minutes)
4. **DEMO_SCRIPT.md** - Full step-by-step demo script (30-45 min)
5. **DEMO_QUICK_REFERENCE.md** - Quick reference card for extended demo
6. **scripts/verify-demo-setup.sh** - Pre-demo verification script
7. **DEMO_README.md** - This file (overview and instructions)

---

## 🚀 Quick Start

### ⏱️ For 10-Minute Demo (Current)

**Use:** `DEMO_10MIN.md` - Condensed script for 10-minute presentation

**Commands Reference:** `docs/04-usage/complete-mode-reference.md` - All commands and modes

### Step 1: Pre-Demo Setup (5 minutes)

```bash
# Run verification script
./scripts/verify-demo-setup.sh

# If services aren't running, start them:
cd lab-environment
docker-compose up -d

# Verify MEDUSA is configured
medusa status
```

### Step 2: Review Demo Materials

1. Read **DEMO_SCRIPT.md** - Full demo flow with all commands
2. Review **DEMO_QUICK_REFERENCE.md** - Quick command reference
3. Assign roles:
   - **Attacker 1:** Primary MEDUSA operator
   - **Attacker 2:** Secondary operator (parallel tasks)
   - **Defender:** EHR system narrator

### Step 3: Run the Demo

Follow **DEMO_SCRIPT.md** phase by phase:
- Phase 1: Introduction (5 min)
- Phase 2: Reconnaissance (5 min)
- Phase 3: Enumeration (7 min)
- Phase 4: Exploitation (8 min)
- Phase 5: Lateral Movement (7 min)
- Phase 6: Post-Exploitation (5 min)
- Phase 7: Reporting (5 min)
- Phase 8: Advanced Features (5 min)

---

## 🎯 Demo Objectives

### What You'll Demonstrate

1. **AI-Powered Decision Making**
   - Natural language command interpretation
   - Context-aware vulnerability assessment
   - Intelligent attack planning

2. **Safety Features**
   - Approval gates for risky actions
   - Risk-based classification
   - Emergency abort capability

3. **Comprehensive Capabilities**
   - Network scanning and enumeration
   - Vulnerability identification
   - Exploitation with approval gates
   - Lateral movement demonstration
   - Comprehensive reporting

4. **Multiple Operating Modes**
   - Observe mode (safe reconnaissance)
   - Autonomous mode (AI-driven with approval)
   - Interactive mode (full user control)

---

## 🏗️ Lab Environment Overview

### Services Being Attacked

| Service | Port | Purpose | Key Vulnerabilities |
|---------|------|---------|---------------------|
| EHR Web Portal | 8080 | Patient portal | SQL Injection, XSS, IDOR |
| EHR API | 3001 | REST API | Missing auth, weak JWT |
| MySQL Database | 3306 | Patient data | Weak credentials, plaintext passwords |
| SSH Server | 2222 | Linux server | Weak passwords, sudo misconfig |
| FTP Server | 21 | File storage | Anonymous access, weak credentials |
| LDAP Server | 389 | Directory | Anonymous bind, unencrypted |
| Log Viewer | 8081 | Logging | Information disclosure |
| Workstation | 445 | SMB shares | Weak permissions, cached creds |

### Network Architecture

```
┌─────────────────────┐
│   Host Machine      │
└──────────┬──────────┘
           │
    ┌──────┴──────┐
    │             │
┌───▼────┐   ┌───▼────────┐
│  DMZ   │   │ Internal  │
│ Network│   │ Network   │
└────────┘   └───────────┘
```

---

## 📊 Expected Demo Flow

### Attack Chain Demonstrated

1. **Reconnaissance** → Network scanning, service discovery
2. **Enumeration** → API endpoints, vulnerability identification
3. **Initial Access** → SQL injection exploitation
4. **Credential Access** → Database credential extraction
5. **Lateral Movement** → SSH and FTP access
6. **Collection** → Patient data exfiltration
7. **Impact** → Complete system compromise

### Key Vulnerabilities Found

- SQL Injection (CVSS 9.8)
- Missing Authentication (CVSS 9.1)
- Weak Credentials (CVSS 9.8)
- Plaintext Passwords (CVSS 9.6)
- Anonymous Access (CVSS 8.2)

---

## 🎤 Team Roles & Responsibilities

### Attacker 1 (Primary Operator)

**Responsibilities:**
- Run main MEDUSA commands
- Demonstrate autonomous mode
- Explain AI decision-making
- Show approval gates

**Key Messages:**
- "MEDUSA uses AI to intelligently plan attacks"
- "Approval gates ensure we maintain control"
- "The system adapts based on discovered vulnerabilities"

### Attacker 2 (Secondary Operator)

**Responsibilities:**
- Run parallel reconnaissance
- Demonstrate observe mode
- Show report generation
- Handle interactive mode examples

**Key Messages:**
- "MEDUSA can run multiple assessments in parallel"
- "Observe mode provides safe reconnaissance"
- "The system scales to assess entire networks"

### Defender (EHR Narrator)

**Responsibilities:**
- Explain vulnerable EHR system
- Describe vulnerabilities as discovered
- Provide healthcare security context
- Explain compliance implications

**Key Messages:**
- "These vulnerabilities are common in healthcare systems"
- "SQL injection can lead to HIPAA violations"
- "Weak credentials are a critical security issue"

---

## ⚠️ Important Safety Notes

### Before Demo

1. ✅ Verify lab environment is isolated
2. ✅ Confirm all services are running
3. ✅ Test MEDUSA commands beforehand
4. ✅ Have backup plan ready
5. ✅ Review talking points

### During Demo

1. ⚠️ Only approve actions you understand
2. ⚠️ Use Ctrl+C to abort if needed
3. ⚠️ Explain that this is a controlled environment
4. ⚠️ Emphasize educational purpose only

### After Demo

1. 🔄 Reset environment: `docker-compose down -v`
2. 📝 Review what worked well
3. 📝 Note any issues for next time
4. 🧹 Clean up logs if needed

---

## 🛠️ Troubleshooting Guide

### Services Won't Start

```bash
# Check Docker status
docker ps
docker-compose ps

# View logs
docker-compose logs [service-name]

# Restart services
docker-compose restart
```

### MEDUSA Not Working

```bash
# Check configuration
medusa status

# Reconfigure if needed
medusa setup --force

# Check installation
pip list | grep medusa
```

### Network Issues

```bash
# Check ports
netstat -an | grep -E '8080|3001|3306'

# Test connectivity
curl http://localhost:8080
curl http://localhost:3001/api/health

# Check firewall
sudo ufw status
```

### Database Access Issues

```bash
# Test database connection
mysql -h localhost -P 3306 -u root -padmin123

# Check database logs
docker-compose logs ehr-database

# Verify database is initialized
docker-compose exec ehr-database mysql -uroot -padmin123 -e "SHOW DATABASES;"
```

---

## 📈 Success Metrics

### Demo is Successful If:

✅ All 8 services are discovered  
✅ SQL injection is successfully exploited  
✅ Database credentials are extracted  
✅ Lateral movement is demonstrated  
✅ Comprehensive report is generated  
✅ MITRE ATT&CK mapping is shown  
✅ Approval gates are demonstrated  
✅ All three modes are showcased  

---

## 📚 Additional Resources

### Documentation

- **MEDUSA CLI README:** `medusa-cli/README.md`
- **Lab Environment Guide:** `lab-environment/README.md`
- **Vulnerability Docs:** `lab-environment/docs/security/`
- **MITRE ATT&CK Mapping:** `docs/architecture/MITRE_ATTACK_MAPPING.md`

### Quick Links

- **Setup Guide:** `docs/00-getting-started/cli-quickstart.md`
- **Usage Examples:** `docs/04-usage/usage-examples.md`
- **Complete Mode Reference:** `docs/04-usage/complete-mode-reference.md`

---

## 🎓 Post-Demo Q&A Preparation

### Common Questions

**Q: How does MEDUSA's AI make decisions?**  
A: MEDUSA uses Google Gemini (or local LLM) to analyze discovered vulnerabilities and recommend attack strategies based on MITRE ATT&CK framework.

**Q: Is MEDUSA safe to use?**  
A: Yes, with approval gates and risk classification. Always use in authorized environments only.

**Q: Can MEDUSA be used for real penetration testing?**  
A: Yes, but ensure proper authorization and follow ethical guidelines. MEDUSA is designed for authorized security testing.

**Q: How accurate are MEDUSA's findings?**  
A: MEDUSA uses real tools (nmap, custom scanners) for reconnaissance and enumeration. Exploitation results may be simulated in some cases.

**Q: What makes MEDUSA different from other tools?**  
A: AI-powered decision making, natural language interface, approval gates, and comprehensive reporting with MITRE ATT&CK mapping.

**Q: What are the hardware requirements?**  
A: 8GB+ RAM recommended, Docker Desktop, Python 3.9+. Can use local LLM (Ollama) or Google Gemini API.

---

## 🎯 Demo Checklist

### Pre-Demo (Day Before)

- [ ] Review DEMO_SCRIPT.md
- [ ] Test all commands
- [ ] Verify lab environment starts correctly
- [ ] Test MEDUSA installation
- [ ] Prepare talking points
- [ ] Assign team roles

### Day of Demo

- [ ] Run `./scripts/verify-demo-setup.sh`
- [ ] Start lab environment: `docker-compose up -d`
- [ ] Verify all services: `docker-compose ps`
- [ ] Test MEDUSA: `medusa status`
- [ ] Review quick reference card
- [ ] Test key commands
- [ ] Have backup plan ready

### During Demo

- [ ] Follow DEMO_SCRIPT.md phases
- [ ] Emphasize safety features
- [ ] Show approval gates
- [ ] Demonstrate all three modes
- [ ] Generate comprehensive report
- [ ] Answer questions clearly

### Post-Demo

- [ ] Reset environment: `docker-compose down -v`
- [ ] Review what worked
- [ ] Note improvements for next time
- [ ] Clean up if needed

---

## 🚀 Getting Started Right Now

```bash
# 1. Verify setup
./scripts/verify-demo-setup.sh

# 2. Start lab (if not running)
cd lab-environment && docker-compose up -d

# 3. Test MEDUSA
medusa observe --target http://localhost:3001

# 4. Review demo script
cat DEMO_SCRIPT.md

# 5. You're ready!
```

---

## 📞 Support

If you encounter issues:

1. Check **DEMO_SCRIPT.md** for detailed commands
2. Review **DEMO_QUICK_REFERENCE.md** for quick help
3. Run `./scripts/verify-demo-setup.sh` to diagnose
4. Check service logs: `docker-compose logs [service]`

---

**Good luck with your demo! 🚀**

Remember: This is an educational demonstration. Always use MEDUSA responsibly and only on systems you own or have explicit permission to test.

---

**Last Updated:** November 2025  
**Version:** 1.0

