# MEDUSA Demo - Quick Summary

## 📋 What You Need

### ⏱️ 10-Minute Demo (Current)
- **Main Script:** `DEMO_10MIN.md` ⭐ **USE THIS**
- **Quick Reference:** `DEMO_10MIN_QUICK_REF.md`
- **All Commands:** `docs/04-usage/complete-mode-reference.md` ⭐ **ALL COMMANDS HERE**

### 📚 Complete Documentation
- **All Commands & Modes:** `docs/04-usage/complete-mode-reference.md`
- **Quick Start Guide:** `docs/00-getting-started/cli-quickstart.md`
- **Usage Examples:** `docs/04-usage/usage-examples.md`

---

## 🎯 10-Minute Demo Flow

### Timeline
1. **0:00-1:00** - Introduction (1 min)
2. **1:00-3:00** - Observe Mode (2 min)
3. **3:00-6:00** - Autonomous Mode (3 min)
4. **6:00-8:00** - Interactive Mode (2 min)
5. **8:00-10:00** - Reporting (2 min)
6. **10:00-15:00** - Q&A (5 min)

### Four Commands to Run

```bash
# 1. Observe Mode (Safe Recon)
medusa observe --target http://localhost:3001

# 2. Autonomous Mode (AI-Driven)
medusa run --target http://localhost:8080 --autonomous

# 3. Interactive Mode (Natural Language)
medusa shell --target http://localhost:3001

# 4. Reports (Results)
medusa reports --open
```

---

## 📖 Where to Find Everything

### All Commands & Modes
**File:** `docs/04-usage/complete-mode-reference.md`

This document contains:
- ✅ All three operating modes (Observe, Autonomous, Interactive)
- ✅ Complete command syntax
- ✅ All CLI commands (`medusa setup`, `medusa status`, `medusa reports`, etc.)
- ✅ Mode comparison table
- ✅ Configuration options
- ✅ Troubleshooting guide

### Demo Scripts
- **10-Minute Demo:** `DEMO_10MIN.md` ⭐
- **Extended Demo (30-45 min):** `DEMO_SCRIPT.md`
- **Quick Reference:** `DEMO_10MIN_QUICK_REF.md`

### Setup & Verification
- **Pre-Demo Check:** `scripts/verify-demo-setup.sh`
- **Lab Environment:** `lab-environment/README.md`

---

## 🚀 Quick Start

```bash
# 1. Verify setup
./scripts/verify-demo-setup.sh

# 2. Start lab
cd lab-environment && docker-compose up -d

# 3. Check MEDUSA
medusa status

# 4. Run demo (follow DEMO_10MIN.md)
medusa observe --target http://localhost:3001
```

---

## 📊 Key Points to Emphasize

1. **AI-Powered** - Uses LLM to plan attacks intelligently
2. **Safety First** - Approval gates for risky actions
3. **Three Modes** - Observe (safe), Autonomous (AI-driven), Interactive (control)
4. **Comprehensive** - Network scanning, vulnerability detection, reporting
5. **MITRE ATT&CK** - Maps findings to ATT&CK framework

---

## ⚠️ Pre-Demo Checklist

- [ ] Lab environment started (`docker-compose up -d`)
- [ ] Services accessible (`curl http://localhost:8080`)
- [ ] MEDUSA configured (`medusa status`)
- [ ] Reviewed `DEMO_10MIN.md`
- [ ] Reviewed `docs/04-usage/complete-mode-reference.md`
- [ ] Team roles assigned

---

**Main Files:**
- Demo Script: `DEMO_10MIN.md`
- Commands Reference: `docs/04-usage/complete-mode-reference.md`
- Quick Reference: `DEMO_10MIN_QUICK_REF.md`

**Good luck! 🚀**
