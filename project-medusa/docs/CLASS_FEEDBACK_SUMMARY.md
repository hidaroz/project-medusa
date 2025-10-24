# Class Feedback Summary - Demo #1

## Key risks & under-specified assumptions (themes)

### Stealth & detectability
* How will the attacking agent avoid EDR/SIEM/USB controls and remain **undetected**?
* No concrete **detection thresholds** or evasion tactics were shown; need a plan to bypass baseline controls (device control, PowerShell/Constrained Language Mode, CrowdStrike, etc.).

### Access model & human factors
* Heavy reliance on **physical access/unlocked workstations** and nurses leaving stations; that's fragile.
* Assumes staff won't log out and that USBs aren't blocked—may be false in many hospitals.

### Attack window realism
* The **2–4 AM** "30-second" window may be too narrow/unrealistic; how does the approach generalize to **other times** and **larger/stricter environments**?

### API assumptions
* Assumes exploitable **API misconfigurations** and broad visibility. Need proof via inventory/auth matrix and targeted tests (IDOR, rate limits, missing auth).

### Multi-agent/RL safety
* **Reward hacking** and safety guardrails are unclear; risk the RL agent "hacks" the objective.

### Generalizability
* Methods may not transfer across **different hospital stacks/vendors**; needs cross-env validation.

---

## Suggested experiments & "next sprint" ideas

### Quantify stealth
* Define **detectability metrics** (alert count, dwell time before first alert, TTI under EDR).
* Run trials against a hardened Windows image with typical controls.

### USB & endpoint controls
* Build a **USB-insertion monitoring/alert** service and measure **time-to-impact** vs. defenses.
* Test **PowerShell** restrictions and common bypasses; document which detections trigger.

### Broaden access vectors
* Add non-physical initial access options (API auth flaws, phishing-to-MFA fatigue, VPN misconfig).
* Validate with an **API discovery & auth test harness** (OpenAPI diffing, IDOR probes, rate-limit tests) against synthetic PHI.

### RL/agent safety
* Start with a **simpler, supervised agent**; add RL only with sandboxed rewards and guardrails.

### Environment diversity
* Test in **multiple simulated hospital networks** (different vendors, policies) to check portability.

### Telemetry & explainability
* Ship a **visualization dashboard** of the agent's decisions and attack chain; log every step, tool, and rationale.

### User research
* **Interview clinical/IT staff** to validate realistic workflows, role duties, and after-hours practices; tighten role scope.

---

## What resonated (strengths called out)

* **Clarity & structure:** Clear experimental framing, strong slide structure, and easy-to-follow flow.
* **Compelling demos:**
  * **USB Rubber Ducky** scenario felt concrete and memorable.
  * **Dashboards** (patient-data view, email quarantine/release) showed end-to-end thinking.
  * **Terminal demo** with command breakdown conveyed technical depth.
* **Storytelling:** Tying technical steps to a healthcare impact model landed well.
* **Agent design detail:** The AI agent architecture and "end-to-end attack chain" impressed several reviewers.

---

## Open questions to answer by Demo #2

1. What **specific controls** can your agent evade, and what is the **measured alert footprint**?
2. How does the attack perform **outside 2–4 AM** and without human workstation negligence?
3. What's the **API exposure reality** (inventory, auth matrix, concrete vulns) in your target twin?
4. How do you **classify email risk**, involve humans, and **measure CTR** ethically?
5. What **RL guardrails** prevent reward hacking and unsafe behaviors?
6. Does the approach **generalize** across at least two distinct simulated hospital environments?

---

## Metrics to report next

* **Time-to-impact (TTI)** with/without common EDR controls.
* **Detection rate** and **mean alerts** per run; **dwell time** pre-detection.
* **Bypass success** for USB control and PowerShell restrictions.
* **API findings:** # of endpoints discovered, auth gaps (IDORs, rate-limit breaks).
* **Email pipeline:** precision/recall by risk tier; human-override rate; simulated CTR.
* **Safety:** incidents of RL reward hacking or unsafe action attempts (should be zero with guardrails).

---

This rolls the class's comments into a focused roadmap: prove stealth, reduce dependency on human lapses, validate APIs with real tests, formalize the email pipeline with a human loop, de-risk RL, and show generalizability—with clear telemetry to back it all.

---

# Class Feedback Summary - Demo #2

## Overall take

The room sees meaningful progress toward a truly **adaptive** adversary: you're moving from "one-off attacks" to a **Detect → Assess → Adapt** loop backed by stakeholder needs, RAG, and clearer role/permission models. Now the bar shifts to proving this loop works under pressure, is safe/ethical, and is measurable.

---

## Strongest improvements

* **Detect–Assess–Adapt loop:** Clearer adaptive logic; fewer "random" LLM actions; explicit learning after mistakes.
* **Stakeholder-driven features:** Requirements translated into concrete capabilities; environment mapping felt more realistic.
* **RAG integration:** Continuous updating vs. a static fine-tune; emphasis on keeping tactics current with patches.
* **Security architecture realism:** RBAC added (roles in JWT), login/auth present; ATT&CK mapping and evasion reasoning tied to healthcare context.
* **Model interpretability:** Scoring/decision tree structure now has "structural integrity" and is easier to understand.
* **Detection awareness:** Training now includes detection vectors; thinking about what gets logged/caught.

---

## Biggest risks & open questions

* **Training quality & decision making:** Will the AI actually choose the right actions at the right time (beyond toy cases)?
* **Legal/ethical exposure (USB path):** Physical insertion + cameras = risk; ensure simulations are clearly sandboxed/ethical.
* **Data/RAG plumbing:** How exactly is data ingested, curated, and versioned for reliable adaptation (not just "adding files")?
* **Generalization & HIL (human-in-loop):** When and how humans arbitrate; consistency of outputs; clarity on CTR testing without real users.
* **Residuals/forensics:** Does Medusa leave artifacts that burn the tool after one use?
* **Defense reactivity:** Need an adaptive **defense** feedback loop, not just adaptive offense.
* **Auth & RBAC robustness:** Can JWT/RBAC withstand replay, expiry, forging, and cross-role attempts?
* **UI/Comms:** TXT-file demos/readability; "System Status" usefulness varies by persona; assessment report design.
* **Data leakage risk:** Role-based data/context may leak between roles if not isolated.

---

## Concrete tests to run before next demo

### Adaptation under shifting defenses
* Change detection rules mid-run; measure *time-to-adapt* and *post-change success rate*.

### RAG evaluation
* Ablation: with vs. without RAG; measure improvement in success, speed, and detection footprint.
* Data hygiene tests: outdated/poisoned docs—does performance degrade safely?

### Stealth/forensics
* Instrument endpoints and SIEM to detect artifacts (files, registry, PowerShell logs). Report *trace rate* per run.

### RBAC/JWT hardening
* Fuzz tokens (expired, tampered signatures), role crossing, replay attempts. Expect zero unauthorized access.

### Email pipeline quality (if in scope)
* Precision/recall on authentic corpora; tune thresholds to reduce false positives and quantify human-override rate.

### Device/OT angle (optional spike)
* Small PoC on legacy medical device protocols in a sandbox to validate feasibility and ethics boundaries.

### Usability checks
* Quick hallway tests on the dashboard: can personas complete key tasks? Is "System Status" actionable?

---

*Note: This feedback summary was synthesized and organized by ChatGPT based on class discussion notes from Demo #1 and Demo #2.*
