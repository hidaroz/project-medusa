# Product Requirements Document: Project Medusa AI Agent

**Document Version:** 2.0  
**Status:** Final Draft  
**Author:** Hidar Elhassan, Lawrence Xu, Brian Yuan
**Last Updated:** October 7, 2025  
**Project Duration:** 7 weeks  
**Target Completion:** November 24, 2025

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [Introduction](#2-introduction)
3. [User Personas](#3-user-personas)
4. [Core Features](#4-core-features)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [Success Metrics](#6-success-metrics)
7. [Testing & Validation Plan](#7-testing--validation-plan)
8. [Ethical & Legal Framework](#8-ethical--legal-framework)
9. [Risk Management](#9-risk-management)
10. [Technical Architecture](#10-technical-architecture)
11. [Dataset Strategy](#11-dataset-strategy)
12. [Timeline & Milestones](#12-timeline--milestones)

---

## 1. Executive Summary

Project Medusa is an autonomous AI red team agent designed to simulate advanced adversary behavior in post-exploitation scenarios. Unlike traditional automated penetration testing tools that follow predefined scripts, Medusa uses a fine-tuned Large Language Model (LLM) to make context-aware decisions, adapting its tactics in real-time based on environmental observations.

**The Problem:** Modern cyber threats are characterized by human adversaries who think creatively, adapt to defenses, and exploit unexpected attack paths. Traditional automated security testing tools cannot replicate this adaptive behavior, creating a validation gap in defensive security posture assessments.

**The Solution:** Medusa combines offensive security expertise encoded in a specialized dataset with the reasoning capabilities of a fine-tuned Llama 3 8B model. The agent operates through an OODA loop (Observe, Orient, Decide, Act), executing reconnaissance, lateral movement, privilege escalation, and data exfiltration within a controlled environment—all while maintaining human oversight through an operator interface.

**Key Innovation:** This project demonstrates that custom-trained, locally-hosted LLMs can perform specialized cybersecurity tasks autonomously, reducing the cost and time of red team engagements while maintaining the adaptive intelligence that distinguishes human adversaries from scripted tools.

---

## 2. Introduction

### 2.1 Background

Red team operations are critical for validating enterprise security controls. However, skilled red team operators are expensive and time-consuming to deploy. Conversely, automated penetration testing tools (like Metasploit's automation or vulnerability scanners) lack the contextual reasoning needed to discover novel attack paths.

Recent advances in Large Language Models have demonstrated strong reasoning capabilities across diverse domains. This project explores whether a fine-tuned LLM can bridge the gap between expensive human expertise and limited automated tools.

### 2.2 Project Objectives

1. **Build a working autonomous red team agent** capable of completing a full attack chain from initial access to objective completion
2. **Demonstrate measurable advantages** over manual operations in terms of speed and consistency
3. **Maintain human oversight** through a Command & Control interface that allows operators to approve high-risk actions
4. **Operate entirely offline** to ensure operational security and demonstrate viability in air-gapped environments
5. **Produce academic research** documenting methodology, results, and lessons learned

### 2.3 Scope & Limitations

**In Scope:**
- Post-exploitation operations (assumes initial access is already obtained)
- Linux-based target environment
- Four kill chain phases: Reconnaissance, Lateral Movement, Privilege Escalation, Data Exfiltration
- Human-in-the-loop approval system
- Performance metrics collection

**Out of Scope:**
- Initial access/exploitation (phishing, vulnerability exploitation)
- Windows Active Directory environments (potential future work)
- Real-world deployment (strictly academic/research)
- Advanced evasion techniques (anti-forensics, memory-only execution)

---

## 3. User Personas

### 3.1 Primary Persona: The Red Team Operator

**Name:** Alex Rivera  
**Role:** Offensive Security Engineer  
**Experience:** 3-5 years in penetration testing and red teaming  
**Technical Skills:** Expert in Linux, networking, scripting; Intermediate in AI/ML

**Goals:**
- Conduct thorough security assessments efficiently
- Test whether AI can replicate adaptive adversary behavior
- Reduce time spent on repetitive post-exploitation tasks
- Quantify the effectiveness of defensive controls

**Pain Points:**
- Manual enumeration and lateral movement is tedious and time-intensive
- Difficult to maintain consistent methodology across engagements
- Hard to objectively measure "how well" a red team performed
- Scripted tools miss opportunities that human intuition would catch

**How Medusa Helps:**
- Automates the reconnaissance-to-exfiltration cycle
- Provides consistent, repeatable methodology
- Generates quantitative metrics (TTO, Autonomy Index, Stealth Score)
- Applies reasoning to discover non-obvious attack paths

### 3.2 Secondary Persona: The Academic Evaluator

**Name:** Dr. Sarah Chen  
**Role:** Cybersecurity Professor / Capstone Advisor  
**Goals:** Assess technical rigor, innovation, and real-world applicability

**Evaluation Criteria:**
- Is the methodology sound and reproducible?
- Does the project demonstrate mastery of LLM fine-tuning?
- Are ethical considerations properly addressed?
- Do the results validate the core hypothesis?

---

## 4. Core Features

### F1.0: Internal Reconnaissance

**F1.1 - Network Enumeration Parsing**  
- **Description:** Agent must parse output from network discovery tools (`nmap`, `arp-scan`, `ping`)
- **Input:** Raw command-line output (text)
- **Output:** Structured data about live hosts, open ports, running services
- **Priority:** P0 (Critical)

**F1.2 - Target Prioritization**  
- **Description:** Agent must reason about discovered hosts to identify high-value targets
- **Logic:** Domain controllers > database servers > file servers > workstations
- **Priority:** P0 (Critical)

**F1.3 - State Management**  
- **Description:** Maintain an evolving "network map" as new information is discovered
- **Storage:** In-memory dictionary structure (no database required)
- **Priority:** P0 (Critical)

---

### F2.0: Lateral Movement

**F2.1 - Credential Reuse**  
- **Description:** Agent must use captured credentials to authenticate to other hosts
- **Tools:** `ssh`, `psexec` (via Impacket), `smbclient`
- **Input:** List of credentials, list of discovered hosts
- **Output:** Successful authentication events
- **Priority:** P0 (Critical)

**F2.2 - Intelligent Credential Selection**  
- **Description:** Agent must reason about which credential to try against which host
- **Example:** Try admin credentials against server-class hosts before workstations
- **Priority:** P1 (Important)

---

### F3.0: Privilege Escalation

**F3.1 - Misconfiguration Identification**  
- **Description:** Detect and exploit common privilege escalation vectors
- **Examples:** 
  - SUID binaries
  - Weak file permissions on sensitive files
  - Sudo misconfigurations
- **Tools:** `find`, `sudo -l`, custom enumeration scripts
- **Priority:** P0 (Critical)

**F3.2 - Credential Harvesting**  
- **Description:** Extract higher-privilege credentials from compromised hosts
- **Tools:** Simulated `mimikatz` equivalent (reads from mock credential store)
- **Priority:** P1 (Important)

---

### F4.0: Data Exfiltration & Impact

**F4.1 - Sensitive Data Discovery**  
- **Description:** Search filesystems for valuable data using keyword matching
- **Keywords:** "confidential", "patient", "SSN", "financial", "password"
- **Tools:** `grep`, `find`
- **Priority:** P0 (Critical)

**F4.2 - Payload Deployment**  
- **Description:** Deploy simulated ransomware or wiper on primary target
- **Implementation:** Script that renames files with `.encrypted` extension
- **Requirement:** Must require human approval before execution
- **Priority:** P0 (Critical)

---

### F5.0: Command & Control Operator Interface

**F5.1 - Mission Initialization**  
- **Input:** High-level goal in natural language (e.g., "Locate and exfiltrate patient database from file server")
- **Output:** Agent acknowledges goal and begins autonomous operation
- **Priority:** P0 (Critical)

**F5.2 - Real-Time OODA Loop Display**  
- **Display Elements:**
  - **Observe:** Current command output
  - **Orient:** Agent's interpretation of the data
  - **Decide:** Proposed next action with reasoning
  - **Act:** Command to be executed
- **Format:** Structured CLI output with color coding
- **Priority:** P0 (Critical)

**F5.3 - Human Approval System**  
- **Trigger:** High-impact actions (privilege escalation, lateral movement, payload deployment)
- **Interface:** CLI prompt with `[A]pprove / [D]eny / [M]odify` options
- **Priority:** P0 (Critical)

**F5.4 - Kill Switch**  
- **Trigger:** Operator enters `CTRL+C` or types `KILL`
- **Behavior:** Immediately halt all operations, save state log, exit gracefully
- **Priority:** P0 (Critical)

**F5.5 - Mission Logging**  
- **Output:** Timestamped log of all observations, decisions, and actions
- **Format:** JSON Lines (`.jsonl`) for easy analysis
- **Priority:** P1 (Important)

---

## 5. Non-Functional Requirements

### NF1: Operational Security (OPSEC)
- Agent must operate entirely offline within containerized environment
- No external API calls to OpenAI, Anthropic, or any cloud service
- All LLM inference must occur on localhost via Ollama

### NF2: Performance
- **Target:** Agent reasoning cycle (command output → LLM inference → next command) completes in <10 seconds
- **Rationale:** Ensures demo remains engaging; simulates real-time decision-making
- **Measurement:** Log timestamps for each OODA loop iteration

### NF3: Reproducibility
- Entire environment (network lab, Medusa agent, EHR system) must deploy via `docker-compose up`
- Dataset and fine-tuning code must be version-controlled
- Documentation must allow replication by third parties

### NF4: Safety
- Agent must never execute commands outside the containerized environment
- All "destructive" actions (file encryption, data deletion) must be simulated with reversible operations
- Human approval required for any action classified as "high-risk"

### NF5: Maintainability
- Code must follow PEP 8 style guidelines (Python)
- All functions must have docstrings
- README must include setup instructions, troubleshooting guide, and architecture diagram

---

## 6. Success Metrics (KPIs)

### 6.1 Time-to-Objective (TTO)
- **Definition:** Elapsed time from agent activation to successful payload deployment on primary target
- **Target:** <30 minutes for a 3-host network
- **Measurement:** Calculate from mission start timestamp to final payload execution log entry
- **Baseline Comparison:** Measure your own manual completion time for the same mission

### 6.2 Autonomy Index
- **Definition:** Percentage of actions completed without human intervention
- **Formula:** `(Autonomous Actions / Total Actions) × 100`
- **Target:** ≥70% autonomy
- **Rationale:** Demonstrates agent can operate independently for majority of mission

### 6.3 Stealth Score
- **Definition:** Ratio of successful actions to EDR alerts generated
- **Formula:** `(Successful Actions / Total EDR Alerts) × 100`
- **Target:** ≥60% (more successful actions than alerts)
- **Measurement:** Parse EDR logs for alert count, compare to action count from mission log

### 6.4 Command Success Rate
- **Definition:** Percentage of issued commands that execute without errors
- **Formula:** `(Successful Commands / Total Commands) × 100`
- **Target:** ≥85%
- **Rationale:** Measures quality of agent's decision-making and parsing accuracy

### 6.5 Novel Path Discovery
- **Definition:** Count of attack paths discovered that were not explicitly in training data
- **Measurement:** Manual review of mission logs to identify emergent behavior
- **Target:** ≥1 per mission (proof of generalization)

---

## 7. Testing & Validation Plan

### 7.1 Unit Testing

**Component:** LLM Response Parser  
- **Test:** Verify JSON extraction from model output
- **Cases:** Valid JSON, malformed JSON, empty response
- **Tool:** `pytest`

**Component:** Command Executor  
- **Test:** Verify commands execute in isolated environment
- **Cases:** Valid commands, invalid commands, timeout scenarios
- **Tool:** `pytest` with mocked subprocess calls

**Component:** State Manager  
- **Test:** Verify network map updates correctly
- **Cases:** New host discovery, credential capture, duplicate detection
- **Tool:** `pytest`

### 7.2 Integration Testing

**Scenario 1:** Reconnaissance Phase  
- **Input:** Agent starts with IP of initial foothold
- **Expected Output:** Discovers all 3 hosts in network, identifies file server as high-value target
- **Pass Criteria:** Correct host identification within 5 minutes

**Scenario 2:** Lateral Movement  
- **Input:** Agent has captured credentials
- **Expected Output:** Successfully authenticates to target server
- **Pass Criteria:** SSH or SMB connection established

**Scenario 3:** Full Kill Chain  
- **Input:** High-level mission goal
- **Expected Output:** Agent completes reconnaissance → lateral movement → privilege escalation → data exfiltration → payload deployment
- **Pass Criteria:** All phases complete with <3 human interventions

### 7.3 Acceptance Testing

**Test Runs:** 5 different mission scenarios × 3 repetitions = 15 total runs

**Scenarios:**
1. **Basic Exfiltration:** "Locate and exfiltrate financial records from file server"
2. **Privilege Escalation Focus:** "Obtain root access on domain controller"
3. **Stealth Mission:** "Exfiltrate data without triggering more than 2 EDR alerts"
4. **Speed Run:** "Complete mission in under 15 minutes"
5. **Recovery Scenario:** "Complete mission even if first lateral movement attempt fails"

**Data Collection:**
- TTO for each run
- Autonomy Index for each run
- Stealth Score for each run
- Timestamped logs
- EDR alert logs

**Success Criteria:**
- 80% of runs complete successfully (12/15)
- Average TTO < 30 minutes
- Average Autonomy Index ≥ 70%

---

## 8. Ethical & Legal Framework

### 8.1 Controlled Environment Statement

This research is conducted **exclusively within isolated, containerized environments**. The Medusa agent will:
- Never be connected to production networks
- Never be tested against systems without explicit authorization
- Never be used for malicious purposes

All testing occurs on virtual machines controlled by the researcher, with no connection to internet or external networks during operation.

### 8.2 Data Privacy & Synthetic Data

- **No Real Data:** The mock EHR system contains 100% synthetically generated patient data
- **No PII:** Names, addresses, SSNs, and medical records are created using faker libraries
- **Data Disposal:** All synthetic data will be deleted upon project completion
- **Compliance:** While HIPAA does not apply to fictional data, we follow its spirit to demonstrate responsible data handling

### 8.3 Academic Integrity

This project adheres to [Your University]'s academic integrity policies:
- All code and ideas from external sources will be properly cited
- The fine-tuning dataset will credit MITRE ATT&CK framework and any adapted examples
- No plagiarism of existing red team agent implementations

### 8.4 Responsible Disclosure

If during development, novel offensive techniques or vulnerabilities are discovered:
1. They will **not** be published in detail
2. Descriptions will be generalized to prevent weaponization
3. If applicable, vulnerabilities will be reported to affected vendors per coordinated disclosure guidelines

### 8.5 No IRB Required (Rationale)

This project does not require Institutional Review Board approval because:
- No human subjects are involved
- No personally identifiable information is collected or processed
- The research is entirely technical in nature
- All systems tested are owned and controlled by the researcher

---

## 9. Risk Management

### 9.1 Technical Risks

| Risk | Probability | Impact | Mitigation Strategy |
|------|-------------|---------|---------------------|
| Fine-tuning produces unusable model | Medium | Critical | Use base Llama 3 with extensive prompt engineering as fallback |
| Google Colab GPU unavailable | Low | High | Fine-tune during off-peak hours; use Colab Pro ($10) if needed |
| Agent gets stuck in infinite loop | Medium | Medium | Implement max iteration counter (50 loops); add timeout per command (30s) |
| Docker networking issues on M1 Mac | Medium | Medium | Test early; fallback to VirtualBox VMs if unsolvable |
| LLM hallucinates dangerous commands | Medium | High | Human approval required for destructive actions; whitelist safe commands only |
| Dataset quality insufficient | High | Critical | Use structured template for all examples; peer review 20% of dataset |

### 9.2 Timeline Risks

| Risk | Probability | Impact | Mitigation Strategy |
|------|-------------|---------|---------------------|
| Dataset creation takes >1 week | High | Critical | Start immediately; reuse MITRE ATT&CK examples; use LLM to help generate initial drafts |
| Integration debugging extends beyond Week 3 | Medium | High | Simplify network to 2 hosts if needed; cut Windows hosts |
| Paper writing takes longer than expected | Medium | Medium | Use conference template (IEEE); write Results section as experiments complete |
| Illness or emergency | Low | Critical | Build 3-day buffer in Week 7; prioritize core demo over optional features |

### 9.3 Ethical Risks

| Risk | Probability | Impact | Mitigation Strategy |
|------|-------------|---------|---------------------|
| Agent breaks containment | Very Low | Critical | Use Docker network isolation; no host network mode; test containment before autonomous runs |
| Techniques could be weaponized | Medium | Medium | Generalize descriptions in paper; don't publish full dataset; add warnings in README |
| Project misunderstood as promoting cybercrime | Low | Medium | Clear ethical statement in all documentation; emphasize defensive value |

---

## 10. Technical Architecture

### 10.1 System Components

```
┌─────────────────────────────────────────────────────────┐
│                    Operator (You)                       │
└───────────────────┬─────────────────────────────────────┘
                    │
                    │ (CLI Interface)
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Medusa CLI Application                     │
│  ┌─────────────────────────────────────────────────┐   │
│  │  OODA Loop Engine                               │   │
│  │  - Observe: Parse command output                │   │
│  │  - Orient: Format prompt for LLM                │   │
│  │  - Decide: Query Ollama API                     │   │
│  │  - Act: Execute command in target environment   │   │
│  └─────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  State Manager                                  │   │
│  │  - Network map                                  │   │
│  │  - Credential store                             │   │
│  │  - Mission log                                  │   │
│  └─────────────────────────────────────────────────┘   │
└───────────────────┬─────────────────────────────────────┘
                    │
                    │ (HTTP API: localhost:11434)
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Ollama (Running Locally)                   │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Custom Medusa Model                            │   │
│  │  (Fine-tuned Llama 3 8B + LoRA Adapter)         │   │
│  └─────────────────────────────────────────────────┘   │
└───────────────────┬─────────────────────────────────────┘
                    │
                    │ (Commands via SSH/Docker exec)
                    ▼
┌─────────────────────────────────────────────────────────┐
│          Containerized Target Network (Docker)          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Workstation │  │  File Server │  │  Domain Ctrl │  │
│  │  (Ubuntu)    │  │  (Ubuntu)    │  │  (Ubuntu)    │  │
│  │  - EDR Agent │  │  - Mock PHI  │  │  - Creds DB  │  │
│  │  - Web Shell │  │  - EDR Agent │  │  - EDR Agent │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                    │
                    │ (HTTP - Runs on Host)
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Mock EHR Web Application                   │
│              (Next.js - Static Frontend)                │
└─────────────────────────────────────────────────────────┘
```

### 10.2 Data Flow

1. **Operator Input:** "Locate and exfiltrate patient database from file server"
2. **Medusa CLI:** Initializes state, sends goal + context to Ollama
3. **Ollama/LLM:** Returns decision: `{"command": "nmap -sn 192.168.1.0/24", "reasoning": "Discover live hosts"}`
4. **Medusa CLI:** Executes `nmap` in target network via SSH
5. **Target Network:** Returns command output
6. **Medusa CLI:** Parses output, updates network map, repeats OODA loop
7. **EDR Agent:** Logs suspicious activity (process creation, network connection)
8. **(Loop continues until objective achieved)**

### 10.3 Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| LLM Base Model | Llama 3 8B Instruct | Best balance of reasoning ability and resource requirements |
| Fine-Tuning Method | QLoRA (4-bit) | Enables training on free Colab GPUs |
| Fine-Tuning Framework | Hugging Face TRL | Industry standard, well-documented |
| Local LLM Hosting | Ollama | Simple API, optimized for Apple Silicon |
| CLI Framework | Python Click | Clean argument parsing, easy to extend |
| Target Environment | Docker Compose | Reproducible, isolated networking |
| Mock EHR | Next.js + TypeScript | Already built, familiar to you |
| EDR Simulation | Python script | Lightweight, logs to JSON |
| Version Control | Git + GitHub | Standard for academic projects |

---

## 11. Dataset Strategy

### 11.1 Dataset Structure

Each training example follows this format:

```json
{
  "instruction": "System prompt + current context + task",
  "input": "Specific data to process (command output, network map, etc.)",
  "output": "Expected JSON response with command and reasoning"
}
```

**Example:**

```json
{
  "instruction": "You are Medusa, an autonomous red team agent. Your goal is to discover live hosts on the network. Parse the following command output and decide the next action.",
  "input": "Starting Nmap scan on 192.168.1.0/24\nHost 192.168.1.10 is up (0.0021s latency)\nHost 192.168.1.20 is up (0.0034s latency)\nHost 192.168.1.30 is up (0.0019s latency)",
  "output": "{\"reasoning\": \"Three hosts discovered. Next step is to identify running services on each host to prioritize targets.\", \"command\": \"nmap -sV -p 22,80,443,445,3389 192.168.1.10 192.168.1.20 192.168.1.30\", \"phase\": \"reconnaissance\", \"risk_level\": \"low\"}"
}
```

### 11.2 Dataset Categories & Distribution

**Total Target:** 200 examples minimum (250-300 ideal)

| Category | Count | Purpose |
|----------|-------|---------|
| **Reconnaissance** | 60 | Parsing nmap, identifying services, prioritizing targets |
| **Lateral Movement** | 50 | Credential selection, SSH/SMB usage, testing access |
| **Privilege Escalation** | 40 | Finding SUID binaries, exploiting sudo, parsing /etc/passwd |
| **Data Exfiltration** | 30 | Searching for sensitive files, staging data, simulating exfil |
| **Error Handling** | 20 | Recovering from failed commands, alternative approaches |

### 11.3 Quality Assurance Checklist

For each training example, verify:

- [ ] **Instruction** is clear and provides sufficient context
- [ ] **Input** resembles realistic command output (including errors, formatting)
- [ ] **Output** is valid JSON with all required fields: `reasoning`, `command`, `phase`, `risk_level`
- [ ] **Command** is syntactically correct and would work in target environment
- [ ] **Reasoning** demonstrates security logic (e.g., "Target host .10 first because port 445 indicates file sharing")
- [ ] **Diversity**: Don't repeat same scenario with minor variations

### 11.4 Sources for Dataset Creation

1. **MITRE ATT&CK Framework**
   - Technique pages include detailed procedures
   - Example: T1021.002 (SMB/Windows Admin Shares) → adapt for Linux/SSH
   - Link: https://attack.mitre.org

2. **HackTheBox / TryHackMe Writeups**
   - Published walkthroughs show realistic command sequences
   - Extract the "what command to run next" decision points
   - Anonymize any specific vulnerability names

3. **Your Own Manual Runs**
   - As you build the lab, document your own enumeration steps
   - Convert your thought process into instruction/output pairs

4. **LLM-Assisted Generation**
   - Use ChatGPT/Claude to generate *drafts* of examples
   - **Critical:** Review and edit every single one for accuracy
   - Prompt example: "Generate a training example where a red team agent needs to parse nmap output showing port 22 open and decide whether to attempt SSH brute force or credential stuffing"

### 11.5 Dataset Template (Use This!)

Create a spreadsheet or markdown file with this structure for tracking:

```markdown
## Example ID: RECON-001

**Instruction:**
You are Medusa, an autonomous red team agent. Your current objective is to discover live hosts on the subnet 192.168.1.0/24. Parse the following nmap output and determine the next action.

**Input:**
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.10
Host is up (0.00021s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http

Nmap scan report for 192.168.1.20
Host is up (0.00034s latency).
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
3306/tcp open  mysql

**Output:**
```json
{
  "reasoning": "Two hosts discovered. Host .10 appears to be a web server (ports 22, 80). Host .20 has SMB and MySQL, indicating it's likely a file/database server and higher value. Prioritize .20 for next enumeration.",
  "command": "nmap -sV -sC -p 445,3306 192.168.1.20",
  "phase": "reconnaissance",
  "risk_level": "low",
  "target_host": "192.168.1.20"
}
```

**QA Notes:**
- ✅ Reasoning demonstrates target prioritization logic
- ✅ Command is syntactically correct
- ✅ JSON is valid
- ✅ Matches realistic red team decision-making

---
```

### 11.6 Time-Saving Tips

1. **Batch Similar Scenarios:** Create 10 reconnaissance examples in one sitting, then switch to lateral movement
2. **Use Find/Replace:** If you need to change IP addresses across many examples, use regex
3. **Validate JSON:** Use an online JSON validator after creating each output
4. **Peer Review:** Have a classmate or ChatGPT check 10 random examples for quality

---

## 12. Timeline & Milestones

*(Refer to separate Timeline artifact for detailed week-by-week breakdown)*

**Key Milestones:**

- **Week 1 End:** Dataset complete (200+ examples)
- **Week 2 End:** Medusa model fine-tuned and running locally
- **Week 3 End:** Target network deployed, agent integrated
- **Week 4 End:** Full autonomous operation working
- **Week 5 End:** All metrics collected, data visualized
- **Week 6 End:** Paper draft complete, demo video recorded
- **Week 7 End:** Final submission ready

---

## 13. Deliverables Checklist

### 13.1 Code Repository (GitHub)

```
medusa-ai-redteam/
├── README.md                    # Setup instructions, architecture diagram
├── requirements.txt             # Python dependencies
├── docker-compose.yml           # Target network definition
├── dataset/
│   ├── dataset.json            # Training data
│   └── generation_notes.md     # How dataset was created
├── fine-tuning/
│   ├── finetune_colab.ipynb   # Google Colab notebook
│   └── merge_adapter.py        # Script to merge LoRA weights
├── medusa-cli/
│   ├── main.py                 # Entry point
│   ├── ooda_loop.py           # Core reasoning engine
│   ├── state_manager.py       # Network map, credentials
│   ├── command_executor.py    # SSH/exec wrapper
│   └── config.yaml            # Configuration
├── target-network/
│   ├── Dockerfile.workstation
│   ├── Dockerfile.fileserver
│   ├── Dockerfile.dc
│   └── edr_agent.py           # Simulated EDR
├── mock-ehr/                   # Your Next.js app (already exists)
├── tests/
│   ├── test_parser.py
│   ├── test_executor.py
│   └── integration_test.py
├── results/
│   ├── mission_logs/          # JSONL files from test runs
│   ├── metrics.csv            # TTO, Autonomy, Stealth data
│   └── visualizations/        # Charts and graphs
└── docs/
    ├── PRD.md                 # This document
    ├── ARCHITECTURE.md        # Detailed technical design
    └── ETHICS.md              # Ethical considerations
```

### 13.2 Academic Paper (6-10 pages)

**Sections:**
1. Abstract (150 words)
2. Introduction (1-1.5 pages)
3. Related Work (1 page)
4. Methodology (2 pages)
5. Results (1.5 pages)
6. Discussion (1 page)
7. Conclusion & Future Work (0.5 pages)
8. References (1 page)

**Format:** IEEE Conference or ACM format (use Overleaf template)

### 13.3 Presentation (15-20 slides)

**Slide Breakdown:**
1. Title Slide
2. Problem Statement (Why AI red teaming matters)
3. Project Objectives
4. Related Work (brief)
5. Technical Architecture (diagram)
6. Dataset Strategy
7. Fine-Tuning Approach
8. Demo Video (3-5 minutes)
9. Results: Time-to-Objective
10. Results: Autonomy Index
11. Results: Stealth Score
12. Key Findings
13. Limitations
14. Future Work
15. Conclusion
16. Questions?

### 13.4 Demo Video (15-20 minutes)

**Script:**
- 0:00-2:00: Introduction and problem overview
- 2:00-4:00: Architecture walkthrough
- 4:00-6:00: Show target network (docker-compose up)
- 6:00-8:00: Initialize Medusa with mission goal
- 8:00-14:00: **Live agent operation** (sped up 2x if needed)
- 14:00-16:00: Results dashboard and metrics
- 16:00-18:00: Lessons learned and future work
- 18:00-20:00: Q&A prep and closing

---

## 14. Success Criteria (Project Evaluation)

This project will be considered successful if:

### Technical Success
- [ ] Fine-tuned model generates valid JSON responses >90% of the time
- [ ] Agent completes at least 3/5 test scenarios autonomously
- [ ] Average TTO < 30 minutes
- [ ] Average Autonomy Index ≥ 70%
- [ ] No containment breaches during testing

### Academic Success
- [ ] Paper clearly articulates methodology and results
- [ ] Results section includes quantitative data and visualizations
- [ ] Discussion acknowledges limitations honestly
- [ ] References cite 8+ relevant academic papers and frameworks

### Presentation Success
- [ ] Demo video shows full kill chain execution
- [ ] Presentation is delivered confidently within time limit
- [ ] Q&A responses demonstrate deep understanding of technical decisions
- [ ] Advisor/evaluators rate project as "exceeds expectations"

---

## 15. Contingency Plans

### If Fine-Tuning Fails
**Symptoms:** Model outputs gibberish, JSON parsing fails constantly, reasoning is nonsensical

**Fallback Plan:**
1. Use base Llama 3 8B Instruct (no fine-tuning)
2. Implement extensive prompt engineering with few-shot examples
3. Create a "prompt library" with 5-10 examples per phase
4. Accept lower autonomy index (50-60%)
5. **Thesis pivot:** Focus on "prompt engineering for red team automation" rather than "fine-tuning"

### If Docker Networking is Unstable
**Symptoms:** Containers can't reach each other, DNS fails, SSH connections timeout

**Fallback Plan:**
1. Switch to VirtualBox with bridged networking
2. Manually assign static IPs
3. Accept longer setup time in exchange for stability
4. Document workaround in paper's "Implementation Challenges" section

### If Timeline Slips
**Priority ranking (complete in order):**
1. **Must Have:** Working agent for 1 scenario + dataset + basic paper
2. **Should Have:** 3 scenarios + full metrics + polished paper
3. **Nice to Have:** 5 scenarios + comparison with manual + publication-ready paper

**Cut if necessary:**
- Comparison with other automated tools
- Advanced evasion techniques
- Windows environment testing
- EDR telemetry analysis (just log, don't analyze deeply)

---

## Appendix A: Glossary

- **OODA Loop:** Observe, Orient, Decide, Act - decision-making framework
- **Kill Chain:** Sequential phases of a cyber attack
- **C2 (Command & Control):** Infrastructure for remotely controlling compromised systems
- **LoRA (Low-Rank Adaptation):** Efficient fine-tuning technique that trains small adapter layers
- **QLoRA:** LoRA with 4-bit quantization for reduced memory usage
- **TTO (Time-to-Objective):** Primary performance metric
- **PHI (Protected Health Information):** Sensitive medical data (all synthetic in this project)
- **EDR (Endpoint Detection and Response):** Security software that monitors host activity

## Appendix B: References

*(To be populated as you conduct literature review)*

1. MITRE ATT&CK Framework. (2024). https://attack.mitre.org
2. Meta AI. (2024). Llama 3 Model Card. https://ai.meta.com/llama/
3. [Your university]'s Ethics Guidelines for Computing Research
4. [Add 5-7 academic papers on: LLMs for cybersecurity, automated penetration testing, red team automation]

---

**End of PRD**