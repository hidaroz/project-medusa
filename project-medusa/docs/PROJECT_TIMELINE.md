# Project Medusa: 7-Week Execution Timeline
---

## **Week 1: Foundation & Learning (Oct 6-12)**
**Goal:** Understand the tech stack and create your dataset foundation

### Monday-Tuesday: Environment Setup
- [ ] Install Ollama on Mac
- [ ] Create Google Colab account and test GPU access
- [ ] Set up GitHub repository with proper structure
- [ ] Install Docker Desktop

### Wednesday-Friday: Dataset Creation (Phase 1)
- [ ] Study MITRE ATT&CK techniques (focus on: T1087, T1021, T1003, T1083)
- [ ] Create 50 instruction/response pairs for **Reconnaissance** phase
- [ ] Create 50 pairs for **Lateral Movement** phase
- [ ] Format dataset as `dataset.json` with proper structure

### Weekend: Dataset Creation (Phase 2)
- [ ] Create 50 pairs for **Privilege Escalation**
- [ ] Create 50 pairs for **Exfiltration**
- [ ] Total: 200 high-quality examples minimum

**Deliverable:** `dataset.json` file with 200+ training examples

---

## **Week 2: Fine-Tuning & Initial Testing (Oct 13-19)**
**Goal:** Get your custom Medusa model running locally

### Monday-Tuesday: Google Colab Fine-Tuning
- [ ] Follow provided Colab notebook step-by-step
- [ ] Upload dataset.json to Colab
- [ ] Execute fine-tuning (2-3 hours of GPU time)
- [ ] Download `medusa-adapter` folder

### Wednesday-Thursday: Local Model Deployment
- [ ] Merge adapter with base Llama 3 model
- [ ] Create Ollama Modelfile
- [ ] Test local inference with simple prompts
- [ ] Validate response format (JSON output)

### Friday-Weekend: Build Medusa CLI (v0.1)
- [ ] Create Python project structure
- [ ] Build basic CLI with `argparse` or `click`
- [ ] Implement Ollama API integration
- [ ] Test with 3-5 manual scenarios

**Deliverable:** Working CLI that can query your local Medusa model

---

## **Week 3: Mock Environment & Integration (Oct 20-26)**
**Goal:** Create the target network and connect Medusa to it

### Monday-Tuesday: Network Lab Setup
- [ ] Design network topology (3-5 VMs)
- [ ] Create Docker Compose file for environment
- [ ] Deploy: 1 Domain Controller, 1 Workstation, 1 File Server (all Linux for simplicity)
- [ ] Configure intentional vulnerabilities

### Wednesday-Thursday: Simulated EDR
- [ ] Write basic Python script that logs process creation
- [ ] Log network connections on each host
- [ ] Create alert rules for suspicious behavior
- [ ] Output logs to centralized file

### Friday-Weekend: Integration Testing
- [ ] Connect Medusa CLI to lab environment
- [ ] Test each kill chain phase individually
- [ ] Debug and fix parsing errors
- [ ] Document any limitations

**Deliverable:** Containerized lab environment with working Medusa integration

---

## **Week 4: OODA Loop & Operator Interface (Oct 27-Nov 2)**
**Goal:** Make Medusa autonomous and add human-in-the-loop controls

### Monday-Wednesday: OODA Loop Implementation
- [ ] Build state management system (track network map, credentials)
- [ ] Implement decision-making logic (LLM → command selection)
- [ ] Add command execution wrapper
- [ ] Parse command output and feed back to LLM

### Thursday-Friday: Operator Controls
- [ ] Add `approve/deny` prompts for high-risk actions
- [ ] Implement kill switch functionality
- [ ] Create real-time logging display
- [ ] Add mission briefing input

### Weekend: End-to-End Testing
- [ ] Run full autonomous mission (start to payload deployment)
- [ ] Measure Time-to-Objective (TTO)
- [ ] Calculate Autonomy Index
- [ ] Record demo video (rough cut)

**Deliverable:** Fully autonomous agent with operator oversight

---

## **Week 5: Metrics Collection & Analysis (Nov 3-9)**
**Goal:** Gather data to prove your project works

### Monday-Tuesday: Automated Testing
- [ ] Create 5 different mission scenarios
- [ ] Run Medusa 3 times per scenario (15 total runs)
- [ ] Log all metrics (TTO, commands executed, alerts triggered)
- [ ] Compare against manual red team baseline (you manually perform the same mission)

### Wednesday-Thursday: Stealth Analysis
- [ ] Review EDR logs from all test runs
- [ ] Calculate Stealth Score for each scenario
- [ ] Identify most common alert triggers
- [ ] Document evasion techniques Medusa discovered

### Friday-Weekend: Data Visualization
- [ ] Create charts: TTO comparison, Autonomy Index trend, Stealth heatmap
- [ ] Build comparison table: Medusa vs Manual vs Scripted Tools
- [ ] Write "Results" section for paper

**Deliverable:** Complete dataset with visualizations proving effectiveness

---

## **Week 6: Documentation & Paper Writing (Nov 10-16)**
**Goal:** Create academic paper and clean up code

### Monday-Tuesday: Academic Paper (Part 1)
- [ ] Write Abstract (150 words)
- [ ] Write Introduction (Why AI red teaming matters)
- [ ] Write Related Work (survey 5-7 similar projects)
- [ ] Write Methodology (your technical approach)

### Wednesday-Thursday: Academic Paper (Part 2)
- [ ] Write Results section (present your metrics)
- [ ] Write Discussion (what worked, what didn't, why)
- [ ] Write Conclusion and Future Work
- [ ] Add References (IEEE format)

### Friday: Code Cleanup
- [ ] Add docstrings to all functions
- [ ] Create comprehensive README.md
- [ ] Write setup instructions
- [ ] Tag release version v1.0

### Weekend: Demo Video Recording
- [ ] Record professional screen capture (15-20 minutes)
- [ ] Show: setup, mission briefing, autonomous operation, results
- [ ] Add voiceover explanation
- [ ] Edit and export final version

**Deliverable:** Draft paper (6-10 pages) and polished demo video

---

## **Week 7: Presentation & Final Polish (Nov 17-23)**
**Goal:** Prepare for defense and final submission

### Monday-Tuesday: Presentation Creation
- [ ] Build 15-20 slide deck (see separate artifact)
- [ ] Include: Problem, Solution, Architecture, Demo clips, Results
- [ ] Practice presentation 3+ times
- [ ] Prepare for Q&A (anticipate 10 common questions)

### Wednesday: Peer Review
- [ ] Have classmate or advisor review paper
- [ ] Incorporate feedback
- [ ] Proofread for typos and formatting
- [ ] Generate final PDF

### Thursday: Final Submission Prep
- [ ] Upload code to GitHub (ensure all secrets removed)
- [ ] Upload demo video to YouTube (unlisted)
- [ ] Submit paper, presentation, and links
- [ ] Create LinkedIn post draft

### Friday: BUFFER DAY
- [ ] Fix any last-minute issues
- [ ] Rehearse presentation one final time
- [ ] Rest and prepare mentally

**Deliverable:** Complete capstone submission package

---

## **Critical Path Items (Cannot Be Delayed)**
1. **Dataset creation (Week 1)** - Everything depends on this
2. **Fine-tuning completion (Week 2)** - Must work before integration
3. **OODA loop (Week 4)** - Core functionality for demo
4. **Metrics collection (Week 5)** - Needed for paper results

## **Time-Saving Strategies**
- Use Linux VMs only (simpler than Windows AD)
- Limit network to 3 hosts maximum
- Focus on 2-3 attack techniques deeply rather than many superficially
- Use existing Docker images (Kali, Ubuntu) rather than building from scratch
- For paper, use conference template (ACM, IEEE) to save formatting time

## **Contingency Plans**
- **If fine-tuning fails:** Use base Llama 3 with extensive prompt engineering
- **If Docker issues persist:** Run VMs in VirtualBox instead
- **If full autonomy is buggy:** Focus on semi-autonomous mode (human approves each step)
- **If time runs short:** Cut comparison with other tools, focus on proving Medusa works

## **Weekly Check-ins**
Every Sunday evening, assess:
1. What % of this week's tasks are complete?
2. What blockers exist?
3. Do I need to adjust next week's scope?