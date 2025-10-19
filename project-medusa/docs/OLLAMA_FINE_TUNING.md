# Ollama Fine-Tuning Implementation Plan
## Project Medusa - Custom Model Training & Deployment

**Author:** Lawrence Wu  
**Date:** October 15, 2025  
**Status:** Planning Phase → Implementation Starting Week 3  
**Target Completion:** October 24, 2025 (Mid-Quarter Analysis)

---

## Executive Summary

This document outlines the complete implementation plan for fine-tuning a custom language model for Project Medusa using Ollama. The fine-tuned model will replace the current Gemini placeholder and provide healthcare-specific red team operational intelligence. This specialized model will understand healthcare infrastructure, medical device vulnerabilities, and HIPAA-compliant attack methodologies.

**Key Objectives:**
- Train a specialized model on 200+ healthcare-focused red team scenarios
- Deploy locally via Ollama for privacy and performance
- Integrate seamlessly with existing OODA loop CLI architecture
- Achieve measurable improvements in decision quality and speed

---

## 1. Current State Assessment

### 1.1 What We Have
- **Dataset Progress:** 127-240 examples (76% complete, targeting 200 minimum)
- **Dataset Structure:** 12 MITRE ATT&CK-aligned categories
- **Current Architecture:** Working OODA loop CLI with Gemini API
- **Baseline Performance:** Basic autonomous operation (3-5 iterations demonstrated)
- **Infrastructure:** Docker containerized environment, Python-based CLI

### 1.2 Why Fine-Tuning is Necessary
**Current Limitation:** Gemini (general-purpose model) lacks:
- Healthcare-specific vulnerability knowledge
- Medical device exploitation patterns  
- HIPAA compliance considerations
- Healthcare network architecture understanding
- Medical terminology and context

**Fine-Tuned Model Benefits:**
- Faster decision-making (domain-specific knowledge)
- Higher accuracy (trained on curated examples)
- Better reasoning (healthcare context built-in)
- Offline capability (no API dependencies)
- Cost efficiency (no per-request API fees)

---

## 2. Base Model Selection

### 2.1 Chosen Base Model: **Llama 3.1 8B Instruct**

**Rationale:**
- **Size:** 8 billion parameters - optimal balance of capability and resource efficiency
- **Performance:** Strong instruction-following capabilities
- **Community Support:** Extensive Ollama integration and tooling
- **Hardware Requirements:** Runs on consumer GPUs (RTX 3090, M1/M2 Macs)
- **License:** Permissive for research use

**Alternative Considered:**
- Mistral 7B (slightly smaller, faster inference)
- Llama 3.1 70B (requires more resources, better reasoning)

**Final Decision:** Llama 3.1 8B provides the best tradeoff for prototype development.

---

## 3. Dataset Preparation

### 3.1 Dataset Format for Fine-Tuning

**Target Format:** JSONL (JSON Lines) with instruction-response pairs

**Example Structure:**
```json
{
  "instruction": "You are in the reconnaissance phase of a red team operation targeting a healthcare facility. You have discovered an open port 3389 (RDP) on IP 10.20.5.45. The hostname resolves to 'RADIOLOGY-WS-03'. What is your next action?",
  "input": "Current context: Hospital network, radiology department subnet, business hours (2:00 PM), medium stealth requirement.",
  "output": "OBSERVE: Port 3389 indicates Windows Remote Desktop. Hostname pattern suggests a radiology workstation. ORIENT: Radiology systems often handle DICOM medical images and may have weaker security than EHR systems. High-value target but potentially monitored. DECIDE: Perform non-intrusive RDP service enumeration to identify Windows version and security configuration. RECOMMEND: Use nmap with -sV flag to fingerprint RDP version, then check for common misconfigurations (NLA disabled, weak encryption). STEALTH: Use slow timing (-T2) to avoid IDS triggers. REASONING: Radiology workstations may provide lateral movement to PACS servers containing protected health information."
}
```

### 3.2 Dataset Categories (MITRE ATT&CK Aligned)

| Category | Examples | Completion Status |
|----------|----------|-------------------|
| Reconnaissance | 25 | ✅ 100% |
| Initial Access | 20 | ✅ 100% |
| Execution | 18 | 🔄 90% |
| Persistence | 15 | 🔄 80% |
| Privilege Escalation | 22 | ✅ 100% |
| Defense Evasion | 20 | 🔄 75% |
| Credential Access | 18 | 🔄 85% |
| Discovery | 25 | ✅ 100% |
| Lateral Movement | 20 | 🔄 70% |
| Collection | 15 | 🔄 60% |
| Command & Control | 12 | 🔄 50% |
| Exfiltration | 10 | 🔄 40% |

**Target Total:** 200-240 examples  
**Current Progress:** ~127-150 examples completed

### 3.3 Data Quality Standards

**Every example must include:**
- ✅ Healthcare-specific context (hospital, clinic, medical device)
- ✅ MITRE ATT&CK technique reference
- ✅ OODA loop structure (Observe → Orient → Decide → Act)
- ✅ Stealth considerations
- ✅ HIPAA-aware reasoning
- ✅ Defensive intelligence output

**Quality Control Process:**
1. AI-assisted generation (using GPT-4 or Claude)
2. Expert curation (manual review by team)
3. MITRE ATT&CK validation (ensure technique accuracy)
4. Healthcare context verification (consult stakeholder feedback)

---

## 4. Fine-Tuning Methodology

### 4.1 Training Platform: **Google Colab Pro**

**Justification:**
- Free GPU access (T4, A100 available)
- Pre-configured Python environment
- Easy integration with Ollama workflow
- Sufficient for 200-example dataset

**Hardware Requirements:**
- GPU: NVIDIA T4 or better (16GB VRAM minimum)
- RAM: 16GB system RAM
- Storage: 50GB for model checkpoints

### 4.2 Fine-Tuning Framework: **Unsloth**

**Why Unsloth?**
- Optimized for Llama models
- 2x faster training than standard methods
- Reduces memory footprint by 40%
- Direct Ollama export support

**Installation:**
```bash
pip install unsloth
pip install bitsandbytes accelerate
```

### 4.3 Training Configuration

**Hyperparameters:**
```python
training_config = {
    "base_model": "unsloth/llama-3.1-8b-instruct",
    "dataset": "training_data.jsonl",
    "num_epochs": 3,
    "learning_rate": 2e-5,
    "batch_size": 4,
    "gradient_accumulation_steps": 4,
    "max_seq_length": 2048,
    "warmup_steps": 50,
    "logging_steps": 10,
    "save_steps": 100,
    "fp16": True,  # Mixed precision training
    "lora_r": 16,  # LoRA rank
    "lora_alpha": 32,
    "lora_dropout": 0.05
}
```

**Training Strategy: LoRA (Low-Rank Adaptation)**
- Fine-tunes only a small subset of model weights
- Reduces training time by 60%
- Maintains base model knowledge
- Smaller final model size (~500MB vs 8GB)

### 4.4 Training Pipeline (Step-by-Step)

**Week 3 Timeline: October 18-24**

#### Day 1-2: Dataset Finalization (Oct 18-19)
```bash
# Validate dataset format
python scripts/validate_dataset.py --input datasets/training_data.jsonl

# Check for duplicates and errors
python scripts/check_quality.py --input datasets/training_data.jsonl

# Split into train/validation (90/10)
python scripts/split_dataset.py --input datasets/training_data.jsonl \
  --train datasets/train.jsonl \
  --val datasets/val.jsonl \
  --split 0.9
```

**Expected Output:** 
- 180 training examples
- 20 validation examples
- Quality report (avg length, category distribution)

#### Day 3: Colab Setup (Oct 20)
```python
# 1. Open Google Colab Pro
# 2. Select GPU runtime (T4 or A100)
# 3. Install dependencies

!pip install unsloth bitsandbytes accelerate
from unsloth import FastLanguageModel
import torch

# 4. Load base model
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="unsloth/llama-3.1-8b-instruct",
    max_seq_length=2048,
    dtype=None,  # Auto-detect
    load_in_4bit=True  # 4-bit quantization for memory efficiency
)

# 5. Configure LoRA
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    bias="none",
    use_gradient_checkpointing=True
)
```

#### Day 4: Training Execution (Oct 21)
```python
from transformers import TrainingArguments, Trainer

# Load dataset
from datasets import load_dataset
dataset = load_dataset("json", data_files={
    "train": "train.jsonl",
    "validation": "val.jsonl"
})

# Training arguments
training_args = TrainingArguments(
    output_dir="./medusa-llama-3.1-8b",
    num_train_epochs=3,
    per_device_train_batch_size=4,
    gradient_accumulation_steps=4,
    learning_rate=2e-5,
    fp16=True,
    logging_steps=10,
    save_steps=100,
    evaluation_strategy="steps",
    eval_steps=50,
    save_total_limit=3,
    load_best_model_at_end=True
)

# Initialize trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=dataset["train"],
    eval_dataset=dataset["validation"],
    tokenizer=tokenizer
)

# Start training
trainer.train()
```

**Expected Training Time:** 2-4 hours (depending on GPU)

**Monitoring Metrics:**
- Training loss (should decrease consistently)
- Validation loss (should track training loss)
- Learning rate schedule
- GPU memory usage

#### Day 5: Model Export (Oct 22)
```python
# Save fine-tuned model in Ollama-compatible format
model.save_pretrained_merged(
    "medusa-healthcare-8b",
    tokenizer,
    save_method="merged_16bit"
)

# Convert to GGUF format for Ollama
!python llama.cpp/convert.py medusa-healthcare-8b \
  --outtype q4_k_m \
  --outfile medusa-healthcare-8b-q4.gguf
```

#### Day 6-7: Ollama Integration (Oct 23-24)
```bash
# 1. Install Ollama locally
curl -fsSL https://ollama.com/install.sh | sh

# 2. Create Modelfile
cat > Modelfile << EOF
FROM ./medusa-healthcare-8b-q4.gguf
TEMPLATE """{{ .System }}

### Instruction:
{{ .Prompt }}

### Response:
"""
PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 4096
EOF

# 3. Import model to Ollama
ollama create medusa-healthcare:latest -f Modelfile

# 4. Test model
ollama run medusa-healthcare:latest "You discover an open SMB share on a medical imaging workstation. What is your next action?"
```

---

## 5. Integration with Existing CLI

### 5.1 Code Changes Required

**Current Implementation (Gemini):**
```python
# src/agents/brain.py
import google.generativeai as genai

class OperationalBrain:
    def __init__(self):
        genai.configure(api_key=os.environ["GEMINI_API_KEY"])
        self.model = genai.GenerativeModel('gemini-pro')
    
    def decide(self, observation):
        response = self.model.generate_content(
            f"Red team scenario: {observation}. What is your next action?"
        )
        return response.text
```

**New Implementation (Ollama):**
```python
# src/agents/brain.py
import requests
import json

class OperationalBrain:
    def __init__(self, model_name="medusa-healthcare:latest"):
        self.model_name = model_name
        self.ollama_url = "http://localhost:11434/api/generate"
    
    def decide(self, observation):
        payload = {
            "model": self.model_name,
            "prompt": f"Red team scenario: {observation}. What is your next action?",
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
                "num_ctx": 4096
            }
        }
        
        response = requests.post(self.ollama_url, json=payload)
        response.raise_for_status()
        
        result = response.json()
        return result["response"]
```

### 5.2 Testing Protocol

**Unit Tests:**
```python
# tests/test_ollama_integration.py
import pytest
from src.agents.brain import OperationalBrain

def test_ollama_connection():
    """Test Ollama service is running"""
    brain = OperationalBrain()
    assert brain.model_name == "medusa-healthcare:latest"

def test_basic_reasoning():
    """Test model produces valid OODA response"""
    brain = OperationalBrain()
    observation = "Discovered open port 22 (SSH) on 192.168.1.100"
    response = brain.decide(observation)
    
    assert "OBSERVE" in response or "observe" in response
    assert len(response) > 50  # Meaningful response
    assert "DECIDE" in response or "decide" in response

def test_healthcare_context():
    """Test model understands healthcare scenarios"""
    brain = OperationalBrain()
    observation = "Found exposed DICOM server on port 11112"
    response = brain.decide(observation)
    
    assert "medical" in response.lower() or "healthcare" in response.lower()
    assert "imaging" in response.lower() or "dicom" in response.lower()
```

### 5.3 Performance Comparison

**Benchmark Tests (Demo 3 Goal):**
| Metric | Gemini (Baseline) | Fine-Tuned Ollama | Target |
|--------|-------------------|-------------------|--------|
| Response Time | ~2-3 seconds | ~1-2 seconds | <2s |
| Healthcare Context Recognition | 60% | 90% | >85% |
| MITRE Technique Accuracy | 70% | 95% | >90% |
| Stealth Awareness | 50% | 85% | >80% |
| Cost per 1000 decisions | $0.50 | $0.00 | $0.00 |

---

## 6. Validation & Evaluation

### 6.1 Evaluation Methodology

**Test Scenarios (15 missions, 5 categories × 3 trials):**
1. **Initial Access** - Phishing + USB attack on hospital reception
2. **Lateral Movement** - Pivot from workstation to EHR database
3. **Credential Access** - Extract cached credentials from medical device
4. **Data Exfiltration** - Steal patient records via DNS tunneling
5. **Persistence** - Maintain access via scheduled task on imaging server

**Metrics Collected:**
- **Time to Objective (TTO):** How fast does Medusa complete the mission?
- **Autonomy Index:** % of actions requiring human approval
- **Stealth Score:** Were any IDS/IPS alerts triggered?
- **Decision Quality:** Expert review of tactical choices (1-5 scale)
- **MITRE Coverage:** How many techniques were correctly identified?

### 6.2 Comparison Framework

**A/B Testing:**
- Run each scenario twice: once with Gemini, once with fine-tuned model
- Measure performance delta
- Identify areas where fine-tuning improved reasoning

**Expected Improvements:**
- 30-40% faster decision-making
- 25% higher stealth scores
- 50% reduction in human intervention needs

---

## 7. Risk Mitigation

### 7.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Fine-tuning fails (loss doesn't converge) | Medium | High | Use pre-validated hyperparameters; start with smaller learning rate |
| Model overfits to training data | Medium | Medium | Use 90/10 train/val split; monitor validation loss |
| Ollama integration breaks CLI | Low | High | Keep Gemini as fallback; extensive testing before Demo 3 |
| Model too large for deployment | Low | Medium | Use 4-bit quantization (reduces size by 75%) |
| Training exceeds Colab free tier | Medium | Low | Use Colab Pro ($10/month) or run locally |

### 7.2 Contingency Plans

**If fine-tuning fails:**
- Option A: Use Ollama with base Llama 3.1 8B (no fine-tuning)
- Option B: Continue with Gemini but improve prompting
- Option C: Use smaller dataset (100 examples) for faster iteration

**If Ollama deployment issues:**
- Keep Gemini API as backup in CLI
- Implement automatic fallback logic
- Demo with Ollama, but have Gemini ready

---

## 8. Timeline & Milestones

### Week 3: Fine-Tuning (Oct 18-24)
- **Oct 18-19:** Complete dataset (200 examples) ✅
- **Oct 20:** Set up Colab, load base model ✅
- **Oct 21:** Execute training (2-4 hours) ✅
- **Oct 22:** Export model to GGUF format ✅
- **Oct 23:** Import to Ollama, test locally ✅
- **Oct 24:** **MID-QUARTER ANALYSIS** - Report fine-tuning results

### Week 4: Integration (Oct 25-Nov 3)
- **Oct 25-27:** Replace Gemini with Ollama in CLI
- **Oct 28-30:** Fix bugs, optimize prompts
- **Oct 31-Nov 3:** End-to-end testing (15 test missions)

### Week 5: Demo 3 Prep (Nov 4-7)
- **Nov 4-5:** Collect metrics, generate comparison charts
- **Nov 6:** Prepare Demo 3 presentation
- **Nov 7:** **DEMO 3** - First fully autonomous mission with fine-tuned model

---

## 9. Success Criteria

**Fine-tuning is successful if:**
- ✅ Model achieves <5% validation loss
- ✅ Generates coherent OODA loop responses
- ✅ Recognizes healthcare context in >85% of test cases
- ✅ Integrates with CLI without breaking existing functionality
- ✅ Inference speed <2 seconds per decision

**Demo 3 is successful if:**
- ✅ Complete one full autonomous mission (initial access → exfiltration)
- ✅ 30+ chained OODA iterations without human intervention
- ✅ Outperforms Gemini baseline in at least 3/5 metrics
- ✅ Generates actionable defensive intelligence report

---

## 10. References & Resources

**Key Documentation:**
- Ollama Documentation: https://github.com/ollama/ollama
- Unsloth Fine-Tuning Guide: https://github.com/unslothai/unsloth
- Llama 3.1 Model Card: https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct
- MITRE ATT&CK: https://attack.mitre.org/

**Training Tutorials:**
- "Fine-tuning Llama 3 with Unsloth" (YouTube)
- "Ollama Custom Models Guide" (Official Docs)
- "LoRA Explained" (Hugging Face Blog)

---

## Appendix A: Hardware Requirements

**Minimum Specs (Training):**
- GPU: NVIDIA T4 (16GB VRAM) or M1 Mac (16GB unified memory)
- CPU: 4+ cores
- RAM: 16GB
- Storage: 50GB free

**Recommended Specs (Training):**
- GPU: NVIDIA A100 (40GB VRAM)
- CPU: 8+ cores
- RAM: 32GB
- Storage: 100GB NVMe SSD

**Deployment Specs (Ollama):**
- GPU: Optional (CPU inference works, slower)
- RAM: 8GB minimum (model loaded in memory)
- Storage: 10GB (model + dependencies)

---

## Appendix B: Cost Analysis

**Training Costs:**
- Google Colab Pro: $10/month (includes A100 access)
- Alternative (AWS g4dn.xlarge): ~$0.50/hour × 4 hours = $2.00

**Deployment Costs:**
- Ollama: $0 (open source, local inference)
- Gemini API (current): $0.50 per 1000 requests

**Estimated Savings:**
- 1000 OODA decisions per test mission
- 15 test missions = 15,000 decisions
- Gemini cost: $7.50
- Ollama cost: $0.00
- **Savings: $7.50 per testing cycle**

---

**Document Version:** 1.0  
**Last Updated:** October 16, 2025  
**Next Review:** October 24, 2025 (Post-Training)