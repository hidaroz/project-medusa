# MEDUSA LLM Quick Start Guide

## 🚀 Get Started in 3 Minutes

### Step 1: Get Your API Key (1 minute)

1. Visit: https://ai.google.dev/gemini-api/docs/quickstart
2. Click "Get API Key"
3. Copy your API key

### Step 2: Configure MEDUSA (1 minute)

```bash
cd medusa-cli

# Option A: Run setup wizard
medusa setup

# Option B: Manual config
cat > ~/.medusa/config.yaml << EOF
api_key: "YOUR_GEMINI_API_KEY_HERE"

llm:
  model: "gemini-pro"
  temperature: 0.7
  max_tokens: 2048
  timeout: 30
  max_retries: 3
  mock_mode: false
EOF
```

### Step 3: Run with AI (30 seconds)

```bash
# Install dependencies (first time only)
python3 -m pip install -r requirements.txt

# Run with real AI
medusa run autonomous --target http://localhost:3001
```

---

## 🎯 What You Get

### Before (Mock AI)
```
❌ Hardcoded responses
❌ No context awareness
❌ Limited to predefined actions
```

### After (Real AI)
```
✅ Dynamic AI reasoning
✅ Context-aware decisions
✅ Adapts to your target
✅ Explains recommendations
```

---

## 💻 Code Examples

### Example 1: Basic Usage

```python
from medusa.client import MedusaClient
import asyncio

async def pentest():
    llm_config = {
        "api_key": "your_key_here",
        "model": "gemini-pro",
        "mock_mode": False
    }
    
    async with MedusaClient(
        "http://target.com",
        "api_key",
        llm_config=llm_config
    ) as client:
        # AI decides what to do
        recommendation = await client.get_ai_recommendation({
            "phase": "reconnaissance",
            "target": "http://target.com"
        })
        
        print(recommendation)

asyncio.run(pentest())
```

### Example 2: Risk Assessment

```python
# Assess vulnerability with AI
vulnerability = {
    "type": "SQL Injection",
    "severity": "high",
    "location": "/api/search"
}

risk = await client.assess_vulnerability_risk(vulnerability)
print(f"AI-assessed risk: {risk}")  # Output: HIGH
```

### Example 3: Attack Planning

```python
# Get AI to plan attack strategy
findings = [
    {"type": "open_port", "port": 80},
    {"type": "api_endpoint", "path": "/api/users"}
]

plan = await client.plan_attack_strategy(
    "http://target.com",
    findings,
    objectives=["data_access"]
)

print(f"Strategy: {plan['strategy_overview']}")
print(f"Steps: {len(plan['attack_chain'])}")
```

---

## 🧪 Testing Without API Key

```bash
# Set mock mode in config
cat > ~/.medusa/config.yaml << EOF
llm:
  mock_mode: true
EOF

# Or run test suite
python3 test_llm_integration.py
```

---

## 🔧 Configuration Options

```yaml
llm:
  # Model selection
  model: "gemini-pro"           # Default: gemini-pro
  
  # AI creativity (0.0-1.0)
  temperature: 0.7              # Default: 0.7 (balanced)
                                # Lower = more deterministic
                                # Higher = more creative
  
  # Response length
  max_tokens: 2048              # Default: 2048
  
  # Network settings
  timeout: 30                   # Seconds to wait for response
  max_retries: 3                # Retry attempts on failure
  
  # Development mode
  mock_mode: false              # true = no API calls
```

---

## 🐛 Troubleshooting

### Problem: "google-generativeai not installed"
```bash
python3 -m pip install google-generativeai
```

### Problem: "Invalid API key"
1. Check your API key at https://ai.google.dev/
2. Verify it's in `~/.medusa/config.yaml`
3. Try mock mode: `llm.mock_mode: true`

### Problem: "Request timeout"
```yaml
llm:
  timeout: 60  # Increase to 60 seconds
```

### Problem: Rate limit exceeded
The client automatically retries with backoff. Just wait a moment.

---

## 📊 What Changed

### Files Modified
- ✅ `medusa/client.py` - Now uses real LLM
- ✅ `medusa/config.py` - Added LLM config
- ✅ All modes - Pass LLM config to client

### Files Added
- ✅ `medusa/core/llm.py` - LLM integration (700+ lines)
- ✅ `test_llm_integration.py` - Test suite
- ✅ `INTEGRATION_GUIDE.md` - Full documentation

### Backward Compatibility
- ✅ No breaking changes
- ✅ Works without config (uses mock mode)
- ✅ Existing code continues to work

---

## 🎓 Learn More

- **Full Guide**: `INTEGRATION_GUIDE.md`
- **Summary**: `LLM_INTEGRATION_SUMMARY.md`
- **Tests**: `python3 test_llm_integration.py`
- **Code**: `medusa/core/llm.py`

---

## ✨ Key Benefits

1. **Real AI Decisions** - No more hardcoded responses
2. **Context-Aware** - AI understands your target
3. **Adaptive** - Changes strategy based on findings
4. **Explained** - AI tells you why it recommends actions
5. **Robust** - Automatic retries and fallbacks
6. **Safe** - Always returns valid data

---

## 🚨 Important Notes

1. **API Key Security**: Keep your API key private
2. **Rate Limits**: Gemini has rate limits (handled automatically)
3. **Mock Mode**: Perfect for testing without API calls
4. **Fallback**: If LLM fails, uses safe defaults
5. **Logging**: Check logs for detailed AI decision info

---

## 📝 Quick Reference

### Check if LLM is Working
```python
from medusa.client import MedusaClient

async with MedusaClient(url, key, llm_config=config) as client:
    if isinstance(client.llm_client, MockLLMClient):
        print("Using mock mode")
    else:
        print("Using real AI")
```

### Switch to Mock Mode
```python
llm_config = {"mock_mode": True}
```

### Increase Verbosity
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

**Ready to go? Just run:**

```bash
medusa run autonomous --target http://localhost:3001
```

🎉 **Enjoy AI-powered pentesting!**

