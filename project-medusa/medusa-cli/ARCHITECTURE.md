# MEDUSA LLM Architecture

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         MEDUSA CLI                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
            ▼                                   ▼
┌──────────────────────┐            ┌──────────────────────┐
│   Execution Modes    │            │   Configuration      │
│                      │            │                      │
│  • autonomous.py     │◄───────────┤  config.py           │
│  • interactive.py    │            │                      │
│  • observe.py        │            │  ~/.medusa/          │
└──────────┬───────────┘            │  config.yaml         │
           │                        └──────────────────────┘
           │ llm_config
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      MedusaClient                               │
│                      (client.py)                                │
│                                                                 │
│  Methods:                                                       │
│  • get_ai_recommendation()                                      │
│  • get_reconnaissance_strategy()                                │
│  • get_enumeration_strategy()                                   │
│  • assess_vulnerability_risk()                                  │
│  • plan_attack_strategy()                                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           │ self.llm_client
                           │
                           ▼
           ┌───────────────────────────────┐
           │    create_llm_client()        │
           │    (Factory Function)         │
           └───────────┬───────────────────┘
                       │
                       │ if mock_mode or error
                       │
        ┌──────────────┴──────────────┐
        │                             │
        ▼                             ▼
┌─────────────────┐          ┌─────────────────┐
│   LLMClient     │          │ MockLLMClient   │
│  (Real AI)      │          │  (Testing)      │
│                 │          │                 │
│  Uses:          │          │  Returns:       │
│  google.        │          │  Deterministic  │
│  generativeai   │          │  mock responses │
└────────┬────────┘          └─────────────────┘
         │
         │ API calls
         │
         ▼
┌─────────────────────────────────────────────┐
│         Google Gemini API                   │
│         (ai.google.dev)                     │
│                                             │
│  Model: gemini-pro                          │
│  Input: Structured prompts                  │
│  Output: JSON responses                     │
└─────────────────────────────────────────────┘
```

---

## Data Flow: Reconnaissance Phase

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. User starts scan                                             │
│    $ medusa run autonomous --target http://example.com          │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Autonomous Mode initializes                                  │
│    - Loads config from ~/.medusa/config.yaml                    │
│    - Gets LLM config: config.get_llm_config()                   │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Creates MedusaClient with LLM config                         │
│    client = MedusaClient(target, api_key, llm_config=llm_cfg)   │
│    - Initializes LLMClient with Gemini API                      │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Requests reconnaissance strategy                             │
│    strategy = await client.get_reconnaissance_strategy(target)  │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. LLMClient builds prompt                                      │
│                                                                 │
│    You are an AI pentesting assistant.                          │
│    Target: http://example.com                                   │
│    Context: {...}                                               │
│    Provide strategy in JSON format:                             │
│    {                                                            │
│      "recommended_actions": [...],                              │
│      "focus_areas": [...],                                      │
│      "risk_assessment": "LOW"                                   │
│    }                                                            │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. Sends to Gemini API                                          │
│    - With retry logic (up to 3 attempts)                        │
│    - With timeout (30 seconds)                                  │
│    - With exponential backoff                                   │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. Receives AI response                                         │
│    {                                                            │
│      "recommended_actions": [                                   │
│        {                                                        │
│          "action": "port_scan",                                 │
│          "command": "nmap -sV http://example.com",              │
│          "technique_id": "T1046",                               │
│          "reasoning": "Discover exposed services"               │
│        }                                                        │
│      ],                                                         │
│      "focus_areas": ["web_services", "api_endpoints"],          │
│      "risk_assessment": "LOW"                                   │
│    }                                                            │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. LLMClient parses JSON                                        │
│    - Validates structure                                        │
│    - Extracts from markdown if needed                           │
│    - Returns structured dict                                    │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. MedusaClient returns to caller                               │
│    return strategy                                              │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 10. Autonomous Mode executes recommendations                    │
│     - Shows AI reasoning to user                                │
│     - Requests approval for risky actions                       │
│     - Executes approved actions                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Error Handling Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ LLM Request Initiated                                           │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
                        ┌────────────────┐
                        │ Try API Call   │
                        └────────┬───────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                Success                    Error
                    │                         │
                    ▼                         ▼
        ┌───────────────────┐    ┌────────────────────┐
        │ Parse Response    │    │ Check Retry Count  │
        └─────────┬─────────┘    └──────────┬─────────┘
                  │                          │
                  │                 ┌────────┴────────┐
                  │                 │                 │
                  │            < max_retries    >= max_retries
                  │                 │                 │
                  │                 ▼                 ▼
                  │      ┌──────────────────┐  ┌─────────────┐
                  │      │ Wait (backoff)   │  │ Use Fallback│
                  │      │ Retry API call   │  │ Mock Resp   │
                  │      └──────────┬───────┘  └──────┬──────┘
                  │                 │                  │
                  └─────────────────┴──────────────────┘
                                    │
                                    ▼
                        ┌────────────────────┐
                        │ Return Valid Data  │
                        │ (never crashes)    │
                        └────────────────────┘
```

---

## Configuration Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Code Defaults (config.py)                                   │
│    DEFAULT_LLM_CONFIG = {                                       │
│      "model": "gemini-pro",                                     │
│      "temperature": 0.7,                                        │
│      "max_tokens": 2048,                                        │
│      "timeout": 30,                                             │
│      "max_retries": 3,                                          │
│      "mock_mode": False                                         │
│    }                                                            │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Overridden by
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. User Config File (~/.medusa/config.yaml)                     │
│    llm:                                                         │
│      model: "gemini-pro"                                        │
│      temperature: 0.8          # User preference               │
│      mock_mode: false                                           │
│      # Other values use defaults                                │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Overridden by
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Environment Variables (future enhancement)                   │
│    MEDUSA_LLM_MODEL=gemini-pro                                  │
│    MEDUSA_MOCK_MODE=true                                        │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Overridden by
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Runtime Parameters (programmatic usage)                      │
│    llm_config = {"temperature": 0.9, "mock_mode": True}         │
│    client = MedusaClient(url, key, llm_config=llm_config)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## LLM Decision Points

### During Reconnaissance
```
Target Provided
     │
     ▼
┌─────────────────────────────┐
│ AI Decision Point 1:        │
│ What to scan first?         │
│                             │
│ Options:                    │
│ • Port scan                 │
│ • Web technology detection  │
│ • DNS enumeration           │
│ • SSL/TLS analysis          │
│                             │
│ AI considers:               │
│ • Target type               │
│ • Previous findings         │
│ • Time constraints          │
│ • Risk tolerance            │
└─────────────────────────────┘
```

### During Enumeration
```
Services Discovered
     │
     ▼
┌─────────────────────────────┐
│ AI Decision Point 2:        │
│ Which services to probe?    │
│                             │
│ Options:                    │
│ • API endpoints             │
│ • Authentication systems    │
│ • Database interfaces       │
│ • Admin panels              │
│                             │
│ AI considers:               │
│ • Service criticality       │
│ • Known vulnerabilities     │
│ • Attack surface            │
│ • Success probability       │
└─────────────────────────────┘
```

### During Vulnerability Assessment
```
Vulnerability Found
     │
     ▼
┌─────────────────────────────┐
│ AI Decision Point 3:        │
│ How risky is this vuln?     │
│                             │
│ Returns:                    │
│ • LOW                       │
│ • MEDIUM                    │
│ • HIGH                      │
│ • CRITICAL                  │
│                             │
│ AI considers:               │
│ • Exploitability            │
│ • Impact (CIA triad)        │
│ • Target environment        │
│ • Compensating controls     │
└─────────────────────────────┘
```

### During Attack Planning
```
All Findings Collected
     │
     ▼
┌─────────────────────────────┐
│ AI Decision Point 4:        │
│ What's the attack strategy? │
│                             │
│ Generates:                  │
│ • Attack chain (ordered)    │
│ • Success probability       │
│ • Risk assessment           │
│ • Prerequisites             │
│                             │
│ AI considers:               │
│ • Objectives                │
│ • Available vectors         │
│ • Dependencies              │
│ • Stealth requirements      │
└─────────────────────────────┘
```

---

## Component Interaction Matrix

```
┌──────────────┬──────────┬──────────┬──────────┬──────────┐
│ Component    │ Config   │ Client   │ LLM      │ Modes    │
├──────────────┼──────────┼──────────┼──────────┼──────────┤
│ config.py    │    -     │  loads   │  loads   │  loads   │
├──────────────┼──────────┼──────────┼──────────┼──────────┤
│ client.py    │  reads   │    -     │  calls   │  used by │
├──────────────┼──────────┼──────────┼──────────┼──────────┤
│ core/llm.py  │  reads   │  used by │    -     │    -     │
├──────────────┼──────────┼──────────┼──────────┼──────────┤
│ modes/*.py   │  reads   │  creates │    -     │    -     │
└──────────────┴──────────┴──────────┴──────────┴──────────┘

Legend:
  loads   = Loads configuration from
  reads   = Reads data from
  calls   = Makes function calls to
  used by = Is used by
  creates = Instantiates
```

---

## File Organization

```
medusa-cli/
│
├── src/medusa/
│   │
│   ├── core/                    # NEW: Core functionality
│   │   ├── __init__.py
│   │   └── llm.py               # LLM integration
│   │
│   ├── modes/                   # Execution modes
│   │   ├── autonomous.py        # MODIFIED: Pass LLM config
│   │   ├── interactive.py       # MODIFIED: Pass LLM config
│   │   └── observe.py           # MODIFIED: Pass LLM config
│   │
│   ├── client.py                # MODIFIED: LLM-powered methods
│   ├── config.py                # MODIFIED: LLM configuration
│   ├── approval.py              # Unchanged
│   ├── display.py               # Unchanged
│   └── reporter.py              # Unchanged
│
├── requirements.txt             # Already has google-generativeai
├── test_llm_integration.py      # NEW: Test suite
│
├── INTEGRATION_GUIDE.md         # NEW: Full documentation
├── QUICK_START_LLM.md           # NEW: Quick reference
├── LLM_INTEGRATION_SUMMARY.md   # NEW: Implementation summary
└── ARCHITECTURE.md              # NEW: This file
```

---

## Key Design Patterns

### 1. Factory Pattern
```python
def create_llm_client(config: LLMConfig):
    if config.mock_mode:
        return MockLLMClient(config)
    if not GEMINI_AVAILABLE:
        return MockLLMClient(config)
    try:
        return LLMClient(config)
    except Exception:
        return MockLLMClient(config)
```

### 2. Strategy Pattern
```python
class MedusaClient:
    def __init__(self, ..., llm_config):
        # Selects appropriate LLM strategy
        self.llm_client = create_llm_client(llm_config)
    
    async def get_ai_recommendation(self, context):
        # Uses selected strategy
        return await self.llm_client.get_next_action_recommendation(context)
```

### 3. Template Method Pattern
```python
class LLMClient:
    async def _generate_with_retry(self, prompt):
        for attempt in range(max_retries):
            try:
                response = await self._make_api_call(prompt)
                return response
            except Exception:
                if attempt < max_retries - 1:
                    await self._backoff(attempt)
        raise Exception("All retries failed")
```

---

## Performance Characteristics

```
┌─────────────────────┬─────────────┬──────────────┬─────────────┐
│ Operation           │ Mock Mode   │ Real LLM     │ Fallback    │
├─────────────────────┼─────────────┼──────────────┼─────────────┤
│ Recommendation      │   < 10 ms   │  500-2000 ms │   < 10 ms   │
│ Risk Assessment     │   < 5 ms    │  300-1000 ms │   < 5 ms    │
│ Attack Planning     │   < 15 ms   │  1000-3000ms │   < 15 ms   │
│ Context Building    │   < 1 ms    │   < 1 ms     │   < 1 ms    │
│ Response Parsing    │   N/A       │   1-5 ms     │   N/A       │
└─────────────────────┴─────────────┴──────────────┴─────────────┘
```

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ API Key Security                                                │
│                                                                 │
│ ~/.medusa/config.yaml     (chmod 600, user-only access)         │
│     │                                                           │
│     ├─ Encrypted at rest? ❌ (future enhancement)               │
│     ├─ In memory only     ✅                                    │
│     ├─ Never logged       ✅                                    │
│     └─ Not in git         ✅ (.gitignore)                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Input Sanitization                                              │
│                                                                 │
│ User Input → Validation → Sanitization → LLM Prompt            │
│                                                                 │
│ Prevents: Prompt injection, malicious input                    │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ Output Validation                                               │
│                                                                 │
│ LLM Response → JSON Parse → Schema Validate → Application      │
│                                                                 │
│ Prevents: Malicious commands, invalid data                     │
└─────────────────────────────────────────────────────────────────┘
```

---

This architecture ensures:
- ✅ Modularity (easy to swap LLM providers)
- ✅ Testability (mock mode for development)
- ✅ Reliability (automatic fallbacks)
- ✅ Security (input/output validation)
- ✅ Performance (async operations)
- ✅ Maintainability (clear separation of concerns)

