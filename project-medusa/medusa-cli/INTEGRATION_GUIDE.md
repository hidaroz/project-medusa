# MEDUSA LLM Integration Guide

## Overview

MEDUSA now includes real AI-powered decision-making using Google's Gemini API. All AI responses have been upgraded from hardcoded mock data to dynamic, context-aware recommendations.

## Architecture

```
medusa-cli/
├── src/medusa/
│   ├── core/
│   │   ├── __init__.py
│   │   └── llm.py          # ← NEW: LLM integration module
│   ├── client.py            # ← UPDATED: Now uses LLM
│   ├── config.py            # ← UPDATED: LLM configuration
│   └── modes/               # ← UPDATED: Pass LLM config
```

## Key Components

### 1. LLM Module (`core/llm.py`)

**Classes:**
- `LLMClient` - Real Gemini API integration
- `MockLLMClient` - Testing/development without API calls
- `LLMConfig` - Configuration dataclass

**Methods:**
```python
# Reconnaissance recommendations
await llm_client.get_reconnaissance_recommendation(target, context)

# Enumeration strategy
await llm_client.get_enumeration_recommendation(target, findings)

# Risk assessment
await llm_client.assess_vulnerability_risk(vulnerability, context)

# Attack planning
await llm_client.plan_attack_strategy(target, findings, objectives)

# Next action recommendation
await llm_client.get_next_action_recommendation(context)
```

### 2. Client Integration (`client.py`)

The `MedusaClient` now accepts an optional `llm_config` parameter:

```python
from medusa.client import MedusaClient
from medusa.config import get_config

config = get_config()
llm_config = config.get_llm_config()

async with MedusaClient(target_url, api_key, llm_config=llm_config) as client:
    # All AI methods now use real LLM
    recommendations = await client.get_ai_recommendation(context)
    strategy = await client.get_reconnaissance_strategy(target)
    risk = await client.assess_vulnerability_risk(vuln)
```

### 3. Configuration (`config.py`)

LLM settings are stored in `~/.medusa/config.yaml`:

```yaml
api_key: "YOUR_GEMINI_API_KEY"

llm:
  model: "gemini-pro"
  temperature: 0.7
  max_tokens: 2048
  timeout: 30
  max_retries: 3
  mock_mode: false  # Set to true for testing
```

## Setup Instructions

### 1. Get Gemini API Key

1. Visit [Google AI Studio](https://ai.google.dev/gemini-api/docs/quickstart)
2. Click "Get API Key"
3. Copy your API key

### 2. Configure MEDUSA

Run the setup wizard:
```bash
cd medusa-cli
medusa setup
```

Enter your Gemini API key when prompted.

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This includes:
- `google-generativeai==0.3.2` - Gemini API client
- `httpx` - Async HTTP
- `rich` - Terminal UI
- `pyyaml` - Configuration

### 4. Verify Installation

Run the test suite:
```bash
python test_llm_integration.py
```

## Usage Examples

### Example 1: Autonomous Mode with Real AI

```bash
medusa run autonomous --target http://localhost:3001
```

The agent will now use real AI to:
- Decide what to scan during reconnaissance
- Determine which services to enumerate
- Assess vulnerability risk levels
- Plan attack strategies

### Example 2: Mock Mode (No API Calls)

Edit `~/.medusa/config.yaml`:
```yaml
llm:
  mock_mode: true
```

Or set environment variable:
```bash
export MEDUSA_MOCK_LLM=true
medusa run autonomous --target http://localhost:3001
```

### Example 3: Custom LLM Settings

```python
from medusa.core.llm import LLMConfig, LLMClient

config = LLMConfig(
    api_key="your_key",
    model="gemini-pro",
    temperature=0.9,  # More creative
    max_tokens=4096,
    timeout=60,
    max_retries=5
)

client = LLMClient(config)
result = await client.plan_attack_strategy(target, findings, objectives)
```

### Example 4: Programmatic Integration

```python
import asyncio
from medusa.client import MedusaClient

async def pentest_with_ai():
    llm_config = {
        "api_key": "your_gemini_key",
        "model": "gemini-pro",
        "temperature": 0.7,
        "mock_mode": False
    }
    
    async with MedusaClient(
        "http://target.com", 
        "medusa_api_key",
        llm_config=llm_config
    ) as client:
        # Get AI reconnaissance strategy
        strategy = await client.get_reconnaissance_strategy(
            "http://target.com",
            {"environment": "production web app"}
        )
        
        print(f"AI recommends {len(strategy['recommended_actions'])} actions")
        
        # Assess vulnerability risk with AI
        vuln = {
            "type": "SQL Injection",
            "severity": "high",
            "location": "/api/search?q="
        }
        risk = await client.assess_vulnerability_risk(vuln)
        print(f"AI-assessed risk: {risk}")

asyncio.run(pentest_with_ai())
```

## Prompt Engineering

The LLM integration uses carefully crafted prompts for each phase:

### Reconnaissance Prompt
```
You are an AI penetration testing assistant. 
Analyze the target and recommend reconnaissance actions.

Target: <url>
Context: <environment details>

Provide strategy in JSON format with:
- recommended_actions (commands, techniques)
- focus_areas
- risk_assessment
- estimated_duration
```

### Risk Assessment Prompt
```
You are a cybersecurity risk assessment expert.
Evaluate this vulnerability considering:
- Exploitability
- Impact (CIA triad)
- Target environment
- Compensating controls

Respond with ONE word: LOW, MEDIUM, HIGH, or CRITICAL
```

### Attack Planning Prompt
```
You are an expert penetration tester.
Create an attack strategy based on findings.

Objectives: <goals>
Findings: <vulnerabilities>

Create attack plan with:
- strategy_overview
- attack_chain (ordered steps)
- success_probability
- risks
```

## Error Handling

The integration includes comprehensive error handling:

1. **API Rate Limits**: Exponential backoff with retries
2. **Network Failures**: Automatic retry with timeout
3. **Invalid Responses**: JSON parsing with fallbacks
4. **Missing API Key**: Graceful degradation to mock mode

Example error handling:
```python
try:
    result = await client.get_ai_recommendation(context)
except Exception as e:
    logger.error(f"LLM failed: {e}")
    # Falls back to safe mock response automatically
```

## Testing

### Run Test Suite
```bash
# Test mock mode (no API key needed)
python test_llm_integration.py

# Test with real API
export GEMINI_API_KEY="your_key"
python test_llm_integration.py
```

### Test Individual Components
```python
import asyncio
from medusa.core.llm import MockLLMClient, LLMConfig

async def test():
    client = MockLLMClient()
    
    # Test reconnaissance
    result = await client.get_reconnaissance_recommendation(
        "http://test.com", 
        {}
    )
    print(result)

asyncio.run(test())
```

## Migration from Mock Responses

### Before (Mock)
```python
async def get_ai_recommendation(self, context):
    # Hardcoded mock responses
    recommendations = [
        {"action": "exploit_sql", "confidence": 0.85},
        {"action": "enumerate_db", "confidence": 0.92}
    ]
    return {"recommendations": random.sample(recommendations, k=2)}
```

### After (Real AI)
```python
async def get_ai_recommendation(self, context):
    # Dynamic AI-powered recommendations
    try:
        result = await self.llm_client.get_next_action_recommendation(context)
        return result
    except Exception as e:
        logger.error(f"LLM failed: {e}")
        return fallback_response()
```

## Backward Compatibility

The integration maintains full backward compatibility:

1. **No LLM config**: Falls back to MockLLMClient
2. **Invalid API key**: Automatically uses mock mode
3. **API unavailable**: Returns safe default responses
4. **Existing code**: Works without modification

## Performance

- **Mock mode**: <10ms response time
- **Real LLM**: 500ms - 2s per request
- **Caching**: Not yet implemented (future optimization)
- **Rate limits**: Handles Gemini API limits gracefully

## Security Considerations

1. **API Key Storage**: Stored in `~/.medusa/config.yaml` (user-only permissions)
2. **Prompt Injection**: Input sanitization before LLM queries
3. **Output Validation**: All LLM responses validated before use
4. **Fallback Safety**: Safe defaults if LLM produces invalid output

## Troubleshooting

### Issue: "google-generativeai not installed"
```bash
pip install google-generativeai
```

### Issue: "Invalid API key"
1. Check `~/.medusa/config.yaml` has correct key
2. Verify key at [Google AI Studio](https://ai.google.dev/)
3. Enable mock mode temporarily: `llm.mock_mode: true`

### Issue: "Request timeout"
Increase timeout in config:
```yaml
llm:
  timeout: 60  # seconds
```

### Issue: "Rate limit exceeded"
The client automatically retries with exponential backoff.
Or increase retry settings:
```yaml
llm:
  max_retries: 5
```

## Future Enhancements

Planned improvements:
- [ ] Response caching for repeated queries
- [ ] Support for Claude, GPT-4, and other models
- [ ] Fine-tuned models for pentesting
- [ ] Streaming responses for long-running tasks
- [ ] Context window management for large operations
- [ ] LLM observability and logging dashboard

## API Reference

See inline documentation in `medusa/core/llm.py` for complete API reference.

## Support

- **Documentation**: `medusa-cli/docs/`
- **Issues**: GitHub Issues
- **Discord**: [MEDUSA Community]

## License

MIT License - See LICENSE file

