# MEDUSA LLM Provider Quick Reference

## TL;DR

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull mistral:7b-instruct

# Start server
ollama serve &

# Run MEDUSA (will auto-detect local model)
medusa autonomous target.com
```

## Environment Variables

### Quick Setup
```bash
# Auto-detect best available (recommended)
export LLM_PROVIDER=auto

# Or explicitly use local
export LLM_PROVIDER=local
export OLLAMA_URL=http://localhost:11434
export LOCAL_MODEL=mistral:7b-instruct
```

### Cloud Setup
```bash
# OpenAI
export LLM_PROVIDER=openai
export CLOUD_API_KEY="sk-..."
export CLOUD_MODEL="gpt-4-turbo-preview"

# Anthropic
export LLM_PROVIDER=anthropic
export CLOUD_API_KEY="sk-ant-..."
export CLOUD_MODEL="claude-3-sonnet-20240229"
```

### Optional Parameters
```bash
LLM_TEMPERATURE=0.7          # 0=focused, 1=creative
LLM_MAX_TOKENS=2048          # Max response length
LLM_TIMEOUT=60               # Request timeout (seconds)
```

## Python Usage

### Auto-Detect (Recommended)
```python
from medusa.core.llm import create_llm_client, LLMConfig

config = LLMConfig(provider="auto")
client = create_llm_client(config)
response = await client.generate("Your prompt")
```

### Local Model
```python
from medusa.core.llm import create_llm_client, LLMConfig

config = LLMConfig(
    provider="local",
    local_model="mistral:7b-instruct"
)
client = create_llm_client(config)
response = await client.generate("Your prompt")
print(response.content)
print(f"Tokens: {response.tokens_used}")
```

### Cloud Provider
```python
from medusa.core.llm import create_llm_client, LLMConfig

config = LLMConfig(
    provider="openai",
    cloud_api_key="sk-...",
    cloud_model="gpt-4-turbo-preview"
)
client = create_llm_client(config)
response = await client.generate("Your prompt")
```

### Testing
```python
from medusa.core.llm import create_llm_client, LLMConfig

config = LLMConfig(provider="mock")
client = create_llm_client(config)
response = await client.generate("Test")  # Returns mock response
```

## Provider Comparison

| Aspect | Local (Ollama) | OpenAI | Anthropic | Mock |
|--------|---|---|---|---|
| Speed | 2-5s | 1-3s | 1-4s | <100ms |
| Cost/month | $0 | $500+ | $50+ | $0 |
| Setup | 5 min | 1 min | 1 min | Auto |
| Privacy | 100% | No | No | Yes |
| Offline | ✅ | ❌ | ❌ | ✅ |
| Rate limits | None | Yes | Yes | No |
| Quality | 9/10 | 10/10 | 9/10 | Mock |
| Default? | ✅ | Optional | Optional | Fallback |

## Troubleshooting

### "Cannot connect to Ollama"
```bash
# Is Ollama running?
curl http://localhost:11434/api/version

# If not, start it:
ollama serve
```

### "Model not found"
```bash
# List models:
ollama list

# Pull the model:
ollama pull mistral:7b-instruct
```

### Switch Providers
```bash
# Change environment variable
export LLM_PROVIDER=openai

# Or create new config
config = LLMConfig(provider="openai", cloud_api_key="...")
```

### Performance Issues
```bash
# Use quantized model (smaller, faster):
ollama pull mistral:7b-instruct-q5_K_M
export LOCAL_MODEL=mistral:7b-instruct-q5_K_M

# Or use faster cloud model:
export LLM_PROVIDER=openai
export CLOUD_MODEL=gpt-3.5-turbo
```

## Legacy Interface (Still Works)

```python
# Old code still works!
from medusa.core.llm import LocalLLMClient, MockLLMClient

client = LocalLLMClient(config)
result = await client.get_reconnaissance_recommendation(target, context)
```

## Alternative Models

### Local (via Ollama)
```bash
# Fast & efficient
ollama pull neural-chat:7b-v3-q5_K_M

# Good quality
ollama pull mistral:7b

# More powerful
ollama pull mixtral:8x7b-instruct-v0.1
```

### OpenAI
```bash
# Best quality
gpt-4-turbo-preview

# Cheaper, fast
gpt-3.5-turbo

# Vision capable
gpt-4-vision-preview
```

### Anthropic
```bash
# Best value
claude-3-sonnet-20240229

# Cheaper
claude-3-haiku-20240307

# Most powerful
claude-3-opus-20240229
```

## Cost Calculator

**Assuming:**
- 1000 requests/day
- 500 tokens per request
- 1 month (30 days)

### Local Ollama
- **Cost/month**: $0
- **Annual**: $0
- Plus 1-time hardware (~$500-2000)

### OpenAI (GPT-4)
- **Tokens/month**: 15M
- **Input cost**: $0.03/1K tokens = $450
- **Output cost**: $0.06/1K tokens = $900
- **Total/month**: ~$1,350
- **Annual**: ~$16,200

### OpenAI (GPT-3.5)
- **Tokens/month**: 15M
- **Cost/month**: ~$7.50
- **Annual**: ~$90

### Anthropic Claude
- **Tokens/month**: 15M
- **Cost/month**: ~$45
- **Annual**: ~$540

## Health Check

```python
from medusa.core.llm import create_llm_client, LLMConfig

config = LLMConfig(provider="auto")
client = create_llm_client(config)

# Check if provider is ready
health = await client.health_check()
print(f"Status: {health['healthy']}")
print(f"Provider: {health['provider']}")
```

## Configuration File

Optional: Create `~/.medusa/.env`
```bash
# LLM Settings
LLM_PROVIDER=local
OLLAMA_URL=http://localhost:11434
LOCAL_MODEL=mistral:7b-instruct

# Optional cloud config
# CLOUD_API_KEY=sk-...
# CLOUD_MODEL=gpt-4-turbo-preview

# Generation settings
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=2048
LLM_TIMEOUT=60
```

## Common Commands

```bash
# Check provider is available
medusa health

# View current configuration
medusa config

# Run with specific provider
LLM_PROVIDER=local medusa observe target.com
LLM_PROVIDER=mock medusa observe target.com

# Run tests
pytest medusa-cli/tests/ -v
```

## More Information

- 📚 **Full Guide**: [GEMINI_REMOVAL_MIGRATION_GUIDE.md](GEMINI_REMOVAL_MIGRATION_GUIDE.md)
- 📋 **Implementation Details**: [GEMINI_REMOVAL_IMPLEMENTATION_SUMMARY.md](GEMINI_REMOVAL_IMPLEMENTATION_SUMMARY.md)
- 🔧 **Architecture**: See `medusa-cli/src/medusa/core/llm/`
- ✅ **Validation Script**: `scripts/validate-gemini-removal.sh`

---

**Last Updated**: November 2025
**Status**: ✅ Production Ready

