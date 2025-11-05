# Ollama Setup Guide for MEDUSA

This guide walks you through setting up Ollama to run MEDUSA's AI brain locally.

## Why Local LLM?

- ✅ **Unlimited usage** - No API rate limits or daily quotas
- ✅ **Zero cost** - No ongoing API fees
- ✅ **Complete privacy** - Data never leaves your machine
- ✅ **Offline capability** - Works without internet
- ✅ **Consistent performance** - No API outages or throttling

## Prerequisites

- **Hardware:** 8GB+ RAM (16GB recommended)
- **Storage:** ~10GB free space for models
- **OS:** Linux, macOS, or Windows
- **Optional:** NVIDIA GPU with CUDA (for faster inference)

## Installation

### Linux / macOS
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Verify installation
ollama --version
```

### Windows

1. Download installer: [https://ollama.com/download](https://ollama.com/download)
2. Run `OllamaSetup.exe`
3. Ollama will start automatically as a Windows service

### Docker (Alternative)
```bash
docker run -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

## Model Setup

### Recommended: Mistral-7B-Instruct (4-bit quantized)
```bash
# Pull the model (~4GB download)
ollama pull mistral:7b-instruct

# Verify it's available
ollama list

# Test it
ollama run mistral:7b-instruct "Say: Hello from MEDUSA!"
```

**Why Mistral-7B?**
- Perfect balance of speed and quality
- Excellent at following instructions
- Strong JSON formatting capabilities
- Works well on consumer hardware

### Alternative Models

**Faster (if limited RAM/CPU):**
```bash
ollama pull phi3:mini  # Only 2.3GB
```

**Better Quality (if more resources):**
```bash
ollama pull llama3:8b  # ~5GB, slower but better reasoning
```

## Configuration

### Method 1: Environment Variable
```bash
# Add to ~/.bashrc or ~/.zshrc
export MEDUSA_LLM_PROVIDER=local
export MEDUSA_LLM_MODEL=mistral:7b-instruct
export OLLAMA_URL=http://localhost:11434
```

### Method 2: Config File

Create or update `~/.medusa/config.yaml`:
```yaml
llm:
  provider: local  # "local", "gemini", "mock", or "auto"
  model: mistral:7b-instruct
  ollama_url: http://localhost:11434
  timeout: 60
  temperature: 0.7
  max_tokens: 2048
```

### Method 3: Auto-Detection (Default)

MEDUSA will automatically:
1. Try local Ollama first
2. Fall back to Gemini API if available
3. Use mock mode as last resort

## Verification

Test that MEDUSA can use the local LLM:
```bash
# Run MEDUSA with local LLM
cd medusa-cli
python -m medusa.cli --help

# Or test directly
python scripts/verify_ollama.py
```

**Expected output:**
```
✅ Ollama is running at http://localhost:11434
✅ Model mistral:7b-instruct is available
✅ Test generation successful
```

## Performance Tuning

### GPU Acceleration

**NVIDIA (CUDA):**
```bash
# Verify GPU is detected
nvidia-smi

# Ollama will automatically use GPU if available
```

**AMD (ROCm):**
```bash
# Set environment variable
export OLLAMA_DEVICE=rocm
```

**Apple Silicon (Metal):**
```bash
# Automatically uses GPU on M1/M2/M3 Macs
# No configuration needed
```

### CPU Optimization

```bash
# Set number of threads (adjust based on CPU cores)
export OLLAMA_NUM_THREADS=8

# Restart Ollama
sudo systemctl restart ollama  # Linux
# Or on macOS: ollama serve
```

### Memory Management

```bash
# Limit Ollama memory usage (if needed)
export OLLAMA_MAX_LOADED_MODELS=1  # Unload unused models
```

## Troubleshooting

### "Cannot connect to Ollama server"

**Check if Ollama is running:**
```bash
curl http://localhost:11434/api/tags
```

**If not running:**
```bash
# Linux
sudo systemctl start ollama
sudo systemctl enable ollama  # Start on boot

# macOS
ollama serve

# Windows
# Should start automatically; check Services app
```

### "Model not found"

```bash
# List installed models
ollama list

# Pull missing model
ollama pull mistral:7b-instruct
```

### Slow Inference

**On CPU:**
- Try smaller model: `ollama pull phi3:mini`
- Reduce max_tokens in config (e.g., 1024 instead of 2048)

**With GPU:**
- Verify GPU is being used: `nvidia-smi` or `ollama ps`
- Update GPU drivers
- Check VRAM usage (model should fit in VRAM)

### High Memory Usage

```bash
# Unload models from memory
ollama stop mistral:7b-instruct

# Or restart Ollama
sudo systemctl restart ollama
```

### Connection Timeout

If you see timeout errors:

**Increase timeout in config:**
```yaml
llm:
  timeout: 120  # Increase from default 60
```

**Or use faster model:**
```bash
ollama pull phi3:mini
```

## Advanced Configuration

### Custom Ollama Server

If running Ollama on a different machine:
```yaml
llm:
  provider: local
  ollama_url: http://192.168.1.100:11434  # Remote Ollama server
  model: mistral:7b-instruct
```

### Multiple Models

Switch models based on task:
```bash
# Fast model for quick tasks
export OLLAMA_MODEL=phi3:mini

# High-quality model for complex tasks
export OLLAMA_MODEL=llama3:8b
```

### Custom Model Parameters

```yaml
llm:
  provider: local
  model: mistral:7b-instruct
  temperature: 0.7  # Higher = more creative, lower = more deterministic
  max_tokens: 2048  # Maximum response length
  timeout: 60       # Request timeout in seconds
```

## Comparison: Ollama vs Gemini API

| Feature | Ollama (Local) | Gemini API |
|---------|----------------|------------|
| Cost | Free | ~$5-15/month |
| Rate Limits | None | 15 req/min (free) |
| Privacy | 100% local | Data sent to Google |
| Speed | 5-20s | 1-2s |
| Quality | Very Good | Excellent |
| Setup | 5 minutes | Instant |
| Offline | ✅ Yes | ❌ No |
| Recommended | ✅ Development & Testing | Production (if budget) |

**Recommendation:** Use Ollama for development and unlimited testing. Consider Gemini for production if you need the absolute best quality and can accept rate limits.

## Security Considerations

### Network Isolation

Ollama listens on localhost by default (127.0.0.1:11434), which is safe. If you need to expose it on a network:

```bash
# WARNING: Only do this on trusted networks
export OLLAMA_HOST=0.0.0.0:11434
ollama serve
```

### Model Integrity

Models are downloaded from Ollama's CDN and verified. To check a model's hash:
```bash
ollama list
# Shows model digest (SHA256)
```

### Data Privacy

All inference happens locally. No data is sent to external servers when using Ollama.

## Updating Ollama

### Linux/macOS
```bash
# Reinstall to update
curl -fsSL https://ollama.com/install.sh | sh
```

### Windows
Download latest installer from https://ollama.com/download and run it.

### Update Models
```bash
# Re-pull model to get latest version
ollama pull mistral:7b-instruct
```

## Uninstalling

### Linux
```bash
sudo systemctl stop ollama
sudo systemctl disable ollama
sudo rm /usr/local/bin/ollama
sudo rm -rf /usr/share/ollama
sudo rm -rf ~/.ollama
```

### macOS
```bash
# Stop Ollama
pkill ollama

# Remove application
rm -rf /Applications/Ollama.app
rm -rf ~/.ollama
```

### Windows
1. Stop Ollama service from Services app
2. Uninstall from "Add or Remove Programs"
3. Delete `%USERPROFILE%\.ollama` folder

## Getting Help

- **Ollama docs:** [https://github.com/ollama/ollama](https://github.com/ollama/ollama)
- **MEDUSA issues:** [https://github.com/your-repo/medusa/issues](https://github.com/your-repo/medusa/issues)
- **Discord:** [Your Discord link]

## Next Steps

Now that Ollama is set up:

1. ✅ Verify installation: `python scripts/verify_ollama.py`
2. ✅ Run your first scan: `medusa observe scanme.nmap.org`
3. ✅ Compare quality: `python scripts/compare_llm_quality.py`
4. ✅ Read the [Architecture Guide](ARCHITECTURE.md)

