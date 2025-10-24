# Medusa CLI Installation Guide

## Prerequisites

- Python 3.9 or higher
- Google Gemini API key (free from [Google AI Studio](https://ai.google.dev/gemini-api/docs/quickstart))
- Backend API running (see main project README)

## Installation Steps

### 1. Get Gemini API Key

1. Go to [Google AI Studio](https://ai.google.dev/gemini-api/docs/quickstart)
2. Sign in with your Google account
3. Click "Get API key"
4. Create a new API key
5. Copy the API key

### 2. Set Environment Variable

```bash
# Add to your ~/.bashrc, ~/.zshrc, or ~/.profile
export GEMINI_API_KEY="your-api-key-here"

# Or set temporarily for current session
export GEMINI_API_KEY="your-api-key-here"
```

### 3. Install Dependencies

```bash
cd medusa-cli
pip install -r requirements.txt
```

### 4. Install CLI (Optional)

```bash
# Install in development mode
pip install -e .

# Or run directly
python medusa.py --help
```

## Usage

### Basic Commands

```bash
# Check system status
python medusa.py status

# Run AI security assessment
python medusa.py assess

# Run assessment and save report
python medusa.py assess --output security_report.txt

# Deploy AI agent
python medusa.py deploy --objective "Find patient data vulnerabilities"

# Monitor operations
python medusa.py monitor --live
```

### Example Workflow

1. **Start Backend API** (in separate terminal):
   ```bash
   cd ../medusa-backend
   node server.js
   ```

2. **Run AI Assessment**:
   ```bash
   cd medusa-cli
   python medusa.py assess
   ```

3. **View Results**: The CLI will display a comprehensive security assessment report

## Troubleshooting

### Common Issues

1. **"GEMINI_API_KEY not set"**
   - Make sure you've set the environment variable
   - Check with: `echo $GEMINI_API_KEY`

2. **"Backend API not running"**
   - Start the backend: `cd ../medusa-backend && node server.js`
   - Check status: `python medusa.py status`

3. **Import errors**
   - Install dependencies: `pip install -r requirements.txt`
   - Check Python version: `python --version` (should be 3.9+)

### Getting Help

```bash
# Show all commands
python medusa.py --help

# Show specific command help
python medusa.py assess --help
```

## Security Note

This tool is designed for authorized security research only. Always ensure you have proper authorization before running security assessments on any system.
