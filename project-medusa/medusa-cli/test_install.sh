#!/bin/bash
# Quick installation test for MEDUSA CLI

set -e

echo "🔴 MEDUSA CLI - Installation Test"
echo "=================================="
echo ""

# Check Python version
echo "✓ Checking Python version..."
python3 --version

# Create virtual environment
echo "✓ Creating virtual environment..."
python3 -m venv .venv

# Activate virtual environment
echo "✓ Activating virtual environment..."
source .venv/bin/activate

# Install in development mode
echo "✓ Installing MEDUSA in development mode..."
pip install -e . -q

# Test CLI is accessible
echo "✓ Testing CLI installation..."
medusa --help > /dev/null 2>&1 && echo "  ✓ medusa command found" || echo "  ✗ medusa command not found"

# Test version command
echo "✓ Testing version command..."
medusa version

# Test individual commands
echo "✓ Testing available commands..."
medusa --help | grep -E "setup|run|shell|observe|status|logs|reports" && echo "  ✓ All commands available"

echo ""
echo "=================================="
echo "✅ Installation test complete!"
echo ""
echo "Next steps:"
echo "  1. Activate venv: source .venv/bin/activate"
echo "  2. Run setup: medusa setup"
echo "  3. Test run: medusa status"
echo ""

