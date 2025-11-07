#!/bin/bash

# MEDUSA Installation Script
# Helps install MEDUSA CLI and resolve PATH issues

set -e

echo ""
echo "🔴 MEDUSA Installation Script"
echo "================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    SHELL_RC="~/.bashrc"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    SHELL_RC="~/.zshrc"
else
    OS="unknown"
    SHELL_RC="~/.bashrc"
fi

echo "✓ Detected OS: $OS"

# Check Python version
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo ""
    echo "❌ Python not found!"
    echo "Please install Python 3.9 or later and try again."
    exit 1
fi

python_version=$($PYTHON_CMD --version | cut -d' ' -f2)
echo "✓ Python version: $python_version"

# Check if version is >= 3.9
major_version=$(echo $python_version | cut -d'.' -f1)
minor_version=$(echo $python_version | cut -d'.' -f2)

if [ "$major_version" -lt 3 ] || ([ "$major_version" -eq 3 ] && [ "$minor_version" -lt 9 ]); then
    echo ""
    echo "❌ Python 3.9+ required (found $python_version)"
    exit 1
fi

echo ""
echo "📦 Installing dependencies..."
echo ""

# Install in editable mode with user flag
$PYTHON_CMD -m pip install -e . --user 2>&1 | grep -E "Successfully|Requirement|ERROR" || true

echo ""
echo "✓ Installation complete!"
echo ""

# Get Python user scripts directory
SCRIPTS_DIR=$($PYTHON_CMD -m site --user-base)/bin

# Check if PATH already contains SCRIPTS_DIR
if [[ ":$PATH:" == *":$SCRIPTS_DIR:"* ]]; then
    echo "✓ Python scripts directory is in PATH"
    echo ""
    echo "🎉 MEDUSA is ready to use!"
    echo ""
    echo "Try these commands:"
    echo "  • medusa --help       # Show help"
    echo "  • medusa setup        # Run setup wizard"
    echo "  • medusa shell        # Start interactive shell"
    echo ""
else
    echo "⚠️  Python scripts directory not in PATH: $SCRIPTS_DIR"
    echo ""
    echo "Add it to your PATH to use 'medusa' command directly:"
    echo ""
    
    if [[ "$SHELL" == *"zsh"* ]]; then
        echo "  Step 1: Edit ~/.zshrc"
        echo "    echo 'export PATH=\"$SCRIPTS_DIR:\$PATH\"' >> ~/.zshrc"
        echo ""
        echo "  Step 2: Reload shell"
        echo "    source ~/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        echo "  Step 1: Edit ~/.bashrc"
        echo "    echo 'export PATH=\"$SCRIPTS_DIR:\$PATH\"' >> ~/.bashrc"
        echo ""
        echo "  Step 2: Reload shell"
        echo "    source ~/.bashrc"
    else
        echo "  Add to your shell configuration:"
        echo "    export PATH=\"$SCRIPTS_DIR:\$PATH\""
    fi
    
    echo ""
    echo "Or use MEDUSA without PATH modification:"
    echo "  $PYTHON_CMD -m medusa.cli --help"
    echo ""
fi

echo "📚 Next steps:"
echo "  1. Review documentation: docs/QUICKSTART.md"
echo "  2. Run setup: medusa setup"
echo "  3. Try: medusa --help"
echo ""

