# External Tools Installation Guide

This guide covers installation of external security tools required for MEDUSA's reconnaissance and exploitation capabilities.

## Overview

MEDUSA integrates the following external tools:

| Tool | Purpose | Platform |
|------|---------|----------|
| Amass | Subdomain enumeration | Linux, macOS, Windows |
| httpx | Web server validation | Linux, macOS, Windows |
| Kerbrute | Kerberos attacks | Linux, macOS, Windows |
| SQLMap | SQL injection testing | Linux, macOS, Windows |
| Nmap | Port scanning | Linux, macOS, Windows |

## Quick Install (Linux/macOS)

### All at Once

```bash
# Linux (Debian/Ubuntu)
sudo apt update && \
sudo apt install -y amass sqlmap nmap && \
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
go install github.com/ropnop/kerbrute@latest

# macOS
brew install amass sqlmap nmap && \
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
go install github.com/ropnop/kerbrute@latest
```

### Verify Installation

```bash
# Check each tool
amass --version
httpx -version
kerbrute --version
sqlmap --version
nmap --version
```

All should return version info without errors.

## Detailed Installation

### Amass

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y amass
```

#### Linux (Other Distributions)
```bash
# Download prebuilt binary
wget https://github.com/OWASP/Amass/releases/download/v4.0.0/amass_linux_amd64.zip
unzip amass_linux_amd64.zip
sudo mv amass_linux_amd64/amass /usr/local/bin/
```

#### macOS
```bash
brew install amass
```

#### From Source (Any OS)
```bash
go install -v github.com/OWASP/Amass/v4/cmd/amass@latest
```

#### Docker
```bash
docker pull caffix/amass:latest
docker run -v /path/to/config:/etc/amass caffix/amass:latest enum -d example.com
```

#### Verification
```bash
amass --version
which amass  # Should show /usr/local/bin/amass or similar
```

### httpx

#### Linux
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

#### macOS
```bash
brew install httpx-toolkit
# OR
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

#### From Source
```bash
git clone https://github.com/projectdiscovery/httpx.git
cd httpx/cmd/httpx
go build
sudo mv httpx /usr/local/bin/
```

#### Docker
```bash
docker pull projectdiscovery/httpx:latest
```

#### Verification
```bash
httpx -version
which httpx
```

### Kerbrute

#### Linux/macOS
```bash
go install github.com/ropnop/kerbrute@latest
```

#### Pre-built Binaries
```bash
# Linux x64
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# macOS
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_darwin_amd64
chmod +x kerbrute_darwin_amd64
sudo mv kerbrute_darwin_amd64 /usr/local/bin/kerbrute

# Windows
# Download .exe from https://github.com/ropnop/kerbrute/releases
```

#### From Source
```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
make linux64  # or macos, win64
```

#### Verification
```bash
kerbrute --version
which kerbrute
```

### SQLMap

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y sqlmap
```

#### Linux (Other Distributions)
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py --version
```

#### macOS
```bash
brew install sqlmap
```

#### From Source (Any OS)
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
chmod +x sqlmap.py
python sqlmap.py --version
```

#### Docker
```bash
docker pull sqlmap/sqlmap:latest
```

#### Verification
```bash
sqlmap --version
which sqlmap
```

### Nmap

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install -y nmap
```

#### macOS
```bash
brew install nmap
```

#### Windows
Download installer from https://nmap.org/download.html

#### From Source
```bash
# https://nmap.org/download/
```

#### Verification
```bash
nmap --version
which nmap
```

## Dependency Management

### Python Dependencies

MEDUSA requires Python packages. Install via:

```bash
# In project root
pip install -r requirements.txt
```

Key packages:
- `google-generativeai` - For LLM integration
- `httpx` - HTTP client for LLM queries
- `click` - CLI framework
- `pytest` - Testing

### Go Tools

If Go is not installed:

```bash
# Linux
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# macOS
brew install go

# Verify
go version
```

## Platform-Specific Setup

### Linux (Ubuntu 22.04 LTS - Recommended)

```bash
#!/bin/bash

# Update package manager
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
  python3-pip \
  git \
  curl \
  wget \
  build-essential \
  golang-go

# Install security tools
sudo apt install -y amass sqlmap nmap

# Go tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ropnop/kerbrute@latest

# Python packages
pip install -r requirements.txt

echo "✓ All tools installed successfully"
```

### macOS (Homebrew)

```bash
#!/bin/bash

# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install amass sqlmap nmap go python3

# Go tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ropnop/kerbrute@latest

# Python packages
pip install -r requirements.txt

echo "✓ All tools installed successfully"
```

### Windows (PowerShell as Admin)

```powershell
# Install Chocolatey if needed
Set-ExecutionPolicy Bypass -Scope Process -Force
iex ((New-Object System.Net.ServicePointManager).SecurityProtocol = 3072; iex(New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install tools
choco install -y amass sqlmap nmap golang python3

# Go tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ropnop/kerbrute@latest

# Python packages
pip install -r requirements.txt

echo "✓ All tools installed successfully"
```

### Docker Environment

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3-pip \
    git \
    curl \
    wget \
    build-essential \
    golang-go \
    amass \
    sqlmap \
    nmap

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

ENV PATH="${PATH}:/root/go/bin"

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/ropnop/kerbrute@latest

CMD ["/bin/bash"]
```

Build and run:
```bash
docker build -t medusa-tools .
docker run -it medusa-tools
```

## Verify All Tools

Create and run verification script:

```bash
#!/bin/bash
# verify_tools.sh

echo "Verifying MEDUSA tools installation..."
echo ""

tools=("amass" "httpx" "kerbrute" "sqlmap" "nmap")
failed=()

for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        version=$($tool --version 2>&1 | head -1)
        echo "✓ $tool: $version"
    else
        echo "✗ $tool: NOT FOUND"
        failed+=("$tool")
    fi
done

echo ""
if [ ${#failed[@]} -eq 0 ]; then
    echo "✓ All tools verified successfully!"
    exit 0
else
    echo "✗ Missing tools: ${failed[@]}"
    exit 1
fi
```

Run it:
```bash
chmod +x verify_tools.sh
./verify_tools.sh
```

## Troubleshooting

### Tool Not Found in PATH

```bash
# Check where tool is installed
which amass

# If not found, add to PATH
export PATH="$PATH:/usr/local/bin"
echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.bashrc
```

### Go Tools Not Working

```bash
# Ensure Go PATH is set
export PATH="$PATH:$HOME/go/bin"
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
source ~/.bashrc

# Reinstall
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Permission Denied

```bash
# Make tools executable
chmod +x /usr/local/bin/amass
chmod +x /usr/local/bin/httpx
chmod +x /usr/local/bin/kerbrute
chmod +x /usr/local/bin/sqlmap

# Or reinstall with sudo
sudo apt install --reinstall amass
```

### Version Conflicts

```bash
# Remove old version
sudo apt remove amass
sudo apt autoremove

# Reinstall latest
sudo apt install amass
```

## Updating Tools

### Apt-based Systems
```bash
sudo apt update
sudo apt upgrade amass sqlmap nmap
```

### Brew (macOS)
```bash
brew upgrade amass sqlmap nmap httpx-toolkit
```

### Go Tools
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ropnop/kerbrute@latest
```

## Building from Source (Advanced)

### Amass
```bash
git clone https://github.com/OWASP/Amass.git
cd Amass
go install ./cmd/amass@latest
```

### httpx
```bash
git clone https://github.com/projectdiscovery/httpx.git
cd httpx/cmd/httpx
go build -o httpx
sudo mv httpx /usr/local/bin/
```

### Kerbrute
```bash
git clone https://github.com/ropnop/kerbrute
cd kerbrute
go build -o kerbrute
sudo mv kerbrute /usr/local/bin/
```

### SQLMap
```bash
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
./sqlmap.py --version
# Create symlink
sudo ln -s $(pwd)/sqlmap.py /usr/local/bin/sqlmap
```

## Minimal Installation

If you only need certain tools:

```bash
# Just reconnaissance tools (Amass + httpx)
sudo apt install amass
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Just initial access tools (Kerbrute + SQLMap)
go install github.com/ropnop/kerbrute@latest
sudo apt install sqlmap

# Just scanning (Nmap)
sudo apt install nmap
```

## Offline Installation

If you need to install on a system without internet:

1. Download tools on system with internet
2. Create offline package:
```bash
# On connected system
mkdir medusa-tools
cd medusa-tools
wget https://github.com/OWASP/Amass/releases/download/v4.0.0/amass_linux_amd64.zip
# ... download other tools
tar czf medusa-tools.tar.gz .
```

3. Transfer medusa-tools.tar.gz to target system
4. Extract and install:
```bash
tar xzf medusa-tools.tar.gz
cd medusa-tools
sudo cp * /usr/local/bin/
```

## Integration Testing

After installation, verify integration with MEDUSA:

```python
from medusa.tools.amass import AmassScanner
from medusa.tools.httpx_scanner import HttpxScanner
from medusa.tools.kerbrute import KerbruteScanner
from medusa.tools.sql_injection import SQLMapScanner

# Test each tool
amass = AmassScanner()
print(f"Amass available: {amass.is_available()}")

httpx = HttpxScanner()
print(f"httpx available: {httpx.is_available()}")

kerbrute = KerbruteScanner()
print(f"Kerbrute available: {kerbrute.is_available()}")

sqlmap = SQLMapScanner()
print(f"SQLMap available: {sqlmap.is_available()}")
```

If all return `True`, installation is successful!

## Next Steps

- [Amass Documentation](./AMASS.md)
- [httpx Documentation](./HTTPX.md)
- [Kerbrute Documentation](./KERBRUTE.md)
- [SQLMap Documentation](./SQLMAP.md)
- [MEDUSA Getting Started](../00-getting-started/cli-quickstart.md)

