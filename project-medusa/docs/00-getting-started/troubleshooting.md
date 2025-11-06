# 🔧 MEDUSA Troubleshooting Guide

This guide helps you resolve common issues when installing, configuring, or running MEDUSA.

---

## Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Issues](#configuration-issues)
- [Runtime Issues](#runtime-issues)
- [LLM API Issues](#llm-api-issues)
- [Lab Environment Issues](#lab-environment-issues)
- [Report Generation Issues](#report-generation-issues)
- [Performance Issues](#performance-issues)
- [Network Issues](#network-issues)
- [Getting Help](#getting-help)

---

## Installation Issues

### Problem: `pip install` fails with permission error

**Symptoms:**
```
ERROR: Could not install packages due to an EnvironmentError: [Errno 13] Permission denied
```

**Solutions:**

1. **Use a virtual environment (recommended):**
```bash
python -m venv medusa-env
source medusa-env/bin/activate  # On Windows: medusa-env\Scripts\activate
pip install -e .
```

2. **Install with user flag:**
```bash
pip install --user -e .
```

3. **Fix permissions (Linux/Mac):**
```bash
sudo chown -R $USER:$USER ~/.local
```

---

### Problem: `ModuleNotFoundError` for required packages

**Symptoms:**
```
ModuleNotFoundError: No module named 'typer'
```

**Solutions:**

1. **Ensure you're in the virtual environment:**
```bash
which python  # Should show virtual environment path
```

2. **Reinstall dependencies:**
```bash
pip install -r requirements.txt
```

3. **Verify installation:**
```bash
pip list | grep typer
```

---

### Problem: Python version incompatibility

**Symptoms:**
```
ERROR: Package 'medusa' requires a different Python: 3.9.0 not in '>=3.11'
```

**Solution:**

MEDUSA requires Python 3.11 or higher. Install the correct version:

```bash
# Using pyenv (recommended)
pyenv install 3.11
pyenv local 3.11

# Or download from python.org
# https://www.python.org/downloads/
```

---

## Configuration Issues

### Problem: `medusa setup` fails to save configuration

**Symptoms:**
```
Error: Could not write configuration file
```

**Solutions:**

1. **Check directory permissions:**
```bash
ls -la ~/.medusa
chmod 755 ~/.medusa
```

2. **Create config directory manually:**
```bash
mkdir -p ~/.medusa/{logs,reports}
```

3. **Run with explicit config path:**
```bash
medusa setup --config-dir ~/custom/medusa/config
```

---

### Problem: LLM API key not being saved

**Symptoms:**
- Configuration wizard completes but key is not saved
- Subsequent runs ask for API key again

**Solutions:**

1. **Verify config file exists:**
```bash
cat ~/.medusa/config.json
```

2. **Manually edit config:**
```bash
nano ~/.medusa/config.json
```

Add:
```json
{
  "llm_api_key": "your-api-key-here",
  "llm_provider": "google",
  "llm_model": "gemini-1.5-flash"
}
```

3. **Re-run setup with force flag:**
```bash
medusa setup --force
```

---

## Runtime Issues

### Problem: "Tool not found" errors (nmap, sqlmap, etc.)

**Symptoms:**
```
Error: Command 'nmap' not found
```

**Solutions:**

1. **Install pentesting tools (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y nmap sqlmap nikto dirb gobuster hydra metasploit-framework
```

2. **Install on macOS:**
```bash
brew install nmap sqlmap nikto
```

3. **Verify installation:**
```bash
which nmap
nmap --version
```

4. **Check PATH:**
```bash
echo $PATH
```

---

### Problem: Docker not found

**Symptoms:**
```
Error: Docker is required but not installed
Cannot start lab environment
```

**Solutions:**

1. **Install Docker (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
```

2. **Add user to docker group:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

3. **Verify Docker:**
```bash
docker --version
docker ps
```

4. **Install on macOS:**
```bash
brew install --cask docker
# Or download Docker Desktop from docker.com
```

---

### Problem: Permission denied when running commands

**Symptoms:**
```
Error: Permission denied: '/var/run/docker.sock'
```

**Solutions:**

1. **Add user to docker group:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

2. **Restart Docker daemon:**
```bash
sudo systemctl restart docker
```

3. **Run with sudo (not recommended):**
```bash
sudo medusa run target.com
```

---

## LLM API Issues

### Problem: "Invalid API key" error

**Symptoms:**
```
Error: Invalid API key for Google Gemini
```

**Solutions:**

1. **Verify API key is correct:**
   - Go to https://makersuite.google.com/app/apikey
   - Generate new key if needed

2. **Update configuration:**
```bash
medusa setup --force
```

3. **Set environment variable:**
```bash
export GOOGLE_API_KEY="your-key-here"
medusa run target.com
```

4. **Check for whitespace:**
```bash
# Trim whitespace from config
sed -i 's/[[:space:]]*$//' ~/.medusa/config.json
```

---

### Problem: Rate limit exceeded

**Symptoms:**
```
Error: Rate limit exceeded for LLM API
```

**Solutions:**

1. **Wait before retrying:**
   - Google Gemini Free Tier: 15 requests/minute
   - Wait 60 seconds between operations

2. **Upgrade API plan:**
   - Visit Google AI Studio
   - Upgrade to paid plan for higher limits

3. **Reduce verbosity:**
```bash
medusa run target.com --risk-level low
```

---

### Problem: LLM timeouts

**Symptoms:**
```
Error: LLM request timed out after 30 seconds
```

**Solutions:**

1. **Increase timeout:**
```bash
# Edit config.json
"llm_timeout": 60
```

2. **Check internet connection:**
```bash
ping -c 4 8.8.8.8
curl -I https://generativelanguage.googleapis.com
```

3. **Use faster model:**
```bash
medusa setup
# Select: gemini-1.5-flash (faster than gemini-1.5-pro)
```

---

## Lab Environment Issues

### Problem: Lab containers fail to start

**Symptoms:**
```
Error: Failed to start DVWA container
```

**Solutions:**

1. **Check Docker is running:**
```bash
sudo systemctl status docker
```

2. **Pull images manually:**
```bash
docker pull vulnerables/web-dvwa
docker pull bkimminich/juice-shop
docker pull webgoat/webgoat-8.0
```

3. **Check port conflicts:**
```bash
sudo netstat -tulpn | grep :80
sudo netstat -tulpn | grep :3000
```

4. **Clean up old containers:**
```bash
docker ps -a
docker rm $(docker ps -aq)
docker system prune -a
```

---

### Problem: Cannot access lab environment

**Symptoms:**
- Lab started but cannot access http://localhost
- Connection refused

**Solutions:**

1. **Check container status:**
```bash
docker ps
```

2. **Check port mappings:**
```bash
docker port <container-id>
```

3. **Test connectivity:**
```bash
curl http://localhost:80
curl http://localhost:3000
```

4. **Check firewall:**
```bash
# Ubuntu/Debian
sudo ufw status
sudo ufw allow 80/tcp

# CentOS/RHEL
sudo firewall-cmd --list-all
sudo firewall-cmd --add-port=80/tcp --permanent
```

---

## Report Generation Issues

### Problem: HTML report not generated

**Symptoms:**
```
Error: Failed to generate HTML report
```

**Solutions:**

1. **Check reports directory:**
```bash
ls -la ~/.medusa/reports/
```

2. **Verify write permissions:**
```bash
chmod 755 ~/.medusa/reports/
```

3. **Generate report manually:**
```bash
python -c "
from medusa.reporter import ReportGenerator
gen = ReportGenerator()
gen.generate_html_report({}, 'test-001')
"
```

---

### Problem: PDF generation fails

**Symptoms:**
```
⚠️  PDF generation requires 'weasyprint' package
```

**Solutions:**

1. **Install WeasyPrint dependencies:**

**Ubuntu/Debian:**
```bash
sudo apt-get install -y python3-dev python3-pip python3-setuptools python3-wheel \
  python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 \
  libffi-dev shared-mime-info
```

**macOS:**
```bash
brew install cairo pango gdk-pixbuf libffi
```

2. **Install WeasyPrint:**
```bash
pip install weasyprint
```

3. **Verify installation:**
```bash
python -c "import weasyprint; print(weasyprint.__version__)"
```

---

### Problem: Report templates not found

**Symptoms:**
```
jinja2.exceptions.TemplateNotFound: technical_report.html
```

**Solutions:**

1. **Verify templates directory:**
```bash
ls -la src/medusa/templates/
```

2. **Reinstall package:**
```bash
pip install -e .
```

3. **Check Python path:**
```bash
python -c "import medusa; print(medusa.__file__)"
```

---

## Performance Issues

### Problem: MEDUSA runs very slowly

**Symptoms:**
- Operations take much longer than expected
- High CPU usage

**Solutions:**

1. **Use faster LLM model:**
```bash
medusa setup
# Select: gemini-1.5-flash
```

2. **Reduce scan depth:**
```bash
medusa run target.com --risk-level low
```

3. **Increase system resources:**
   - Add more RAM
   - Use SSD instead of HDD

4. **Monitor resource usage:**
```bash
top -p $(pgrep -f medusa)
htop
```

---

### Problem: High memory usage

**Symptoms:**
```
MemoryError: Unable to allocate memory
```

**Solutions:**

1. **Increase swap space:**
```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

2. **Limit concurrent operations:**
```bash
# Edit config.json
"max_concurrent_actions": 2
```

3. **Use lighter model:**
```bash
medusa setup
# Select: gemini-1.5-flash
```

---

## Network Issues

### Problem: Cannot connect to target

**Symptoms:**
```
Error: Connection refused to target.com
```

**Solutions:**

1. **Check target is reachable:**
```bash
ping target.com
curl -I http://target.com
```

2. **Check DNS resolution:**
```bash
nslookup target.com
dig target.com
```

3. **Check firewall:**
```bash
sudo iptables -L
sudo ufw status
```

4. **Use VPN if required:**
```bash
# Connect to VPN first
openvpn config.ovpn
# Then run MEDUSA
medusa run target.com
```

---

### Problem: SSL/TLS certificate errors

**Symptoms:**
```
Error: SSL: CERTIFICATE_VERIFY_FAILED
```

**Solutions:**

1. **Update CA certificates:**
```bash
sudo apt-get install ca-certificates
sudo update-ca-certificates
```

2. **Use `--no-verify-ssl` (if safe):**
```bash
medusa run target.com --no-verify-ssl
```

3. **Install custom certificate:**
```bash
sudo cp custom-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

---

## Getting Help

### Debug Mode

Run MEDUSA with debug output:

```bash
medusa run target.com --verbose
medusa run target.com --debug
```

### Check Logs

```bash
# View latest log
tail -f ~/.medusa/logs/run-*.json

# View all logs
ls -lht ~/.medusa/logs/
```

### System Information

Gather system info for bug reports:

```bash
# MEDUSA version
medusa version

# Python version
python --version

# OS version
uname -a
cat /etc/os-release

# Installed packages
pip list

# Docker version
docker --version

# Tool versions
nmap --version
sqlmap --version
```

### Report an Issue

If you can't resolve the issue:

1. **Check existing issues:** https://github.com/yourusername/medusa/issues

2. **Create a new issue with:**
   - MEDUSA version (`medusa version`)
   - Operating system
   - Python version
   - Complete error message
   - Steps to reproduce
   - Relevant logs

3. **Include diagnostic info:**
```bash
medusa status > diagnostic.txt
cat diagnostic.txt
```

---

## Common Error Messages Reference

| Error | Cause | Solution |
|-------|-------|----------|
| `Command not found: medusa` | Not installed or not in PATH | `pip install -e .` |
| `ModuleNotFoundError` | Missing dependency | `pip install -r requirements.txt` |
| `Invalid API key` | Wrong/expired key | Run `medusa setup --force` |
| `Rate limit exceeded` | Too many API calls | Wait 60s, upgrade plan |
| `Permission denied` | Insufficient permissions | Add user to docker group |
| `Connection refused` | Target unreachable | Check network, firewall |
| `Docker not found` | Docker not installed | Install Docker |
| `Tool not found: nmap` | Missing pentesting tool | `apt-get install nmap` |
| `Template not found` | Missing template files | Reinstall package |
| `Memory allocation failed` | Out of memory | Increase RAM/swap |

---

## Best Practices

### Prevent Common Issues

1. **Always use virtual environments:**
```bash
python -m venv medusa-env
source medusa-env/bin/activate
```

2. **Keep dependencies updated:**
```bash
pip install --upgrade pip
pip install --upgrade -r requirements.txt
```

3. **Regular Docker cleanup:**
```bash
docker system prune -a --volumes
```

4. **Monitor resource usage:**
```bash
htop
df -h
```

5. **Backup configuration:**
```bash
cp ~/.medusa/config.json ~/.medusa/config.json.backup
```

---

## Emergency Recovery

### Reset MEDUSA completely

```bash
# Backup reports and logs
cp -r ~/.medusa/reports ~/medusa-backup-reports
cp -r ~/.medusa/logs ~/medusa-backup-logs

# Remove configuration
rm -rf ~/.medusa

# Reinstall
pip uninstall medusa -y
pip install -e .

# Reconfigure
medusa setup
```

### Reset specific components

```bash
# Reset configuration only
rm ~/.medusa/config.json
medusa setup

# Clear logs
rm ~/.medusa/logs/*.json

# Clear reports
rm ~/.medusa/reports/*.html

# Reset Docker environment
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
docker system prune -a
```

---

## Platform-Specific Issues

### Windows (WSL)

1. **Docker integration:**
```bash
# Ensure Docker Desktop is running with WSL2 backend
wsl --set-default-version 2
```

2. **File permissions:**
```bash
# WSL may have permission issues
sudo chmod -R 755 ~/.medusa
```

### macOS

1. **Xcode command line tools:**
```bash
xcode-select --install
```

2. **Homebrew issues:**
```bash
brew update
brew doctor
```

### Linux (Various Distributions)

**Arch/Manjaro:**
```bash
sudo pacman -S python-pip docker nmap
```

**Fedora/CentOS:**
```bash
sudo dnf install python3-pip docker nmap
```

**openSUSE:**
```bash
sudo zypper install python3-pip docker nmap
```

---

## Still Having Issues?

1. **Join the community:** [Discord/Slack link]
2. **Read the docs:** https://docs.medusa-pentest.io
3. **File an issue:** https://github.com/yourusername/medusa/issues
4. **Email support:** support@medusa-pentest.io

---

**Last Updated:** 2025-11-05
**MEDUSA Version:** 1.0.0
