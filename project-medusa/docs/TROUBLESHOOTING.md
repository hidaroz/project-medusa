# MEDUSA Troubleshooting Guide

## Installation Issues

### Missing Dependencies

If you get import errors, install all dependencies:
```bash
cd medusa-cli
pip install -r requirements.txt
pip install -e .
```

Required packages:
- typer[all]==0.9.0
- rich==13.7.1
- **prompt_toolkit==3.0.52** ⚠️ Often missed
- httpx==0.26.0
- pyyaml==6.0.1
- google-generativeai==0.3.2
- jinja2==3.1.3

### Issue: `ModuleNotFoundError: No module named 'prompt_toolkit'`

**Solution:** Install missing dependency:
```bash
pip install prompt_toolkit==3.0.52
```

Or reinstall MEDUSA CLI:
```bash
cd medusa-cli
pip install -e . --upgrade
```

## LLM Integration Issues

### Issue: LLM response parsing errors

**Symptoms:** Error message about `response.text` accessor or "multi-part response" errors

**Solution:** Update to latest version with multi-part response support:
```bash
cd medusa-cli
git pull
pip install -e . --upgrade
```

### Issue: Observe mode hangs or times out

**Symptoms:** No progress after "Agent Thinking"

**Troubleshooting:**

1. Check API key configuration:
```bash
cat ~/.medusa/config.yaml | grep api_key
```

2. Test API connectivity:
```bash
curl -H "x-goog-api-key: YOUR_KEY" \
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent" \
  -H 'Content-Type: application/json' \
  -d '{"contents":[{"parts":[{"text":"test"}]}]}'
```

3. Check rate limits in Google Cloud Console

4. Try using mock mode:
```bash
medusa observe --target localhost --mock
```

### Issue: Empty or blocked LLM responses

**Symptoms:** "Response blocked by safety filters" or empty responses

**Solution:**
1. Review your prompts - avoid potentially unsafe content
2. Adjust safety settings in `~/.medusa/config.yaml`
3. Use mock mode for testing: `--mock` flag

## Docker Lab Issues

### Issue: FTP server unhealthy in Docker

**Symptoms:** `docker ps` shows FTP container as "unhealthy"

**Solution 1:** Restart the FTP container:
```bash
docker-compose restart ftp-server
docker logs -f medusa_ftp_server
```

**Solution 2:** Rebuild if restart doesn't work:
```bash
docker-compose build --no-cache ftp-server
docker-compose up -d ftp-server
```

**Solution 3:** Check if FTP port is in use:
```bash
lsof -i :21
# Kill conflicting process if found
```

### Issue: Containers fail to start

**Symptoms:** Services exit immediately or show errors in logs

**Troubleshooting:**

1. Check logs:
```bash
docker-compose logs service-name
```

2. Check resource usage:
```bash
docker stats
```

3. Ensure ports are not in use:
```bash
lsof -i :8080  # Web app
lsof -i :3000  # API
lsof -i :3306  # MySQL
lsof -i :21    # FTP
```

4. Clean restart:
```bash
docker-compose down -v
docker-compose up -d
```

### Issue: Network connectivity between containers

**Symptoms:** Services can't communicate with each other

**Solution:**
```bash
# Check networks exist
docker network ls | grep medusa

# Inspect network
docker network inspect project-medusa_healthcare-internal

# Restart with network recreation
docker-compose down
docker network prune -f
docker-compose up -d
```

## CLI Issues

### Issue: `medusa: command not found`

**Solution 1:** Ensure virtual environment is activated:
```bash
source .venv/bin/activate  # On macOS/Linux
.venv\Scripts\activate     # On Windows
```

**Solution 2:** Reinstall in development mode:
```bash
cd medusa-cli
pip install -e .
```

**Solution 3:** Check PATH:
```bash
which python
which medusa
# If medusa not found, ensure pip bin directory is in PATH
```

### Issue: Configuration file not found

**Symptoms:** "Config file not found" error

**Solution:** Run setup:
```bash
medusa setup
```

Or manually create `~/.medusa/config.yaml`:
```yaml
api_key: YOUR_GEMINI_API_KEY
target: localhost
mode: observe
llm:
  model: gemini-pro
  temperature: 0.7
  max_tokens: 2048
  timeout: 30
  max_retries: 3
```

## Performance Issues

### Issue: Slow LLM responses

**Solutions:**
1. Reduce `max_tokens` in config
2. Increase `timeout` if requests are timing out
3. Check your internet connection
4. Verify Google API status
5. Use mock mode for faster testing

### Issue: High memory usage

**Solutions:**
1. Limit Docker container resources in `docker-compose.yml`
2. Reduce number of concurrent operations
3. Clear old logs and reports:
```bash
rm -rf ~/.medusa/logs/*
rm -rf ~/.medusa/reports/*
```

## Testing Issues

### Issue: Tests fail with API errors

**Solution:** Tests requiring LLM will skip if no API key:
```bash
# Set API key for tests
export GOOGLE_API_KEY=your_key

# Or skip slow tests
pytest tests/unit/ -v
pytest -m "not slow" -v
```

### Issue: Integration tests timeout

**Solution:** Increase timeout or skip slow tests:
```bash
# Skip slow tests
pytest -m "not slow" -v

# Or increase timeout
pytest tests/integration/ --timeout=300
```

## Database Issues

### Issue: MySQL connection refused

**Solutions:**
```bash
# Check MySQL is running
docker-compose ps | grep mysql

# Check MySQL logs
docker-compose logs ehr-database

# Restart MySQL
docker-compose restart ehr-database

# Wait for health check
docker-compose ps
```

### Issue: Database initialization failed

**Solutions:**
```bash
# Check init scripts ran
docker-compose logs ehr-database | grep "init"

# Manually run init script
docker-compose exec ehr-database mysql -u root -p < lab-environment/init-scripts/db/init.sql

# Or recreate with fresh data
docker-compose down -v
docker-compose up -d
```

## API Server Issues

### Issue: EHR API not responding

**Troubleshooting:**
```bash
# Check if API is running
curl http://localhost:3000/health

# Check logs
docker-compose logs ehr-api

# Restart API
docker-compose restart ehr-api

# Check port availability
lsof -i :3000
```

## Common Error Messages

### "Rate limit exceeded"

**Solution:** 
- Wait before retrying (exponential backoff is built-in)
- Check Google Cloud Console quotas
- Consider upgrading API plan

### "SSL certificate verify failed"

**Solution:**
```bash
# Update certificates
pip install --upgrade certifi

# Or disable SSL verification (not recommended for production)
export HTTPX_VERIFY=false
```

### "Permission denied" on logs/reports

**Solution:**
```bash
# Fix permissions
chmod -R 755 ~/.medusa
chown -R $USER:$USER ~/.medusa
```

## Getting Help

If you're still experiencing issues:

1. **Check the logs:**
```bash
# CLI logs
ls -la ~/.medusa/logs/

# Docker logs
docker-compose logs
```

2. **Enable debug mode:**
```bash
medusa observe --target localhost --debug
```

3. **Run diagnostics:**
```bash
medusa status
docker-compose ps
docker stats
```

4. **Report issues:**
- Include error messages
- Include relevant log files
- Include system information (OS, Python version, Docker version)
- Include steps to reproduce

## Quick Reference

### Essential Commands

```bash
# Setup
medusa setup

# Check status
medusa status
docker-compose ps

# View logs
medusa logs
docker-compose logs -f

# Restart everything
docker-compose restart

# Clean slate
docker-compose down -v
rm -rf ~/.medusa/logs/* ~/.medusa/reports/*
docker-compose up -d

# Run tests
pytest tests/unit/ -v
pytest tests/integration/ -v
```

### Health Checks

```bash
# All services
docker ps --format "table {{.Names}}\t{{.Status}}"

# Specific checks
curl http://localhost:8080              # Web app
curl http://localhost:3000/health       # API
docker-compose exec ehr-database mysql -u root -p -e "SELECT 1"  # DB
ftp localhost 21                        # FTP
```

