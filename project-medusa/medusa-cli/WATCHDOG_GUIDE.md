# MEDUSA Watchdog Service Guide

## Overview

The MEDUSA Watchdog Service is an application-level monitoring system designed to detect and respond to "zombie" states where the MEDUSA API process is alive but the logic is stuck (e.g., infinite loops, deadlocks, or unresponsive operations).

## Key Features

### 1. Health Monitoring
- Regular health endpoint pings (`/health`)
- Configurable check intervals (default: 30 seconds)
- Consecutive failure detection
- Automatic restart on critical failures (optional)

### 2. Stuck Operation Detection
- Monitors `last_state_update_timestamp` for each operation
- Detects operations in "RUNNING" state with no updates
- Configurable stuck threshold (default: 10 minutes)
- Per-operation or all-operations monitoring

### 3. Docker-Friendly Design
- Logs to stderr for Docker log capture
- Non-zero exit codes trigger Docker restart policies
- Environment variable configuration
- Graceful shutdown handling

## Exit Codes

The watchdog uses specific exit codes to indicate different failure scenarios:

| Exit Code | Meaning | When It Occurs |
|-----------|---------|----------------|
| 0 | Normal shutdown | User interrupted (Ctrl+C) or graceful stop |
| 1 | Health check failure | API unreachable after max consecutive failures |
| 2 | Stuck operation | Operation stuck longer than threshold |
| 3 | Watchdog crash | Internal watchdog service error |

## Usage

### Basic Usage

```bash
# Monitor all running operations with defaults
medusa watchdog

# Monitor a specific operation
medusa watchdog --operation-id op_abc123

# Custom check interval (60 seconds)
medusa watchdog --check-interval 60

# Custom stuck threshold (5 minutes = 300 seconds)
medusa watchdog --stuck-threshold 300

# Enable auto-restart (exits on failures for Docker)
medusa watchdog --auto-restart
```

### Docker Deployment

#### Using Environment Variables

```bash
# Set environment variables
export MEDUSA_API_URL="http://medusa-api:8000"
export WATCHDOG_CHECK_INTERVAL="30"
export WATCHDOG_STUCK_THRESHOLD="600"
export WATCHDOG_MAX_FAILURES="3"
export WATCHDOG_AUTO_RESTART="true"

# Run with environment config
medusa watchdog --env-config
```

#### Docker Compose Example

```yaml
version: '3.8'

services:
  medusa-api:
    image: medusa-api:latest
    ports:
      - "8000:8000"
    restart: unless-stopped

  medusa-watchdog:
    image: medusa-cli:latest
    command: medusa watchdog --env-config
    environment:
      - MEDUSA_API_URL=http://medusa-api:8000
      - WATCHDOG_CHECK_INTERVAL=30
      - WATCHDOG_STUCK_THRESHOLD=600
      - WATCHDOG_AUTO_RESTART=true
    depends_on:
      - medusa-api
    restart: unless-stopped
```

#### Standalone Docker Run

```bash
docker run -d \
  --name medusa-watchdog \
  --restart unless-stopped \
  -e MEDUSA_API_URL=http://medusa-api:8000 \
  -e WATCHDOG_AUTO_RESTART=true \
  medusa-cli:latest \
  medusa watchdog --env-config
```

### Standalone Python Script

You can also run the watchdog as a standalone Python script:

```bash
# Direct execution
python -m medusa.core.watchdog \
  --api-url http://localhost:8000 \
  --check-interval 30 \
  --stuck-threshold 600 \
  --auto-restart

# Using the module directly
cd medusa-cli/src
python -m medusa.core.watchdog --help
```

## Configuration

### CLI Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--api-url` | `-u` | `http://localhost:8000` | MEDUSA API base URL |
| `--operation-id` | `-o` | None (all ops) | Specific operation to monitor |
| `--check-interval` | `-i` | 30 | Seconds between health checks |
| `--stuck-threshold` | `-t` | 600 | Seconds before operation considered stuck |
| `--auto-restart` | `-r` | False | Enable auto-restart on failures |
| `--env-config` | `-e` | False | Load config from environment |

### Environment Variables

When using `--env-config`, the following environment variables are used:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MEDUSA_API_URL` | string | `http://localhost:8000` | API base URL |
| `WATCHDOG_CHECK_INTERVAL` | int | 30 | Health check interval (seconds) |
| `WATCHDOG_STUCK_THRESHOLD` | int | 600 | Stuck detection threshold (seconds) |
| `WATCHDOG_MAX_FAILURES` | int | 3 | Max consecutive failures before alert |
| `WATCHDOG_REQUEST_TIMEOUT` | int | 10 | HTTP request timeout (seconds) |
| `WATCHDOG_AUTO_RESTART` | bool | false | Enable auto-restart (`true`/`false`) |

## How It Works

### Monitoring Loop

```
┌─────────────────────────────────────────┐
│         Watchdog Monitor Loop           │
└─────────────────────────────────────────┘
                   │
                   ▼
      ┌────────────────────────┐
      │  1. Check /health      │
      │     endpoint           │
      └────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
   [Success]             [Failure]
        │                     │
        │              ┌──────▼──────┐
        │              │ Increment   │
        │              │ failure     │
        │              │ counter     │
        │              └──────┬──────┘
        │                     │
        │              ┌──────▼──────────┐
        │              │ Max failures?   │
        │              └──────┬──────────┘
        │                     │
        │              ┌──────▼──────────┐
        │              │ Auto-restart?   │
        │              │   Exit(1)       │
        │              └─────────────────┘
        │
        ▼
┌──────────────────────────┐
│  2. Get running ops      │
│     (or specific op)     │
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│  3. Check each op:       │
│     - Status = RUNNING?  │
│     - Time since update? │
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│  If stuck (>threshold):  │
│     - Log alert          │
│     - Auto-restart?      │
│       Exit(2)            │
└──────────────────────────┘
        │
        ▼
┌──────────────────────────┐
│  4. Sleep (interval)     │
│     then repeat          │
└──────────────────────────┘
```

### Stuck Detection Logic

An operation is considered **stuck** if:

1. Operation status is `"RUNNING"`
2. Time since `last_state_update_timestamp` exceeds `stuck_threshold`

Example:
```python
# Operation stuck for 12 minutes, threshold is 10 minutes
time_since_update = 720 seconds  # 12 minutes
stuck_threshold = 600 seconds    # 10 minutes
is_stuck = (time_since_update > stuck_threshold)  # True
```

## Testing

### Quick Start Testing

We provide a comprehensive test script to verify watchdog functionality:

```bash
# Check current API status
python test_watchdog.py check

# Simulate a stuck operation
python test_watchdog.py stuck

# Test API failure handling
python test_watchdog.py api-failure
```

### Manual Testing Scenarios

#### Scenario 1: Stuck Operation Detection

1. Start the MEDUSA API:
   ```bash
   cd medusa-cli
   python api_server.py
   ```

2. Create a test operation (or use test script):
   ```bash
   python test_watchdog.py stuck
   ```

3. In another terminal, start the watchdog with short threshold:
   ```bash
   medusa watchdog --operation-id <op_id> --stuck-threshold 60
   ```

4. Wait 60+ seconds without updating the operation
5. Watchdog should detect stuck state and alert

#### Scenario 2: API Health Failure

1. Start the watchdog:
   ```bash
   medusa watchdog --auto-restart
   ```

2. Stop the API while watchdog is running:
   ```bash
   pkill -f api_server.py
   ```

3. After 3 consecutive failures, watchdog should exit with code 1

#### Scenario 3: Docker Auto-Restart

1. Set up Docker with restart policy:
   ```yaml
   medusa-watchdog:
     restart: unless-stopped
     command: medusa watchdog --auto-restart
   ```

2. Simulate failure (stop API)
3. Watchdog exits with non-zero code
4. Docker automatically restarts the watchdog container

## Acceptance Criteria Verification

### ✅ Task 3.1: Application-Level Watchdog

**Requirements:**
- [x] WatchdogService class created
- [x] monitor_loop() implemented with:
  - [x] /health ping every 30 seconds (configurable)
  - [x] Logic check for last_state_update_timestamp
  - [x] Detection of operations stuck >10 minutes (configurable)
- [x] Alerts logged to stderr for Docker
- [x] Non-zero exit code on failure (Docker restart compatible)

**Acceptance Test:**
```bash
# 1. Simulate stuck agent (manual sleep in operation)
python test_watchdog.py stuck

# 2. Start watchdog with 60-second threshold
medusa watchdog --operation-id <op_id> --stuck-threshold 60

# 3. Wait 60+ seconds
# Expected: Watchdog detects stuck state and alerts

# 4. With auto-restart enabled
medusa watchdog --operation-id <op_id> --stuck-threshold 60 --auto-restart

# Expected: Watchdog exits with code 2 (stuck operation)
echo $?  # Should print: 2
```

## Troubleshooting

### Watchdog Not Detecting Stuck Operations

**Possible causes:**
1. Threshold too high - lower `--stuck-threshold`
2. Operation not in RUNNING state - check `/api/operations/<id>/status`
3. Timestamps being updated - verify operation is truly stuck

**Debug steps:**
```bash
# Check operation status manually
curl http://localhost:8000/api/operations/<op_id>/status | jq .

# Run watchdog with shorter intervals
medusa watchdog --operation-id <op_id> --check-interval 10 --stuck-threshold 30
```

### Watchdog Exiting Immediately

**Possible causes:**
1. API not reachable
2. Auto-restart enabled with failing checks

**Debug steps:**
```bash
# Check API health manually
curl http://localhost:8000/health

# Run without auto-restart to see errors
medusa watchdog --api-url http://localhost:8000

# Check watchdog logs
docker logs medusa-watchdog  # If using Docker
```

### False Positives (Healthy Operations Marked as Stuck)

**Possible causes:**
1. System time drift
2. Timezone mismatches
3. Operation legitimately slow

**Solutions:**
- Increase `--stuck-threshold` to allow more time
- Verify system clocks are synchronized
- Check `last_state_update_timestamp` format

## Integration with Other Components

### API Server Requirements

The MEDUSA API must provide:

1. **Health endpoint** (`/health`):
   ```json
   {
     "status": "healthy",
     "timestamp": "2025-11-20T12:00:00Z"
   }
   ```

2. **Operation status endpoint** (`/api/operations/<id>/status`):
   ```json
   {
     "id": "op_123",
     "status": "RUNNING",
     "last_state_update_timestamp": "2025-11-20T11:55:00Z"
   }
   ```

3. **Running operations list** (`/api/operations?status=RUNNING`):
   ```json
   [
     {
       "id": "op_123",
       "status": "RUNNING",
       "last_state_update_timestamp": "2025-11-20T11:55:00Z"
     }
   ]
   ```

### Monitoring Tools

The watchdog integrates well with:

- **Docker**: Auto-restart via exit codes
- **Prometheus**: Export metrics via custom exporter
- **Grafana**: Visualize watchdog alerts
- **ELK Stack**: Aggregate stderr logs
- **Sentry**: Capture critical failures

## Best Practices

### Production Deployment

1. **Always use auto-restart in production**:
   ```bash
   medusa watchdog --auto-restart --env-config
   ```

2. **Set appropriate thresholds**:
   - Short interval: 30-60 seconds
   - Long threshold: 5-10 minutes (depends on operation complexity)

3. **Monitor watchdog itself**:
   - Set up Docker restart policy
   - Alert on repeated restarts
   - Track exit code patterns

4. **Use environment variables**:
   - Easier to update without code changes
   - Better for containerized deployments

### Development/Testing

1. **Disable auto-restart locally**:
   ```bash
   medusa watchdog  # No --auto-restart flag
   ```

2. **Use shorter thresholds for faster iteration**:
   ```bash
   medusa watchdog --check-interval 10 --stuck-threshold 30
   ```

3. **Test with the provided test script**:
   ```bash
   python test_watchdog.py check
   ```

## Advanced Usage

### Custom Watchdog Scripts

You can import and use the watchdog programmatically:

```python
import asyncio
from medusa.core.watchdog import WatchdogService, WatchdogConfig

# Create custom config
config = WatchdogConfig(
    api_base_url="http://localhost:8000",
    health_check_interval=30,
    stuck_threshold=600,
    enable_auto_restart=True
)

# Create and run watchdog
watchdog = WatchdogService(config)
asyncio.run(watchdog.monitor_loop(operation_id="op_123"))
```

### Multiple Watchdog Instances

Monitor different operations with separate watchdogs:

```bash
# Terminal 1: Monitor operation A
medusa watchdog --operation-id op_aaa --stuck-threshold 300

# Terminal 2: Monitor operation B
medusa watchdog --operation-id op_bbb --stuck-threshold 600

# Terminal 3: Monitor all operations
medusa watchdog --stuck-threshold 900
```

### Custom Alerting

Extend the watchdog for custom alerts:

```python
from medusa.core.watchdog import WatchdogService

class CustomWatchdog(WatchdogService):
    def handle_stuck_operation(self, operation_id, check_result):
        # Custom alerting (e.g., send to Slack, PagerDuty)
        send_alert(f"Operation {operation_id} is stuck!")
        super().handle_stuck_operation(operation_id, check_result)
```

## Summary

The MEDUSA Watchdog Service provides:

- ✅ Automated health monitoring
- ✅ Stuck operation detection (zombie states)
- ✅ Docker-friendly design with restart policies
- ✅ Configurable thresholds and intervals
- ✅ Multiple deployment options (CLI, Docker, standalone)
- ✅ Comprehensive testing tools
- ✅ Production-ready with auto-restart

For more information, see:
- [watchdog.py](src/medusa/core/watchdog.py) - Source code
- [test_watchdog.py](test_watchdog.py) - Test suite
- [cli.py](src/medusa/cli.py) - CLI integration
