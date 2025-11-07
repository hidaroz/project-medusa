# Performance Guide for Running Tests on macOS

## Problem

Running MEDUSA tool integration tests on macOS can cause system lag and slowdowns because:
- Tools like `httpx` default to 50 concurrent threads
- `amass` can be CPU/memory intensive
- macOS handles high thread counts less efficiently than Linux

## Solutions

### 1. Use Platform-Aware Test Configuration (Automatic)

Tests now automatically detect macOS and use lower thread counts:
- **macOS**: Max 5 threads for httpx tests
- **Linux**: Up to 10 threads
- **Windows**: Max 5 threads

This is handled automatically via the `test_thread_count` fixture.

### 2. Skip Resource-Intensive Tests

Some tests are marked as `resource_intensive` and can be skipped:

```bash
# Skip resource-intensive tests (faster, less system impact)
pytest tests/integration/test_new_reconnaissance_tools.py -m "not resource_intensive"

# Run only resource-intensive tests
pytest tests/integration/test_new_reconnaissance_tools.py -m "resource_intensive"
```

### 3. Run Tests Selectively

Run only the tests you need:

```bash
# Run only initialization tests (very fast)
pytest tests/integration/test_new_reconnaissance_tools.py -k "initialization"

# Run only parser/structure tests (fast, no real tool execution)
pytest tests/integration/test_new_reconnaissance_tools.py -k "finding_structure or invalid"

# Skip real tool execution tests
pytest tests/integration/test_new_reconnaissance_tools.py -k "not real_execution"
```

### 4. Limit Concurrent Test Execution

Pytest runs tests in parallel by default. Limit this on macOS:

```bash
# Run tests sequentially (one at a time)
pytest tests/integration/test_new_reconnaissance_tools.py -x

# Or limit to 1 worker
pytest tests/integration/test_new_reconnaissance_tools.py -n 1
```

### 5. Reduce Tool Timeouts

Tests now use shorter timeouts (60 seconds) via the `test_timeout` fixture.

### 6. Close Other Applications

Before running tests:
- Close resource-intensive applications (browsers, IDEs, etc.)
- Free up RAM
- Close unnecessary background processes

## Recommended Test Commands for macOS

### Quick Test (Fast, Low Impact)
```bash
# Skip resource-intensive and real tool execution tests
pytest tests/integration/test_new_reconnaissance_tools.py \
  -m "not resource_intensive" \
  -k "not real_execution" \
  -v
```

### Standard Test (Moderate Impact)
```bash
# Run all tests except resource-intensive ones
pytest tests/integration/test_new_reconnaissance_tools.py \
  -m "not resource_intensive" \
  -v
```

### Full Test Suite (High Impact - Use Sparingly)
```bash
# Run everything (may cause system lag)
pytest tests/integration/test_new_reconnaissance_tools.py -v
```

## Configuration

### Custom Thread Counts

You can override thread counts in tests by using the fixture:

```python
def test_my_httpx_test(test_thread_count):
    scanner = HttpxScanner(threads=test_thread_count)  # Uses platform-optimal count
```

### Environment Variables

Set these to reduce resource usage:

```bash
# Limit httpx threads globally
export HTTPX_THREADS=5

# Limit amass timeout
export AMASS_TIMEOUT=60
```

## Monitoring System Resources

While tests run, monitor system resources:

```bash
# macOS Activity Monitor
open -a "Activity Monitor"

# Or use command line
top -l 1 | head -20
```

## Troubleshooting

### System Still Lags

1. **Reduce thread counts further**: Edit `conftest.py` and lower `max_threads` in `get_optimal_thread_count()`
2. **Skip more tests**: Use `-k` to skip specific test patterns
3. **Run tests one at a time**: Use `-x` flag to stop on first failure
4. **Increase system resources**: Close other apps, free up RAM

### Tests Time Out

1. **Increase timeout**: Tests use 60s by default, increase if needed
2. **Check network**: Some tests require internet connectivity
3. **Check tool installation**: Verify tools are installed and in PATH

## Best Practices

1. **Run quick tests during development**: Use `-m "not resource_intensive"`
2. **Run full suite before commits**: Only when system resources allow
3. **Use CI/CD for full testing**: Let automated systems handle resource-intensive tests
4. **Monitor system resources**: Keep Activity Monitor open during tests

## Summary

- ✅ Tests automatically use lower thread counts on macOS
- ✅ Resource-intensive tests can be skipped with `-m "not resource_intensive"`
- ✅ Use selective test execution with `-k` flag
- ✅ Run tests sequentially with `-x` or `-n 1` if needed
- ✅ Close other applications before running full test suite

