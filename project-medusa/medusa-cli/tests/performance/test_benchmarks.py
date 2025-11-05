#!/usr/bin/env python3
"""
Performance benchmarks for MEDUSA

Tests to ensure MEDUSA meets performance requirements:
- Reconnaissance completes in reasonable time
- Memory usage stays within limits
- LLM response times are acceptable
- Concurrent operations scale properly
"""

import pytest
import time
import asyncio
import psutil
import os
from typing import List
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_llm_config():
    """Fast mock LLM configuration for performance testing"""
    return {
        "api_key": "test",
        "model": "gemini-pro",
        "mock_mode": True
    }


@pytest.fixture
def measure_memory():
    """Fixture to measure memory usage"""
    process = psutil.Process(os.getpid())

    def get_memory_mb():
        return process.memory_info().rss / 1024 / 1024

    return get_memory_mb


# ============================================================================
# Response Time Benchmarks
# ============================================================================

@pytest.mark.performance
@pytest.mark.asyncio
async def test_llm_response_time_mock(mock_llm_config):
    """Benchmark: Mock LLM response time should be < 1 second"""
    from medusa.core.llm import create_llm_client, LLMConfig

    config = LLMConfig(**mock_llm_config)
    client = create_llm_client(config)

    start = time.time()
    result = await client.get_reconnaissance_recommendation(
        "http://test.com",
        {"phase": "initial"}
    )
    duration = time.time() - start

    assert duration < 1.0, f"Mock LLM too slow: {duration:.2f}s (expected < 1s)"
    assert "recommended_actions" in result

    print(f"\n✅ Mock LLM response time: {duration*1000:.0f}ms")


@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
async def test_reconnaissance_speed(mock_llm_config):
    """Benchmark: Reconnaissance strategy should be fast"""
    from medusa.client import MedusaClient

    start = time.time()

    async with MedusaClient(
        "http://localhost:8080",
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        await client.get_reconnaissance_strategy("http://localhost:8080")

    duration = time.time() - start

    # Should complete in under 5 seconds with mock LLM
    assert duration < 5.0, f"Reconnaissance too slow: {duration:.2f}s"

    print(f"\n✅ Reconnaissance completed in {duration:.2f}s")


@pytest.mark.performance
@pytest.mark.asyncio
async def test_concurrent_llm_requests(mock_llm_config):
    """Benchmark: Multiple concurrent LLM requests"""
    from medusa.core.llm import create_llm_client, LLMConfig

    config = LLMConfig(**mock_llm_config)
    client = create_llm_client(config)

    async def make_request():
        return await client.get_reconnaissance_recommendation(
            "http://test.com",
            {"phase": "initial"}
        )

    # Run 10 concurrent requests
    start = time.time()
    tasks = [make_request() for _ in range(10)]
    results = await asyncio.gather(*tasks)
    duration = time.time() - start

    assert len(results) == 10
    # Should complete in under 5 seconds for mock mode
    assert duration < 5.0, f"Concurrent requests too slow: {duration:.2f}s"

    throughput = len(results) / duration
    print(f"\n✅ Concurrent requests: {len(results)} in {duration:.2f}s ({throughput:.1f} req/s)")


# ============================================================================
# Memory Usage Benchmarks
# ============================================================================

@pytest.mark.performance
@pytest.mark.asyncio
async def test_memory_usage_single_scan(mock_llm_config, measure_memory):
    """Benchmark: Memory usage for single scan"""
    from medusa.client import MedusaClient

    initial_memory = measure_memory()

    async with MedusaClient(
        "http://localhost:8080",
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Perform multiple operations
        for _ in range(5):
            await client.get_reconnaissance_strategy("http://localhost:8080")

    final_memory = measure_memory()
    memory_increase = final_memory - initial_memory

    # Should not use more than 100MB for basic operations
    assert memory_increase < 100, f"Memory usage too high: {memory_increase:.1f}MB"

    print(f"\n✅ Memory usage: {memory_increase:.1f}MB increase")


@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
async def test_memory_leak_detection(mock_llm_config, measure_memory):
    """Benchmark: Check for memory leaks over many iterations"""
    from medusa.client import MedusaClient

    measurements: List[float] = []

    async with MedusaClient(
        "http://localhost:8080",
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Run 20 iterations
        for i in range(20):
            await client.get_reconnaissance_strategy("http://localhost:8080")

            # Measure every 5 iterations
            if i % 5 == 0:
                measurements.append(measure_memory())

    # Memory should stabilize, not continuously grow
    # Check that last measurement is not significantly higher than first
    memory_growth = measurements[-1] - measurements[0]

    # Allow up to 50MB growth (some growth is normal)
    assert memory_growth < 50, \
        f"Potential memory leak: {memory_growth:.1f}MB growth over iterations"

    print(f"\n✅ Memory leak test passed: {memory_growth:.1f}MB growth (acceptable)")


# ============================================================================
# Scalability Benchmarks
# ============================================================================

@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
async def test_multiple_targets_performance(mock_llm_config):
    """Benchmark: Scanning multiple targets"""
    from medusa.client import MedusaClient

    targets = [
        "http://localhost:8080",
        "http://localhost:3001",
        "http://localhost:8081"
    ]

    start = time.time()

    for target in targets:
        async with MedusaClient(
            target,
            api_key="test",
            llm_config=mock_llm_config
        ) as client:
            await client.get_reconnaissance_strategy(target)

    duration = time.time() - start
    avg_per_target = duration / len(targets)

    # Should average under 3 seconds per target with mock LLM
    assert avg_per_target < 3.0, \
        f"Average time per target too high: {avg_per_target:.2f}s"

    print(f"\n✅ {len(targets)} targets scanned in {duration:.2f}s "
          f"({avg_per_target:.2f}s/target)")


# ============================================================================
# Tool Execution Benchmarks
# ============================================================================

@pytest.mark.performance
@pytest.mark.requires_docker
@pytest.mark.slow
def test_nmap_scan_performance():
    """Benchmark: Nmap scan execution time"""
    import subprocess

    start = time.time()

    try:
        result = subprocess.run(
            ["nmap", "-p", "8080,3001,3306", "localhost"],
            capture_output=True,
            timeout=60
        )

        duration = time.time() - start

        assert result.returncode == 0
        # Nmap scan should complete in under 30 seconds for 3 ports
        assert duration < 30, f"Nmap scan too slow: {duration:.2f}s"

        print(f"\n✅ Nmap scan completed in {duration:.2f}s")

    except FileNotFoundError:
        pytest.skip("nmap not installed")
    except subprocess.TimeoutExpired:
        pytest.fail("Nmap scan timed out")


# ============================================================================
# Throughput Benchmarks
# ============================================================================

@pytest.mark.performance
@pytest.mark.asyncio
async def test_llm_throughput(mock_llm_config):
    """Benchmark: LLM request throughput"""
    from medusa.core.llm import create_llm_client, LLMConfig

    config = LLMConfig(**mock_llm_config)
    client = create_llm_client(config)

    request_count = 50
    start = time.time()

    tasks = []
    for i in range(request_count):
        task = client.get_reconnaissance_recommendation(
            f"http://test{i}.com",
            {"phase": "initial"}
        )
        tasks.append(task)

    await asyncio.gather(*tasks)

    duration = time.time() - start
    throughput = request_count / duration

    # Mock mode should handle at least 10 requests/second
    assert throughput >= 10, f"Throughput too low: {throughput:.1f} req/s"

    print(f"\n✅ LLM Throughput: {throughput:.1f} requests/second")


# ============================================================================
# Latency Benchmarks
# ============================================================================

@pytest.mark.performance
@pytest.mark.asyncio
async def test_client_initialization_time(mock_llm_config):
    """Benchmark: Client initialization should be fast"""
    from medusa.client import MedusaClient

    start = time.time()

    async with MedusaClient(
        "http://localhost:8080",
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        pass  # Just measure initialization

    duration = time.time() - start

    # Client initialization should be near-instant
    assert duration < 1.0, f"Client initialization too slow: {duration:.2f}s"

    print(f"\n✅ Client initialization: {duration*1000:.0f}ms")


@pytest.mark.performance
@pytest.mark.asyncio
async def test_vulnerability_risk_assessment_speed(mock_llm_config):
    """Benchmark: Vulnerability risk assessment speed"""
    from medusa.client import MedusaClient

    vuln = {
        "type": "SQL Injection",
        "severity": "high",
        "location": "/api/search"
    }

    start = time.time()

    async with MedusaClient(
        "http://localhost:8080",
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        risk = await client.assess_vulnerability_risk(vuln)

    duration = time.time() - start

    # Risk assessment should be fast
    assert duration < 2.0, f"Risk assessment too slow: {duration:.2f}s"
    assert risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    print(f"\n✅ Risk assessment: {duration*1000:.0f}ms")


# ============================================================================
# Stress Tests
# ============================================================================

@pytest.mark.performance
@pytest.mark.slow
@pytest.mark.asyncio
async def test_sustained_load(mock_llm_config, measure_memory):
    """Stress test: Sustained operations over time"""
    from medusa.client import MedusaClient

    initial_memory = measure_memory()
    request_count = 100

    start = time.time()

    async with MedusaClient(
        "http://localhost:8080",
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        for i in range(request_count):
            await client.get_reconnaissance_strategy("http://localhost:8080")

            # Small delay to simulate realistic usage
            await asyncio.sleep(0.01)

    duration = time.time() - start
    final_memory = measure_memory()
    memory_increase = final_memory - initial_memory

    # Performance assertions
    avg_time = duration / request_count
    assert avg_time < 0.5, f"Average request time too high: {avg_time:.3f}s"

    # Memory assertions
    assert memory_increase < 150, f"Memory usage too high: {memory_increase:.1f}MB"

    print(f"\n✅ Sustained load test:")
    print(f"   - {request_count} requests in {duration:.2f}s")
    print(f"   - Average: {avg_time*1000:.0f}ms/request")
    print(f"   - Memory increase: {memory_increase:.1f}MB")


# ============================================================================
# Performance Summary
# ============================================================================

@pytest.mark.performance
def test_performance_summary():
    """
    Print performance requirements summary
    This is a documentation test - always passes
    """
    summary = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║         MEDUSA Performance Requirements Summary               ║
    ╚═══════════════════════════════════════════════════════════════╝

    Response Time Requirements:
      ✓ Mock LLM:           < 1 second
      ✓ Reconnaissance:     < 5 seconds (mock mode)
      ✓ Risk Assessment:    < 2 seconds
      ✓ Client Init:        < 1 second

    Memory Requirements:
      ✓ Single Scan:        < 100 MB
      ✓ Sustained Load:     < 150 MB
      ✓ Memory Leak:        < 50 MB growth over 20 iterations

    Throughput Requirements:
      ✓ LLM Requests:       > 10 req/s (mock mode)
      ✓ Concurrent Reqs:    10 concurrent in < 5s

    Scalability Requirements:
      ✓ Multi-target:       < 3s per target
      ✓ Sustained Load:     100 requests in reasonable time

    Tool Execution:
      ✓ Nmap Scan:          < 30 seconds (3 ports)
    """
    print(summary)
    assert True  # Always pass - this is informational
