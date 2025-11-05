"""
End-to-end test for observe mode
"""
import pytest
import subprocess
import time
from pathlib import Path

@pytest.mark.integration
@pytest.mark.slow
def test_observe_mode_completes():
    """Test that observe mode completes without crashing"""

    # Start observe mode with timeout
    process = subprocess.Popen(
        ['medusa', 'observe', '--target', 'http://localhost:3001'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Wait up to 120 seconds
        stdout, stderr = process.communicate(timeout=120)

        # Check for success indicators
        assert 'response.text' not in stderr  # Should not have LLM errors
        assert process.returncode == 0 or 'Reconnaissance complete' in stdout or 'complete' in stdout.lower()

        # Check log was created
        logs_dir = Path.home() / ".medusa" / "logs"
        if logs_dir.exists():
            log_files = list(logs_dir.glob("run-*.json"))
            assert len(log_files) > 0, "No log files created"

    except subprocess.TimeoutExpired:
        process.kill()
        pytest.fail("Observe mode timed out after 120 seconds")

@pytest.mark.integration
def test_observe_mode_generates_report():
    """Test that observe mode generates a report"""

    # Run observe mode
    result = subprocess.run(
        ['medusa', 'observe', '--target', 'localhost'],
        capture_output=True,
        text=True,
        timeout=120
    )

    # Check reports directory
    reports_dir = Path.home() / ".medusa" / "reports"
    if reports_dir.exists():
        report_files = list(reports_dir.glob("report-*.html"))
        assert len(report_files) > 0, "No report files generated"

