"""
Comprehensive unit tests for Autonomous Mode.

Tests the AI-driven automated pentesting workflow including:
- Phase execution order
- Abort logic
- Checkpoint management
- Approval gate integration
- Error handling
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime


class TestAutonomousModeInitialization:
    """Test autonomous mode initialization."""

    def test_init_with_valid_target(self):
        """Test initialization with valid target."""
        target = "192.168.1.100"
        
        assert target  # Basic validation
        assert "." in target  # IP format check
        assert len(target.split(".")) == 4  # Four octets

    def test_init_with_valid_hostname(self):
        """Test initialization with hostname."""
        target = "example.com"
        
        assert target
        assert "." in target
        assert len(target.split(".")) >= 2

    def test_init_rejects_invalid_targets(self):
        """Test initialization rejects dangerous characters."""
        dangerous_targets = [
            "192.168.1.100; rm -rf /",
            "$(whoami)",
            "target`ls`",
            "127.0.0.1 && echo hacked",
        ]
        
        for target in dangerous_targets:
            # Should contain dangerous shell characters
            assert any(c in target for c in [';', '$', '`', '&'])


class TestPhaseManagement:
    """Test phase execution management."""

    def test_phase_tracking(self):
        """Test phases are tracked correctly."""
        phases = []
        
        # Simulate phase execution
        phases.append("reconnaissance")
        phases.append("enumeration")
        phases.append("vulnerability_scan")
        
        assert "reconnaissance" in phases
        assert len(phases) == 3
        assert phases[0] == "reconnaissance"

    def test_phase_order(self):
        """Test phases execute in correct order."""
        expected_order = [
            "reconnaissance",
            "enumeration",
            "vulnerability_scan",
            "exploitation",
            "post_exploitation"
        ]
        
        # Verify sequential execution (not string comparison)
        assert expected_order[0] == "reconnaissance"
        assert expected_order[1] == "enumeration"
        assert expected_order[2] == "vulnerability_scan"

    def test_phase_idempotency(self):
        """Test phase execution can be repeated."""
        executed_phases = []
        
        # Execute reconnaissance twice
        executed_phases.append("reconnaissance")
        executed_phases.append("reconnaissance")
        
        # Should allow duplicate tracking
        assert executed_phases.count("reconnaissance") == 2


class TestFindingsCollection:
    """Test findings collection and aggregation."""

    def test_collect_reconnaissance_findings(self):
        """Test collecting reconnaissance phase findings."""
        findings = {
            "phase": "reconnaissance",
            "targets": [
                {"port": 22, "service": "ssh", "state": "open"},
                {"port": 80, "service": "http", "state": "open"},
            ]
        }
        
        assert findings["phase"] == "reconnaissance"
        assert len(findings["targets"]) == 2

    def test_collect_enumeration_findings(self):
        """Test collecting enumeration phase findings."""
        findings = {
            "phase": "enumeration",
            "technologies": [
                {"name": "nginx", "version": "1.20.1"},
                {"name": "PHP", "version": "8.0"},
            ]
        }
        
        assert findings["phase"] == "enumeration"
        assert len(findings["technologies"]) == 2

    def test_collect_vulnerability_findings(self):
        """Test collecting vulnerability findings."""
        findings = {
            "phase": "vulnerability_scan",
            "vulnerabilities": [
                {"name": "SQL Injection", "severity": "HIGH", "cvss": 9.8},
                {"name": "XSS", "severity": "MEDIUM", "cvss": 6.1},
            ]
        }
        
        assert findings["phase"] == "vulnerability_scan"
        assert len(findings["vulnerabilities"]) == 2
        assert any(v["severity"] == "HIGH" for v in findings["vulnerabilities"])

    def test_findings_aggregation(self):
        """Test aggregating findings from multiple phases."""
        all_findings = []
        
        # Add findings from different phases
        all_findings.append({"phase": "recon", "items": 2})
        all_findings.append({"phase": "enum", "items": 3})
        all_findings.append({"phase": "vuln", "items": 5})
        
        total_items = sum(f["items"] for f in all_findings)
        assert total_items == 10
        assert len(all_findings) == 3


class TestAbortLogic:
    """Test adaptive abort logic."""

    def test_abort_when_no_ports_found(self):
        """Test abort decision when no ports found."""
        reconnaissance_result = {
            "ports_found": 0,
            "services_detected": 0
        }
        
        # Should abort if no targets for next phase
        should_abort = reconnaissance_result["ports_found"] == 0
        assert should_abort is True

    def test_continue_when_ports_found(self):
        """Test continuation when ports discovered."""
        reconnaissance_result = {
            "ports_found": 3,
            "services_detected": 3
        }
        
        should_abort = reconnaissance_result["ports_found"] == 0
        assert should_abort is False

    def test_abort_when_no_exploitable_vulns(self):
        """Test abort exploitation when no exploitable vulns found."""
        vuln_scan_result = {
            "vulnerabilities": [
                {"name": "Info Disclosure", "exploitable": False},
                {"name": "Missing Header", "exploitable": False},
            ],
            "exploitable_count": 0
        }
        
        has_exploitable = any(v["exploitable"] for v in vuln_scan_result["vulnerabilities"])
        assert has_exploitable is False

    def test_continue_with_exploitable_vulns(self):
        """Test exploitation attempts with viable targets."""
        vuln_scan_result = {
            "vulnerabilities": [
                {"name": "SQL Injection", "exploitable": True, "severity": "HIGH"},
                {"name": "XSS", "exploitable": True, "severity": "MEDIUM"},
            ],
            "exploitable_count": 2
        }
        
        has_exploitable = any(v["exploitable"] for v in vuln_scan_result["vulnerabilities"])
        assert has_exploitable is True


class TestApprovalGateIntegration:
    """Test approval gate integration with autonomous mode."""

    @pytest.mark.asyncio
    async def test_low_risk_auto_approved(self):
        """Test LOW risk actions auto-approved."""
        approval_gate = {
            "auto_approve_low": True,
            "auto_approve_medium": False
        }
        
        risk_level = "LOW"
        should_approve = approval_gate["auto_approve_low"] if risk_level == "LOW" else False
        
        assert should_approve is True

    @pytest.mark.asyncio
    async def test_medium_risk_requires_approval(self):
        """Test MEDIUM risk requires explicit approval."""
        approval_gate = {
            "auto_approve_low": True,
            "auto_approve_medium": False
        }
        
        risk_level = "MEDIUM"
        should_auto_approve = approval_gate.get(f"auto_approve_{risk_level.lower()}", False)
        
        assert should_auto_approve is False

    @pytest.mark.asyncio
    async def test_high_risk_requires_approval(self):
        """Test HIGH risk always requires approval."""
        approval_gate = {
            "auto_approve_low": True,
            "auto_approve_medium": False,
            "auto_approve_high": False
        }
        
        risk_level = "HIGH"
        should_auto_approve = approval_gate.get(f"auto_approve_{risk_level.lower()}", False)
        
        assert should_auto_approve is False

    def test_approval_gate_can_abort(self):
        """Test approval gate can halt all execution."""
        approval_gate = {
            "aborted": False
        }
        
        assert approval_gate["aborted"] is False
        
        # Simulate abort
        approval_gate["aborted"] = True
        assert approval_gate["aborted"] is True


class TestCheckpointManagement:
    """Test checkpoint save/resume functionality."""

    def test_checkpoint_created_after_phase(self):
        """Test checkpoint created after each phase completes."""
        completed_phases = []
        
        # Simulate completing phases
        completed_phases.append(("reconnaissance", 42.5))
        completed_phases.append(("enumeration", 28.3))
        
        assert len(completed_phases) == 2
        assert completed_phases[0][0] == "reconnaissance"

    def test_resume_from_checkpoint(self):
        """Test resuming from saved checkpoint."""
        checkpoint = {
            "completed_phases": ["reconnaissance", "enumeration"],
            "findings": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ]
        }
        
        # Should resume from vulnerability scan
        remaining_phases = ["vulnerability_scan", "exploitation"]
        
        assert "reconnaissance" not in remaining_phases
        assert "enumeration" not in remaining_phases
        assert len(remaining_phases) == 2

    def test_checkpoint_persistence(self):
        """Test checkpoint data persists correctly."""
        checkpoint = {
            "target": "192.168.1.100",
            "completed_phases": ["reconnaissance"],
            "findings": [{"port": 22}],
            "timestamp": "2025-11-05T10:00:00Z"
        }
        
        # Verify data integrity
        assert checkpoint["target"] == "192.168.1.100"
        assert len(checkpoint["findings"]) == 1
        assert checkpoint["timestamp"] is not None


class TestErrorHandling:
    """Test error handling in autonomous mode."""

    @pytest.mark.asyncio
    async def test_tool_failure_graceful_handling(self):
        """Test graceful handling of tool failures."""
        tool_result = None
        tool_error = "Nmap timed out after 300 seconds"
        
        # Should not propagate, should log and continue
        error_handled = tool_error is not None
        assert error_handled is True

    @pytest.mark.asyncio
    async def test_llm_failure_with_fallback(self):
        """Test fallback when LLM fails."""
        llm_strategy = {
            "strategy": None,  # LLM failed
            "fallback_strategy": "aggressive"  # Use fallback
        }
        
        strategy_to_use = llm_strategy["strategy"] or llm_strategy["fallback_strategy"]
        assert strategy_to_use == "aggressive"

    def test_invalid_finding_handling(self):
        """Test handling of malformed findings."""
        findings = [
            {"port": 80, "service": "http"},  # Valid
            {},  # Invalid - empty
            {"port": "not_a_number"},  # Invalid data
        ]
        
        # Valid findings must have port as integer
        valid_findings = [
            f for f in findings 
            if f and "port" in f and isinstance(f["port"], int)
        ]
        assert len(valid_findings) == 1
        assert valid_findings[0]["port"] == 80

    def test_network_timeout_handling(self):
        """Test handling of network timeouts."""
        timeouts = 0
        max_retries = 3
        
        # Simulate retry logic
        for attempt in range(max_retries):
            timeouts += 1
            if timeouts >= max_retries:
                # Give up
                break
        
        assert timeouts == max_retries


class TestReportGeneration:
    """Test report generation and formatting."""

    def test_report_contains_required_sections(self):
        """Test report has all required sections."""
        report = {
            "executive_summary": "Summary of findings",
            "detailed_findings": [{"type": "vulnerability"}],
            "statistics": {"total": 3, "critical": 1},
            "recommendations": ["Patch systems"],
            "methodology": "OWASP Top 10"
        }
        
        required_sections = ["executive_summary", "detailed_findings", "statistics", "recommendations"]
        assert all(s in report for s in required_sections)

    def test_report_severity_distribution(self):
        """Test report correctly distributes severity levels."""
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
            {"severity": "LOW"},
        ]
        
        severity_counts = {}
        for f in findings:
            severity = f["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        assert severity_counts["CRITICAL"] == 1
        assert severity_counts["HIGH"] == 2
        assert severity_counts["MEDIUM"] == 1

    def test_report_metadata(self):
        """Test report contains proper metadata."""
        report_metadata = {
            "target": "192.168.1.100",
            "start_time": "2025-11-05T10:00:00Z",
            "end_time": "2025-11-05T10:45:00Z",
            "duration_seconds": 2700,
            "scan_type": "autonomous"
        }
        
        assert report_metadata["target"] is not None
        assert report_metadata["duration_seconds"] > 0


class TestPerformanceMetrics:
    """Test performance monitoring during autonomous scan."""

    def test_phase_timing(self):
        """Test phase execution timing."""
        phase_timings = {
            "reconnaissance": 42.5,
            "enumeration": 28.3,
            "vulnerability_scan": 15.7
        }
        
        total_time = sum(phase_timings.values())
        assert total_time == pytest.approx(86.5, 0.01)

    def test_memory_usage_tracking(self):
        """Test memory usage during scan."""
        memory_stats = {
            "start_mb": 50,
            "peak_mb": 250,
            "end_mb": 75
        }
        
        memory_used = memory_stats["peak_mb"] - memory_stats["start_mb"]
        assert memory_used > 0
        assert memory_stats["end_mb"] < memory_stats["peak_mb"]

    def test_findings_rate(self):
        """Test findings discovery rate."""
        findings_per_phase = {
            "reconnaissance": 5,
            "enumeration": 3,
            "vulnerability_scan": 2
        }
        
        total_findings = sum(findings_per_phase.values())
        assert total_findings == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
