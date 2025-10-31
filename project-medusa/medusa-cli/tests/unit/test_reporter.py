"""
Unit tests for report generation

Tests report generation, JSON logging, and HTML report creation
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, mock_open
from medusa.reporter import ReportGenerator


@pytest.mark.unit
class TestReportGenerator:
    """Test ReportGenerator initialization and basic functionality"""
    
    @patch('medusa.reporter.get_config')
    def test_reporter_initialization(self, mock_get_config, temp_dir):
        """Test ReportGenerator initializes with config"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        
        assert reporter.config is not None
    
    @patch('medusa.reporter.get_config')
    def test_save_json_log_creates_file(self, mock_get_config, temp_dir):
        """Test save_json_log creates JSON log file"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "mode": "observe",
            "findings": []
        }
        
        result_path = reporter.save_json_log(operation_data, "test_op_123")
        
        assert result_path.exists()
        assert result_path.suffix == ".json"
        assert "test_op_123" in result_path.name
    
    @patch('medusa.reporter.get_config')
    def test_save_json_log_content_structure(self, mock_get_config, temp_dir):
        """Test save_json_log creates properly structured JSON"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "mode": "observe",
            "findings": [
                {"type": "vulnerability", "severity": "HIGH"}
            ]
        }
        
        result_path = reporter.save_json_log(operation_data, "test_op_123")
        
        # Read and verify JSON structure
        with open(result_path, "r") as f:
            log_data = json.load(f)
        
        assert "metadata" in log_data
        assert "operation" in log_data
        assert log_data["metadata"]["operation_id"] == "test_op_123"
        assert log_data["operation"]["target"] == "test.com"
    
    @patch('medusa.reporter.get_config')
    def test_save_json_log_creates_directory(self, mock_get_config, temp_dir):
        """Test save_json_log creates logs directory if it doesn't exist"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        # Ensure directory doesn't exist
        assert not mock_config.logs_dir.exists()
        
        reporter = ReportGenerator()
        reporter.save_json_log({"target": "test.com"}, "test_op")
        
        # Verify directory was created
        assert mock_config.logs_dir.exists()
    
    @patch('medusa.reporter.get_config')
    def test_generate_html_report_creates_file(self, mock_get_config, temp_dir):
        """Test generate_html_report creates HTML file"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "mode": "observe",
            "duration_seconds": 120.5,
            "summary": {
                "total_findings": 5,
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
                "techniques_used": 3,
                "success_rate": 1.0
            },
            "findings": [],
            "mitre_coverage": [],
            "phases": []
        }
        
        result_path = reporter.generate_html_report(operation_data, "test_op_123")
        
        assert result_path.exists()
        assert result_path.suffix == ".html"
        assert "test_op_123" in result_path.name
    
    @patch('medusa.reporter.get_config')
    def test_generate_html_report_contains_expected_content(self, mock_get_config, temp_dir):
        """Test HTML report contains expected sections"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.example.com",
            "mode": "observe",
            "duration_seconds": 120.5,
            "summary": {
                "total_findings": 5,
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
                "techniques_used": 3,
                "success_rate": 1.0
            },
            "findings": [
                {
                    "title": "SQL Injection",
                    "severity": "high",
                    "description": "SQL injection vulnerability",
                    "recommendation": "Use parameterized queries"
                }
            ],
            "mitre_coverage": [
                {
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "status": "complete"
                }
            ],
            "phases": [
                {
                    "name": "reconnaissance",
                    "status": "complete",
                    "duration": 30,
                    "findings": 2,
                    "techniques": 1
                }
            ]
        }
        
        result_path = reporter.generate_html_report(operation_data, "test_op_123")
        
        # Read HTML content
        with open(result_path, "r") as f:
            html_content = f.read()
        
        # Verify key sections present
        assert "MEDUSA Security Assessment Report" in html_content
        assert "test.example.com" in html_content
        assert "SQL Injection" in html_content
        assert "T1046" in html_content
        assert "reconnaissance" in html_content
    
    @patch('medusa.reporter.get_config')
    def test_generate_summary_text(self, mock_get_config):
        """Test generate_summary_text creates text summary"""
        mock_config = Mock()
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "duration_seconds": 120.5,
            "summary": {
                "total_findings": 5,
                "critical": 1,
                "high": 2,
                "medium": 1,
                "low": 1,
                "techniques_used": 3,
                "success_rate": 0.85
            },
            "findings": [
                {
                    "title": "SQL Injection",
                    "severity": "high",
                    "description": "SQL injection in /api/search"
                },
                {
                    "title": "XSS Vulnerability",
                    "severity": "medium",
                    "description": "Reflected XSS in search parameter"
                }
            ]
        }
        
        summary_text = reporter.generate_summary_text(operation_data)
        
        assert "MEDUSA Security Assessment Summary" in summary_text
        assert "Total Findings: 5" in summary_text
        assert "Critical: 1" in summary_text
        assert "High: 2" in summary_text
        assert "Success Rate: 85.0%" in summary_text
        assert "SQL Injection" in summary_text


@pytest.mark.unit
class TestJSONLogFormat:
    """Test JSON log format and structure"""
    
    @patch('medusa.reporter.get_config')
    def test_json_log_metadata_structure(self, mock_get_config, temp_dir):
        """Test JSON log metadata has required fields"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        result_path = reporter.save_json_log({"test": "data"}, "test_op")
        
        with open(result_path, "r") as f:
            log_data = json.load(f)
        
        metadata = log_data["metadata"]
        assert "operation_id" in metadata
        assert "timestamp" in metadata
        assert "medusa_version" in metadata
        assert "log_format_version" in metadata
    
    @patch('medusa.reporter.get_config')
    def test_json_log_preserves_data_types(self, mock_get_config, temp_dir):
        """Test JSON log preserves various data types"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "string": "test",
            "integer": 42,
            "float": 3.14,
            "boolean": True,
            "list": [1, 2, 3],
            "dict": {"nested": "value"}
        }
        
        result_path = reporter.save_json_log(operation_data, "test_op")
        
        with open(result_path, "r") as f:
            log_data = json.load(f)
        
        operation = log_data["operation"]
        assert operation["string"] == "test"
        assert operation["integer"] == 42
        assert operation["float"] == 3.14
        assert operation["boolean"] is True
        assert operation["list"] == [1, 2, 3]
        assert operation["dict"]["nested"] == "value"
    
    @patch('medusa.reporter.get_config')
    def test_json_log_handles_datetime_objects(self, mock_get_config, temp_dir):
        """Test JSON log handles datetime objects"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "timestamp": datetime.now()
        }
        
        # Should not raise exception
        result_path = reporter.save_json_log(operation_data, "test_op")
        
        # Verify file was created
        assert result_path.exists()


@pytest.mark.unit
class TestHTMLReportGeneration:
    """Test HTML report generation"""
    
    @patch('medusa.reporter.get_config')
    def test_html_template_rendering(self, mock_get_config, temp_dir):
        """Test HTML template renders correctly"""
        mock_config = Mock()
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "duration_seconds": 100,
            "summary": {
                "total_findings": 3,
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 1,
                "techniques_used": 2,
                "success_rate": 1.0
            },
            "findings": [],
            "mitre_coverage": [],
            "phases": []
        }
        
        result_path = reporter.generate_html_report(operation_data, "test_op")
        
        with open(result_path, "r") as f:
            html = f.read()
        
        # Verify HTML structure
        assert "<!DOCTYPE html>" in html
        assert "<html lang=\"en\">" in html
        assert "</html>" in html
    
    @patch('medusa.reporter.get_config')
    def test_html_findings_severity_badges(self, mock_get_config, temp_dir):
        """Test HTML report includes severity badges"""
        mock_config = Mock()
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "duration_seconds": 100,
            "summary": {
                "total_findings": 2,
                "critical": 1,
                "high": 1,
                "medium": 0,
                "low": 0,
                "techniques_used": 1,
                "success_rate": 1.0
            },
            "findings": [
                {
                    "title": "Critical Finding",
                    "severity": "critical",
                    "description": "Critical issue",
                    "recommendation": "Fix immediately"
                },
                {
                    "title": "High Finding",
                    "severity": "high",
                    "description": "High severity issue",
                    "recommendation": "Fix soon"
                }
            ],
            "mitre_coverage": [],
            "phases": []
        }
        
        result_path = reporter.generate_html_report(operation_data, "test_op")
        
        with open(result_path, "r") as f:
            html = f.read()
        
        assert "severity-badge" in html
        assert "critical" in html.lower()
        assert "high" in html.lower()
    
    @patch('medusa.reporter.get_config')
    def test_html_mitre_coverage_section(self, mock_get_config, temp_dir):
        """Test HTML report includes MITRE ATT&CK coverage"""
        mock_config = Mock()
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "duration_seconds": 100,
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "techniques_used": 2,
                "success_rate": 1.0
            },
            "findings": [],
            "mitre_coverage": [
                {
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "status": "complete"
                },
                {
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "status": "complete"
                }
            ],
            "phases": []
        }
        
        result_path = reporter.generate_html_report(operation_data, "test_op")
        
        with open(result_path, "r") as f:
            html = f.read()
        
        assert "MITRE ATT&CK Coverage" in html
        assert "T1046" in html
        assert "T1190" in html
        assert "Network Service Discovery" in html


@pytest.mark.unit
class TestReportFilenaming:
    """Test report file naming conventions"""
    
    @patch('medusa.reporter.get_config')
    def test_json_log_filename_format(self, mock_get_config, temp_dir):
        """Test JSON log follows naming convention"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        result_path = reporter.save_json_log({}, "test_operation_123")
        
        # Should be: run-TIMESTAMP-OPERATION_ID.json
        filename = result_path.name
        assert filename.startswith("run-")
        assert "test_operation_123" in filename
        assert filename.endswith(".json")
    
    @patch('medusa.reporter.get_config')
    def test_html_report_filename_format(self, mock_get_config, temp_dir):
        """Test HTML report follows naming convention"""
        mock_config = Mock()
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "duration_seconds": 100,
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "techniques_used": 0, "success_rate": 1.0},
            "findings": [],
            "mitre_coverage": [],
            "phases": []
        }
        
        result_path = reporter.generate_html_report(operation_data, "test_operation_123")
        
        # Should be: report-TIMESTAMP-OPERATION_ID.html
        filename = result_path.name
        assert filename.startswith("report-")
        assert "test_operation_123" in filename
        assert filename.endswith(".html")


@pytest.mark.unit
class TestReportEdgeCases:
    """Test report generation edge cases"""
    
    @patch('medusa.reporter.get_config')
    def test_empty_findings_list(self, mock_get_config, temp_dir):
        """Test report generation with no findings"""
        mock_config = Mock()
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        operation_data = {
            "target": "test.com",
            "duration_seconds": 100,
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "techniques_used": 0, "success_rate": 1.0},
            "findings": [],
            "mitre_coverage": [],
            "phases": []
        }
        
        # Should not raise exception
        json_path = reporter.save_json_log(operation_data, "test_op")
        html_path = reporter.generate_html_report(operation_data, "test_op")
        
        assert json_path.exists()
        assert html_path.exists()
    
    @patch('medusa.reporter.get_config')
    def test_missing_optional_fields(self, mock_get_config, temp_dir):
        """Test report generation with missing optional fields"""
        mock_config = Mock()
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        reporter = ReportGenerator()
        # Minimal data
        operation_data = {
            "target": "test.com"
        }
        
        # Should use defaults for missing fields
        result_path = reporter.generate_html_report(operation_data, "test_op")
        
        assert result_path.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

