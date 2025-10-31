"""
Integration tests for Observe Mode

Tests the full observe mode workflow including reconnaissance, enumeration, and reporting
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from medusa.modes.observe import ObserveMode
from medusa.reporter import ReportGenerator


@pytest.mark.integration
class TestObserveModeIntegration:
    """Integration tests for complete observe mode workflow"""
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.MedusaClient')
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_observe_mode_complete_run(self, mock_get_config, mock_display, mock_client_class, temp_dir, mock_llm_client):
        """Test full observe mode execution"""
        # Setup mocks
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={
            "api_key": "test-key",
            "model": "gemini-pro",
            "mock_mode": True
        })
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        # Mock client responses
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        
        mock_client.perform_reconnaissance = AsyncMock(return_value={
            "findings": [
                {"type": "open_port", "port": 80, "service": "http"},
                {"type": "open_port", "port": 443, "service": "https"}
            ],
            "techniques": [{"id": "T1046", "name": "Network Service Discovery"}]
        })
        
        mock_client.enumerate_services = AsyncMock(return_value={
            "findings": [
                {
                    "type": "api_endpoint",
                    "path": "/api/users",
                    "method": "GET",
                    "severity": "medium",
                    "title": "Unauthenticated Endpoint",
                    "description": "API endpoint accessible without authentication",
                    "recommendation": "Implement authentication"
                }
            ],
            "techniques": [{"id": "T1590", "name": "Gather Victim Network Information"}]
        })
        
        mock_client.get_ai_recommendation = AsyncMock(return_value={
            "recommendations": [
                {
                    "action": "exploit_api_endpoint",
                    "confidence": 0.85,
                    "reasoning": "Unauthenticated API endpoints detected",
                    "risk_level": "MEDIUM"
                }
            ]
        })
        
        mock_client_class.return_value = mock_client
        
        # Run observe mode
        observer = ObserveMode(target="http://test-target.local", api_key="test-key")
        await observer.run()
        
        # Verify intelligence was gathered
        assert observer.intelligence["target"] == "http://test-target.local"
        assert observer.intelligence["mode"] == "observe"
        assert "reconnaissance" in observer.intelligence
        assert "enumeration" in observer.intelligence
        assert "attack_plan" in observer.intelligence
        
        # Verify client methods were called
        mock_client.perform_reconnaissance.assert_called_once()
        mock_client.enumerate_services.assert_called_once()
        mock_client.get_ai_recommendation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.MedusaClient')
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_observe_mode_generates_reports(self, mock_get_config, mock_display, mock_client_class, temp_dir):
        """Test that observe mode generates JSON and HTML reports"""
        # Setup mocks
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={
            "api_key": "test-key",
            "model": "gemini-pro",
            "mock_mode": True
        })
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        # Mock client
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.perform_reconnaissance = AsyncMock(return_value={
            "findings": [],
            "techniques": []
        })
        mock_client.enumerate_services = AsyncMock(return_value={
            "findings": [],
            "techniques": []
        })
        mock_client.get_ai_recommendation = AsyncMock(return_value={
            "recommendations": []
        })
        mock_client_class.return_value = mock_client
        
        # Run observe mode
        observer = ObserveMode(target="http://test-target.local", api_key="test-key")
        await observer.run()
        
        # Verify report files were created
        assert (temp_dir / "logs").exists()
        assert (temp_dir / "reports").exists()
        
        # Check for JSON log files
        log_files = list((temp_dir / "logs").glob("*.json"))
        assert len(log_files) > 0
        
        # Check for HTML report files
        report_files = list((temp_dir / "reports").glob("*.html"))
        assert len(report_files) > 0
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.MedusaClient')
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_observe_mode_no_exploitation(self, mock_get_config, mock_display, mock_client_class, temp_dir):
        """Test that observe mode does NOT perform exploitation"""
        # Setup mocks
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={
            "api_key": "test-key",
            "model": "gemini-pro",
            "mock_mode": True
        })
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        # Mock client
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.perform_reconnaissance = AsyncMock(return_value={
            "findings": [],
            "techniques": []
        })
        mock_client.enumerate_services = AsyncMock(return_value={
            "findings": [],
            "techniques": []
        })
        mock_client.get_ai_recommendation = AsyncMock(return_value={
            "recommendations": []
        })
        
        # Add exploit method that should NOT be called
        mock_client.exploit_vulnerability = AsyncMock()
        mock_client_class.return_value = mock_client
        
        # Run observe mode
        observer = ObserveMode(target="http://test-target.local", api_key="test-key")
        await observer.run()
        
        # Verify exploit was NOT called
        mock_client.exploit_vulnerability.assert_not_called()
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.MedusaClient')
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_observe_mode_operation_id_format(self, mock_get_config, mock_display, mock_client_class):
        """Test operation ID follows correct format"""
        # Setup minimal mocks
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={})
        mock_get_config.return_value = mock_config
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        # Verify operation ID format: observe_YYYYMMDD_HHMMSS
        assert observer.operation_id.startswith("observe_")
        assert len(observer.operation_id.split("_")) == 3
        
        # Verify intelligence structure
        assert observer.intelligence["operation_id"] == observer.operation_id
        assert observer.intelligence["mode"] == "observe"
        assert observer.intelligence["target"] == "http://test.com"


@pytest.mark.integration
class TestObserveModePhaes:
    """Test individual phases of observe mode"""
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_passive_reconnaissance_phase(self, mock_get_config, mock_display):
        """Test passive reconnaissance phase"""
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={})
        mock_get_config.return_value = mock_config
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        mock_client = AsyncMock()
        mock_client.perform_reconnaissance = AsyncMock(return_value={
            "findings": [
                {"type": "open_port", "port": 22},
                {"type": "open_port", "port": 80}
            ],
            "techniques": []
        })
        
        await observer._passive_reconnaissance(mock_client)
        
        # Verify reconnaissance was stored
        assert "reconnaissance" in observer.intelligence
        assert len(observer.intelligence["reconnaissance"]["findings"]) == 2
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_active_enumeration_phase(self, mock_get_config, mock_display):
        """Test active enumeration phase"""
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={})
        mock_get_config.return_value = mock_config
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        mock_client = AsyncMock()
        mock_client.enumerate_services = AsyncMock(return_value={
            "findings": [
                {"type": "api_endpoint", "path": "/api/users"}
            ],
            "techniques": []
        })
        
        await observer._active_enumeration(mock_client)
        
        # Verify enumeration was stored
        assert "enumeration" in observer.intelligence
        assert len(observer.intelligence["enumeration"]["findings"]) == 1
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_vulnerability_assessment_phase(self, mock_get_config, mock_display):
        """Test vulnerability assessment phase"""
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={})
        mock_get_config.return_value = mock_config
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        # Set up enumeration findings
        observer.intelligence["enumeration"] = {
            "findings": [
                {
                    "type": "vulnerability",
                    "severity": "high",
                    "title": "SQL Injection"
                },
                {
                    "type": "vulnerability",
                    "severity": "medium",
                    "title": "XSS"
                }
            ]
        }
        
        mock_client = AsyncMock()
        
        await observer._vulnerability_assessment(mock_client)
        
        # Phase should complete without errors
        assert True
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_generate_attack_plan_phase(self, mock_get_config, mock_display):
        """Test attack plan generation phase"""
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={})
        mock_get_config.return_value = mock_config
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        # Set up reconnaissance and enumeration data
        observer.intelligence["reconnaissance"] = {
            "findings": []
        }
        observer.intelligence["enumeration"] = {
            "findings": []
        }
        
        mock_client = AsyncMock()
        mock_client.get_ai_recommendation = AsyncMock(return_value={
            "recommendations": [
                {
                    "action": "test_action",
                    "confidence": 0.9,
                    "reasoning": "Test reasoning",
                    "risk_level": "LOW"
                }
            ]
        })
        
        await observer._generate_attack_plan(mock_client)
        
        # Verify attack plan was stored
        assert "attack_plan" in observer.intelligence
        assert len(observer.intelligence["attack_plan"]["recommendations"]) == 1


@pytest.mark.integration
class TestObserveModeReporting:
    """Test observe mode reporting functionality"""
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_generate_intelligence_report(self, mock_get_config, mock_display, temp_dir):
        """Test intelligence report generation"""
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={})
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        # Set up intelligence data
        observer.intelligence = {
            "operation_id": observer.operation_id,
            "target": "http://test.com",
            "mode": "observe",
            "duration_seconds": 120.5,
            "reconnaissance": {
                "findings": [],
                "techniques": []
            },
            "enumeration": {
                "findings": [
                    {
                        "type": "vulnerability",
                        "severity": "high",
                        "title": "Test Vulnerability",
                        "description": "Test description",
                        "recommendation": "Fix it"
                    }
                ],
                "techniques": []
            },
            "attack_plan": {
                "recommendations": []
            }
        }
        
        await observer._generate_intelligence_report()
        
        # Verify files were created
        assert (temp_dir / "logs").exists()
        assert (temp_dir / "reports").exists()
        
        # Verify at least one file of each type
        assert len(list((temp_dir / "logs").glob("*.json"))) > 0
        assert len(list((temp_dir / "reports").glob("*.html"))) > 0
    
    def test_risk_color_mapping(self):
        """Test risk level color mapping"""
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        assert observer._risk_color("LOW") == "green"
        assert observer._risk_color("MEDIUM") == "yellow"
        assert observer._risk_color("HIGH") == "red"
        assert observer._risk_color("CRITICAL") == "bold red"
        assert observer._risk_color("UNKNOWN") == "white"


@pytest.mark.integration
@pytest.mark.slow
class TestObserveModePerformance:
    """Performance tests for observe mode"""
    
    @pytest.mark.asyncio
    @patch('medusa.modes.observe.MedusaClient')
    @patch('medusa.modes.observe.display')
    @patch('medusa.modes.observe.get_config')
    async def test_observe_mode_completes_in_reasonable_time(self, mock_get_config, mock_display, mock_client_class, temp_dir):
        """Test that observe mode completes in reasonable time"""
        import time
        
        # Setup mocks
        mock_config = Mock()
        mock_config.get_llm_config = Mock(return_value={
            "api_key": "test-key",
            "mock_mode": True
        })
        mock_config.logs_dir = temp_dir / "logs"
        mock_config.reports_dir = temp_dir / "reports"
        mock_get_config.return_value = mock_config
        
        # Mock fast client
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client.perform_reconnaissance = AsyncMock(return_value={"findings": [], "techniques": []})
        mock_client.enumerate_services = AsyncMock(return_value={"findings": [], "techniques": []})
        mock_client.get_ai_recommendation = AsyncMock(return_value={"recommendations": []})
        mock_client_class.return_value = mock_client
        
        observer = ObserveMode(target="http://test.com", api_key="test-key")
        
        start_time = time.time()
        await observer.run()
        duration = time.time() - start_time
        
        # Should complete in under 30 seconds (with mocked sleep times)
        assert duration < 30


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

