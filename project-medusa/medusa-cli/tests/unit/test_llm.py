"""
Unit tests for LLM integration

Tests LLM client functionality with mock responses and error handling
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from medusa.core.llm import (
    LLMClient, MockLLMClient, LLMConfig, RiskLevel, create_llm_client
)


@pytest.mark.unit
class TestLLMConfig:
    """Test LLMConfig dataclass"""
    
    def test_llm_config_creation(self, mock_api_key):
        """Test creating LLMConfig with default values"""
        config = LLMConfig(api_key=mock_api_key)
        
        assert config.api_key == mock_api_key
        assert config.model == "gemini-pro"
        assert config.temperature == 0.7
        assert config.max_tokens == 2048
        assert config.timeout == 30
        assert config.max_retries == 3
        assert config.mock_mode is False
    
    def test_llm_config_with_custom_values(self):
        """Test LLMConfig with custom values"""
        config = LLMConfig(
            api_key="custom-key",
            model="gemini-1.5-pro",
            temperature=0.9,
            max_tokens=4096,
            timeout=60,
            max_retries=5,
            mock_mode=True
        )
        
        assert config.model == "gemini-1.5-pro"
        assert config.temperature == 0.9
        assert config.max_tokens == 4096
        assert config.timeout == 60
        assert config.max_retries == 5
        assert config.mock_mode is True


@pytest.mark.unit
class TestMockLLMClient:
    """Test MockLLMClient functionality"""
    
    @pytest.mark.asyncio
    async def test_mock_client_initialization(self, mock_llm_config):
        """Test MockLLMClient initializes correctly"""
        client = MockLLMClient(mock_llm_config)
        
        # MockLLMClient preserves the config it receives
        assert client.config.mock_mode is True
        assert client.config is not None
    
    @pytest.mark.asyncio
    async def test_reconnaissance_recommendation(self, mock_llm_client):
        """Test mock reconnaissance recommendation"""
        result = await mock_llm_client.get_reconnaissance_recommendation(
            "192.168.1.100",
            {"phase": "initial"}
        )
        
        assert "recommended_actions" in result
        assert "focus_areas" in result
        assert "risk_assessment" in result
        assert "estimated_duration" in result
        
        # Verify structure of actions
        actions = result["recommended_actions"]
        assert len(actions) > 0
        assert "action" in actions[0]
        assert "command" in actions[0]
        assert "technique_id" in actions[0]
    
    @pytest.mark.asyncio
    async def test_enumeration_recommendation(self, mock_llm_client, mock_scan_results):
        """Test mock enumeration recommendation"""
        result = await mock_llm_client.get_enumeration_recommendation(
            "192.168.1.100",
            [mock_scan_results]
        )
        
        assert "recommended_actions" in result
        assert "services_to_probe" in result
        assert "risk_assessment" in result
        assert "potential_vulnerabilities" in result
    
    @pytest.mark.asyncio
    async def test_assess_vulnerability_risk(self, mock_llm_client, mock_vulnerability):
        """Test mock vulnerability risk assessment"""
        risk = await mock_llm_client.assess_vulnerability_risk(mock_vulnerability)
        
        assert risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    @pytest.mark.asyncio
    async def test_assess_vulnerability_risk_sql_injection(self, mock_llm_client):
        """Test risk assessment identifies SQL injection as HIGH"""
        vuln = {
            "type": "sql injection",
            "severity": "HIGH"
        }
        
        risk = await mock_llm_client.assess_vulnerability_risk(vuln)
        
        assert risk == "HIGH"
    
    @pytest.mark.asyncio
    async def test_plan_attack_strategy(self, mock_llm_client):
        """Test mock attack strategy planning"""
        findings = [
            {"type": "open_port", "port": 80},
            {"type": "vulnerability", "name": "SQL Injection"}
        ]
        
        result = await mock_llm_client.plan_attack_strategy(
            "192.168.1.100",
            findings,
            ["data_access", "privilege_escalation"]
        )
        
        assert "strategy_overview" in result
        assert "attack_chain" in result
        assert "success_probability" in result
        assert "estimated_duration" in result
        assert "risks" in result
        
        # Verify attack chain structure
        chain = result["attack_chain"]
        assert len(chain) > 0
        assert "step" in chain[0]
        assert "action" in chain[0]
        assert "risk_level" in chain[0]
    
    @pytest.mark.asyncio
    async def test_get_next_action_recommendation(self, mock_llm_client):
        """Test mock next action recommendation"""
        context = {
            "phase": "enumeration",
            "current_phase": "enumeration",
            "findings": []
        }
        
        result = await mock_llm_client.get_next_action_recommendation(context)
        
        assert "recommendations" in result
        assert "context_analysis" in result
        assert "suggested_next_phase" in result
        
        # Verify recommendations structure
        recommendations = result["recommendations"]
        assert len(recommendations) > 0
        assert "action" in recommendations[0]
        assert "confidence" in recommendations[0]
        assert "reasoning" in recommendations[0]


@pytest.mark.unit
@patch('medusa.core.llm.GEMINI_AVAILABLE', True)
class TestLLMClient:
    """Test real LLMClient functionality (with mocked API calls)"""
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_llm_client_initialization(self, mock_model_class, mock_configure, mock_llm_config):
        """Test LLMClient initializes correctly"""
        client = LLMClient(mock_llm_config)
        
        # Verify Gemini was configured with API key
        mock_configure.assert_called_once_with(api_key=mock_llm_config.api_key)
        
        # Verify model was created
        mock_model_class.assert_called_once()
    
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_llm_client_initialization_without_gemini(self, mock_model_class, mock_configure, mock_llm_config):
        """Test LLMClient raises error when google-generativeai not available"""
        with patch('medusa.core.llm.GEMINI_AVAILABLE', False):
            with pytest.raises(ImportError, match="google-generativeai is required"):
                LLMClient(mock_llm_config)
    
    @pytest.mark.asyncio
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    async def test_generate_with_retry_success(self, mock_model_class, mock_configure, mock_llm_config):
        """Test _generate_with_retry succeeds on first attempt"""
        # Setup mock response
        mock_response = Mock()
        mock_response.text = '{"action": "test"}'
        
        mock_model = Mock()
        mock_model.generate_content = Mock(return_value=mock_response)
        mock_model_class.return_value = mock_model
        
        client = LLMClient(mock_llm_config)
        
        # Mock asyncio.wait_for to avoid actual async execution
        with patch('asyncio.wait_for', new_callable=AsyncMock) as mock_wait:
            mock_wait.return_value = mock_response
            
            result = await client._generate_with_retry("test prompt")
            
            assert result == '{"action": "test"}'
    
    @pytest.mark.asyncio
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    async def test_generate_with_retry_fails_all_attempts(self, mock_model_class, mock_configure, mock_llm_config):
        """Test _generate_with_retry fails after max retries"""
        mock_model_class.return_value = Mock()
        
        client = LLMClient(mock_llm_config)
        
        # Mock to always timeout
        with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError()):
            with pytest.raises(Exception, match="LLM request failed after"):
                await client._generate_with_retry("test prompt")
    
    def test_extract_json_from_response_direct_json(self):
        """Test extracting JSON from direct JSON response"""
        config = LLMConfig(api_key="test", mock_mode=True)
        
        with patch('google.generativeai.configure'):
            with patch('google.generativeai.GenerativeModel'):
                with patch('medusa.core.llm.GEMINI_AVAILABLE', True):
                    client = LLMClient(config)
                    
                    response = '{"action": "test", "risk": "LOW"}'
                    result = client._extract_json_from_response(response)
                    
                    assert result["action"] == "test"
                    assert result["risk"] == "LOW"
    
    def test_extract_json_from_markdown_code_block(self):
        """Test extracting JSON from markdown code block"""
        config = LLMConfig(api_key="test", mock_mode=True)
        
        with patch('google.generativeai.configure'):
            with patch('google.generativeai.GenerativeModel'):
                with patch('medusa.core.llm.GEMINI_AVAILABLE', True):
                    client = LLMClient(config)
                    
                    response = '''```json
                    {"action": "test", "risk": "LOW"}
                    ```'''
                    result = client._extract_json_from_response(response)
                    
                    assert result["action"] == "test"
                    assert result["risk"] == "LOW"
    
    def test_extract_json_invalid_response(self):
        """Test extracting JSON from invalid response raises error"""
        config = LLMConfig(api_key="test", mock_mode=True)
        
        with patch('google.generativeai.configure'):
            with patch('google.generativeai.GenerativeModel'):
                with patch('medusa.core.llm.GEMINI_AVAILABLE', True):
                    client = LLMClient(config)
                    
                    with pytest.raises(ValueError, match="Invalid JSON response"):
                        client._extract_json_from_response("not valid json at all")


@pytest.mark.unit
class TestLLMClientFallbacks:
    """Test LLM client fallback methods"""
    
    def test_fallback_reconnaissance(self, mock_llm_client):
        """Test fallback reconnaissance returns valid structure"""
        result = mock_llm_client._get_fallback_reconnaissance()
        
        assert "recommended_actions" in result
        assert "focus_areas" in result
        assert "risk_assessment" in result
        assert result["risk_assessment"] == "LOW"
    
    def test_fallback_enumeration(self, mock_llm_client):
        """Test fallback enumeration returns valid structure"""
        result = mock_llm_client._get_fallback_enumeration()
        
        assert "recommended_actions" in result
        assert "services_to_probe" in result
        assert "risk_assessment" in result
    
    def test_fallback_risk_assessment(self, mock_llm_client):
        """Test fallback risk assessment maps severity correctly"""
        test_cases = [
            ({"severity": "CRITICAL"}, "CRITICAL"),
            ({"severity": "HIGH"}, "HIGH"),
            ({"severity": "MEDIUM"}, "MEDIUM"),
            ({"severity": "LOW"}, "LOW"),
            ({"severity": "UNKNOWN"}, "MEDIUM"),  # Default
        ]
        
        for vuln, expected_risk in test_cases:
            risk = mock_llm_client._get_fallback_risk_assessment(vuln)
            assert risk == expected_risk
    
    def test_fallback_attack_plan(self, mock_llm_client):
        """Test fallback attack plan returns valid structure"""
        result = mock_llm_client._get_fallback_attack_plan()
        
        assert "strategy_overview" in result
        assert "attack_chain" in result
        assert "success_probability" in result
        assert len(result["attack_chain"]) > 0
    
    def test_fallback_next_action(self, mock_llm_client):
        """Test fallback next action returns valid structure"""
        result = mock_llm_client._get_fallback_next_action()
        
        assert "recommendations" in result
        assert "context_analysis" in result
        assert "suggested_next_phase" in result


@pytest.mark.unit
class TestCreateLLMClient:
    """Test create_llm_client factory function"""
    
    def test_create_mock_client_when_mock_mode(self, mock_llm_config):
        """Test factory creates MockLLMClient when mock_mode is True"""
        client = create_llm_client(mock_llm_config)
        
        assert isinstance(client, MockLLMClient)
    
    @patch('medusa.core.llm.GEMINI_AVAILABLE', False)
    def test_create_mock_client_when_gemini_unavailable(self, mock_llm_config):
        """Test factory creates MockLLMClient when Gemini not available"""
        mock_llm_config.mock_mode = False
        client = create_llm_client(mock_llm_config)
        
        assert isinstance(client, MockLLMClient)
    
    @patch('medusa.core.llm.GEMINI_AVAILABLE', True)
    @patch('google.generativeai.configure')
    @patch('google.generativeai.GenerativeModel')
    def test_create_real_client_when_available(self, mock_model, mock_configure, mock_llm_config):
        """Test factory creates real LLMClient when Gemini available"""
        mock_llm_config.mock_mode = False
        client = create_llm_client(mock_llm_config)
        
        assert isinstance(client, LLMClient)
    
    @patch('medusa.core.llm.GEMINI_AVAILABLE', True)
    @patch('google.generativeai.configure', side_effect=Exception("API error"))
    def test_create_mock_client_on_initialization_error(self, mock_configure, mock_llm_config):
        """Test factory falls back to MockLLMClient on initialization error"""
        mock_llm_config.mock_mode = False
        client = create_llm_client(mock_llm_config)
        
        # Should fallback to mock client
        assert isinstance(client, MockLLMClient)


@pytest.mark.unit
class TestRiskLevelEnum:
    """Test RiskLevel enum"""
    
    def test_risk_level_values(self):
        """Test RiskLevel enum values"""
        assert RiskLevel.LOW == "LOW"
        assert RiskLevel.MEDIUM == "MEDIUM"
        assert RiskLevel.HIGH == "HIGH"
        assert RiskLevel.CRITICAL == "CRITICAL"


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.requires_api
class TestRealLLMIntegration:
    """Integration tests with real Gemini API (requires API key)"""
    
    @pytest.mark.asyncio
    async def test_real_llm_reconnaissance(self):
        """Test real LLM reconnaissance (requires API key)"""
        import os
        api_key = os.getenv("GEMINI_API_KEY")
        
        if not api_key:
            pytest.skip("GEMINI_API_KEY not set")
        
        config = LLMConfig(api_key=api_key, mock_mode=False)
        client = create_llm_client(config)
        
        result = await client.get_reconnaissance_recommendation(
            "http://example.com",
            {"environment": "web application"}
        )
        
        assert "recommended_actions" in result
        assert isinstance(result["recommended_actions"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

