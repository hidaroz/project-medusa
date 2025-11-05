"""
Unit tests for LocalLLMClient.

Tests the local LLM implementation without requiring actual Ollama instance
(using mocks where appropriate).
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, AsyncMock
from medusa.core.llm import LocalLLMClient, LLMConfig, LLMError


@pytest.fixture
def local_llm_config():
    """Create test configuration for local LLM"""
    return LLMConfig(
        provider="local",
        model="mistral:7b-instruct",
        ollama_url="http://localhost:11434",
        timeout=30
    )


@pytest.fixture
def mock_ollama_response():
    """Mock successful Ollama API response"""
    return {
        "model": "mistral:7b-instruct",
        "created_at": "2024-11-04T12:00:00Z",
        "response": '{"recommended_actions": [{"action": "port_scan", "technique_id": "T1046", "priority": "high"}], "risk_assessment": "LOW"}',
        "done": True
    }


class TestLocalLLMClientInitialization:
    """Test client initialization and configuration"""
    
    def test_init_with_defaults(self, local_llm_config):
        """Test initialization with default config"""
        client = LocalLLMClient(local_llm_config)
        
        assert client.model == "mistral:7b-instruct"
        assert client.base_url == "http://localhost:11434"
        assert client.config.timeout == 30
    
    def test_init_with_custom_model(self):
        """Test initialization with custom model"""
        config = LLMConfig(provider="local", model="llama3:8b")
        client = LocalLLMClient(config)
        
        assert client.model == "llama3:8b"
    
    def test_init_with_custom_url(self):
        """Test initialization with custom Ollama URL"""
        config = LLMConfig(
            provider="local",
            ollama_url="http://192.168.1.100:11434"
        )
        client = LocalLLMClient(config)
        
        assert client.base_url == "http://192.168.1.100:11434"


class TestOllamaHealthCheck:
    """Test Ollama server health checking"""
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, local_llm_config):
        """Test successful health check"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'get', new_callable=AsyncMock) as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "models": [
                    {"name": "mistral:7b-instruct"},
                    {"name": "llama3:8b"}
                ]
            }
            mock_get.return_value = mock_response
            
            is_healthy = await client._check_ollama_health()
            
            assert is_healthy is True
            mock_get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_health_check_model_not_found(self, local_llm_config):
        """Test health check when model not available"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'get', new_callable=AsyncMock) as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "models": [
                    {"name": "llama3:8b"}  # mistral not in list
                ]
            }
            mock_get.return_value = mock_response
            
            is_healthy = await client._check_ollama_health()
            
            assert is_healthy is False
    
    @pytest.mark.asyncio
    async def test_health_check_server_down(self, local_llm_config):
        """Test health check when Ollama server not responding"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'get', new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = Exception("Connection refused")
            
            is_healthy = await client._check_ollama_health()
            
            assert is_healthy is False


class TestGenerateWithRetry:
    """Test LLM generation with retry logic"""
    
    @pytest.mark.asyncio
    async def test_generate_success(self, local_llm_config, mock_ollama_response):
        """Test successful generation"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_ollama_response
            mock_post.return_value = mock_response
            
            result = await client._generate_with_retry("Test prompt", force_json=True)
            
            assert isinstance(result, str)
            assert len(result) > 0
            assert client.metrics.successful_requests == 1
    
    @pytest.mark.asyncio
    async def test_generate_with_retry_on_timeout(self, local_llm_config):
        """Test retry logic on timeout"""
        config = LLMConfig(provider="local", timeout=1, max_retries=2)
        client = LocalLLMClient(config)
        
        with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
            import httpx
            mock_post.side_effect = httpx.TimeoutException("Timeout")
            
            with pytest.raises(LLMError, match="timeout"):
                await client._generate_with_retry("Test prompt")
            
            # Should have retried
            assert mock_post.call_count == 2
            assert client.metrics.failed_requests == 1
    
    @pytest.mark.asyncio
    async def test_generate_ollama_not_running(self, local_llm_config):
        """Test error when Ollama not running"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
            import httpx
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.json.return_value = {}
            mock_response.text = "Not Found"
            
            error = httpx.HTTPStatusError("Not found", request=Mock(), response=mock_response)
            mock_post.side_effect = error
            
            with pytest.raises(LLMError, match="Cannot connect to Ollama"):
                await client._generate_with_retry("Test prompt")
    
    @pytest.mark.asyncio
    async def test_generate_model_not_found(self, local_llm_config):
        """Test error when model not available"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
            import httpx
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.json.return_value = {"error": "model not found"}
            mock_response.text = "model not found"
            
            error = httpx.HTTPStatusError("Model not found", request=Mock(), response=mock_response)
            mock_post.side_effect = error
            
            with pytest.raises(LLMError, match="not found"):
                await client._generate_with_retry("Test prompt")


class TestLLMFunctions:
    """Test high-level LLM functions"""
    
    @pytest.mark.asyncio
    async def test_get_reconnaissance_recommendation(self, local_llm_config):
        """Test reconnaissance recommendation generation"""
        client = LocalLLMClient(local_llm_config)
        
        mock_response = {
            "recommended_actions": [
                {
                    "action": "port_scan",
                    "technique_id": "T1046",
                    "priority": "high",
                    "reasoning": "Identify open services"
                }
            ],
            "focus_areas": ["network_services"],
            "risk_assessment": "LOW"
        }
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = json.dumps(mock_response)
            
            result = await client.get_reconnaissance_recommendation(
                target="10.0.0.1",
                context={"environment": "internal"}
            )
            
            assert "recommended_actions" in result
            assert "risk_assessment" in result
            assert result["risk_assessment"] == "LOW"
            assert len(result["recommended_actions"]) > 0
    
    @pytest.mark.asyncio
    async def test_get_enumeration_recommendation(self, local_llm_config):
        """Test enumeration recommendation generation"""
        client = LocalLLMClient(local_llm_config)
        
        mock_response = {
            "recommended_actions": [
                {
                    "action": "enumerate_api_endpoints",
                    "technique_id": "T1590",
                    "priority": "high"
                }
            ],
            "services_to_probe": ["http", "https"],
            "risk_assessment": "LOW"
        }
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = json.dumps(mock_response)
            
            result = await client.get_enumeration_recommendation(
                target="10.0.0.1",
                reconnaissance_findings=[{"type": "open_port", "port": 80}]
            )
            
            assert "recommended_actions" in result
            assert "services_to_probe" in result
    
    @pytest.mark.asyncio
    async def test_assess_vulnerability_risk(self, local_llm_config):
        """Test vulnerability risk assessment"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = "HIGH"
            
            risk = await client.assess_vulnerability_risk(
                vulnerability={"type": "SQL Injection", "severity": "high"},
                target_context={"environment": "production"}
            )
            
            assert risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            assert risk == "HIGH"
    
    @pytest.mark.asyncio
    async def test_assess_vulnerability_risk_invalid_response(self, local_llm_config):
        """Test risk assessment with invalid response defaults to MEDIUM"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = "INVALID_LEVEL"
            
            risk = await client.assess_vulnerability_risk(
                vulnerability={"type": "Unknown"},
                target_context={}
            )
            
            # Should default to MEDIUM
            assert risk == "MEDIUM"
    
    @pytest.mark.asyncio
    async def test_plan_attack_strategy(self, local_llm_config):
        """Test attack strategy planning"""
        client = LocalLLMClient(local_llm_config)
        
        mock_response = {
            "strategy_overview": "Multi-stage attack",
            "attack_chain": [
                {
                    "step": 1,
                    "action": "exploit_sqli",
                    "technique_id": "T1190"
                }
            ]
        }
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = json.dumps(mock_response)
            
            result = await client.plan_attack_strategy(
                target="example.com",
                findings=[{"type": "SQL Injection"}],
                objectives=["data_access"]
            )
            
            assert "attack_chain" in result
            assert len(result["attack_chain"]) > 0
    
    @pytest.mark.asyncio
    async def test_parse_natural_language_command(self, local_llm_config):
        """Test natural language parsing"""
        client = LocalLLMClient(local_llm_config)
        
        mock_response = {
            "understanding": "User wants to scan ports",
            "action": "port_scan",
            "parameters": {"target": "localhost"},
            "confidence": 0.95
        }
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = json.dumps(mock_response)
            
            result = await client.parse_natural_language_command(
                user_input="scan the target",
                context={"target": "localhost"}
            )
            
            assert "action" in result
            assert result["action"] == "port_scan"
    
    @pytest.mark.asyncio
    async def test_get_next_action_recommendation(self, local_llm_config):
        """Test next action recommendation"""
        client = LocalLLMClient(local_llm_config)
        
        mock_response = {
            "recommendations": [
                {
                    "action": "enumerate_endpoints",
                    "confidence": 0.9,
                    "risk_level": "LOW"
                }
            ],
            "context_analysis": "Continue enumeration"
        }
        
        with patch.object(client, '_generate_with_retry', new_callable=AsyncMock) as mock_gen:
            mock_gen.return_value = json.dumps(mock_response)
            
            result = await client.get_next_action_recommendation(
                context={"phase": "enumeration"}
            )
            
            assert "recommendations" in result
            assert len(result["recommendations"]) > 0


class TestJSONExtraction:
    """Test JSON extraction from responses"""
    
    def test_extract_valid_json(self, local_llm_config):
        """Test extraction of valid JSON"""
        client = LocalLLMClient(local_llm_config)
        
        response = '{"action": "scan", "priority": "high"}'
        result = client._extract_json_from_response(response)
        
        assert result["action"] == "scan"
        assert result["priority"] == "high"
    
    def test_extract_json_from_markdown(self, local_llm_config):
        """Test extraction from markdown code block"""
        client = LocalLLMClient(local_llm_config)
        
        response = '```json\n{"action": "scan"}\n```'
        result = client._extract_json_from_response(response)
        
        assert result["action"] == "scan"
    
    def test_extract_json_with_extra_text(self, local_llm_config):
        """Test extraction with surrounding text"""
        client = LocalLLMClient(local_llm_config)
        
        response = 'Here is the result: {"action": "scan"} as requested'
        result = client._extract_json_from_response(response)
        
        assert result["action"] == "scan"
    
    def test_extract_invalid_json_raises_error(self, local_llm_config):
        """Test that invalid JSON raises ValueError"""
        client = LocalLLMClient(local_llm_config)
        
        response = "This is not JSON at all"
        with pytest.raises(ValueError, match="Invalid JSON"):
            client._extract_json_from_response(response)


class TestMetrics:
    """Test metrics tracking"""
    
    @pytest.mark.asyncio
    async def test_metrics_tracking(self, local_llm_config, mock_ollama_response):
        """Test that metrics are properly tracked"""
        client = LocalLLMClient(local_llm_config)
        
        with patch.object(client.client, 'post', new_callable=AsyncMock) as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_ollama_response
            mock_post.return_value = mock_response
            
            await client._generate_with_retry("Test prompt")
            
            metrics = client.get_metrics()
            assert metrics["total_requests"] == 1
            assert metrics["successful_requests"] == 1
            assert metrics["failed_requests"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

