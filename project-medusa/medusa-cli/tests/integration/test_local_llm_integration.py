"""
Integration tests for LocalLLMClient.

These tests require:
- Ollama running locally
- mistral:7b-instruct model pulled

Skip these tests if Ollama not available.
"""

import pytest
import asyncio
import os

try:
    import httpx
except ImportError:
    httpx = None

from medusa.core.llm import LocalLLMClient, LLMConfig, create_llm_client


def is_ollama_available() -> bool:
    """Check if Ollama server is running"""
    if httpx is None:
        return False
    
    try:
        response = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
        return response.status_code == 200
    except:
        return False


# Skip all tests in this file if Ollama not available
pytestmark = pytest.mark.skipif(
    not is_ollama_available(),
    reason="Ollama server not available"
)


@pytest.fixture
def integration_config():
    """Config for integration tests"""
    return LLMConfig(
        provider="local",
        model="mistral:7b-instruct",
        timeout=60
    )


class TestRealOllamaIntegration:
    """Test against real Ollama instance"""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_health_check(self, integration_config):
        """Test real health check"""
        client = LocalLLMClient(integration_config)
        is_healthy = await client._check_ollama_health()
        
        assert is_healthy is True
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_basic_generation(self, integration_config):
        """Test basic text generation"""
        client = LocalLLMClient(integration_config)
        
        response = await client._generate_with_retry(
            "Respond with exactly: SUCCESS",
            force_json=False
        )
        
        assert len(response) > 0
        assert "SUCCESS" in response.upper()
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_json_mode(self, integration_config):
        """Test JSON mode enforcement"""
        client = LocalLLMClient(integration_config)
        
        response = await client._generate_with_retry(
            'Output this JSON: {"status": "ok", "value": 42}',
            force_json=True
        )
        
        # Should be valid JSON
        import json
        parsed = json.loads(response)
        assert isinstance(parsed, dict)
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_reconnaissance_recommendation(self, integration_config):
        """Test real reconnaissance recommendation"""
        client = LocalLLMClient(integration_config)
        
        result = await client.get_reconnaissance_recommendation(
            target="192.168.1.1",
            context={"environment": "internal_network"}
        )
        
        # Validate structure
        assert "recommended_actions" in result
        assert "risk_assessment" in result
        assert isinstance(result["recommended_actions"], list)
        assert len(result["recommended_actions"]) > 0
        
        # Validate first action
        first_action = result["recommended_actions"][0]
        assert "action" in first_action
        assert "technique_id" in first_action
        assert "priority" in first_action
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_risk_assessment(self, integration_config):
        """Test real vulnerability risk assessment"""
        client = LocalLLMClient(integration_config)
        
        risk = await client.assess_vulnerability_risk(
            vulnerability={
                "type": "SQL Injection",
                "severity": "high",
                "url": "http://example.com/login"
            },
            target_context={"environment": "production"}
        )
        
        assert risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_attack_strategy_planning(self, integration_config):
        """Test real attack strategy generation"""
        client = LocalLLMClient(integration_config)
        
        result = await client.plan_attack_strategy(
            target="example.com",
            findings=[
                {
                    "type": "SQL Injection",
                    "severity": "high",
                    "url": "http://example.com/search?q="
                }
            ],
            objectives=["initial_access", "data_exfiltration"]
        )
        
        assert "attack_chain" in result
        assert isinstance(result["attack_chain"], list)
        assert len(result["attack_chain"]) > 0
        
        first_step = result["attack_chain"][0]
        assert "action" in first_step
        assert "technique_id" in first_step
        assert "step" in first_step
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_enumeration_recommendation(self, integration_config):
        """Test real enumeration recommendation"""
        client = LocalLLMClient(integration_config)
        
        result = await client.get_enumeration_recommendation(
            target="example.com",
            reconnaissance_findings=[
                {"type": "open_port", "port": 80, "service": "http"},
                {"type": "open_port", "port": 443, "service": "https"}
            ]
        )
        
        assert "recommended_actions" in result
        assert isinstance(result["recommended_actions"], list)
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_natural_language_parsing(self, integration_config):
        """Test real natural language parsing"""
        client = LocalLLMClient(integration_config)
        
        result = await client.parse_natural_language_command(
            user_input="scan the web server for vulnerabilities",
            context={"target": "example.com"}
        )
        
        assert "action" in result
        assert "confidence" in result
        assert isinstance(result["confidence"], (int, float))
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_next_action_recommendation(self, integration_config):
        """Test real next action recommendation"""
        client = LocalLLMClient(integration_config)
        
        result = await client.get_next_action_recommendation(
            context={
                "phase": "enumeration",
                "findings": [
                    {"type": "open_port", "port": 80}
                ]
            }
        )
        
        assert "recommendations" in result
        assert isinstance(result["recommendations"], list)


class TestFactoryPatternIntegration:
    """Test factory pattern with real Ollama"""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_create_local_client(self):
        """Test factory creates local client"""
        config = LLMConfig(provider="local", model="mistral:7b-instruct")
        client = create_llm_client(config)
        
        assert isinstance(client, LocalLLMClient)
        
        # Test it works
        response = await client._generate_with_retry("Say: OK", force_json=False)
        assert len(response) > 0
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_auto_detect_local(self):
        """Test auto-detection finds local LLM"""
        config = LLMConfig(provider="auto")
        client = create_llm_client(config)
        
        # Should auto-detect and use LocalLLMClient
        assert isinstance(client, LocalLLMClient)


class TestPerformance:
    """Performance benchmarks"""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.slow
    async def test_response_time_benchmark(self, integration_config):
        """Benchmark average response time"""
        client = LocalLLMClient(integration_config)
        
        times = []
        for i in range(3):  # Reduced to 3 for faster test
            import time
            start = time.time()
            
            await client.get_reconnaissance_recommendation(
                target=f"10.0.0.{i}",
                context={"environment": "test"}
            )
            
            elapsed = time.time() - start
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        print(f"\nAverage response time: {avg_time:.2f}s")
        print(f"Min: {min(times):.2f}s, Max: {max(times):.2f}s")
        
        # Should complete in reasonable time (adjust based on hardware)
        assert avg_time < 60  # 60 seconds is acceptable for pentesting
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_concurrent_requests(self, integration_config):
        """Test handling concurrent requests"""
        client = LocalLLMClient(integration_config)
        
        # Run 3 concurrent requests
        tasks = [
            client.get_reconnaissance_recommendation(f"10.0.0.{i}", {})
            for i in range(3)
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 3
        for result in results:
            assert "recommended_actions" in result


class TestErrorHandling:
    """Test error handling with real Ollama"""
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_timeout_handling(self):
        """Test handling of timeouts"""
        # Use very short timeout to force timeout
        config = LLMConfig(
            provider="local",
            timeout=0.1,  # 100ms - too short
            max_retries=1
        )
        client = LocalLLMClient(config)
        
        with pytest.raises(Exception):  # Should timeout
            await client.get_reconnaissance_recommendation(
                target="test.com",
                context={}
            )
    
    @pytest.mark.asyncio
    @pytest.mark.integration
    async def test_invalid_model_handling(self):
        """Test handling of invalid model name"""
        config = LLMConfig(
            provider="local",
            model="nonexistent-model:latest"
        )
        
        # Factory should raise error when checking health
        with pytest.raises(Exception):
            create_llm_client(config)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

