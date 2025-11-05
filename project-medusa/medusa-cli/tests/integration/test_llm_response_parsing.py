"""
Integration tests for LLM response parsing
Tests various Gemini response types
"""
import pytest
import asyncio
from medusa.core.llm import LLMClient, LLMConfig
from pathlib import Path
import yaml

@pytest.fixture
def llm_config():
    """Load LLM config from user's config file"""
    config_path = Path.home() / ".medusa" / "config.yaml"
    if not config_path.exists():
        pytest.skip("No MEDUSA config found")

    with open(config_path) as f:
        config = yaml.safe_load(f)

    return LLMConfig(
        api_key=config['api_key'],
        model=config['llm']['model'],
        temperature=config['llm']['temperature'],
        max_tokens=config['llm']['max_tokens'],
        timeout=config['llm']['timeout'],
        max_retries=config['llm']['max_retries']
    )

@pytest.fixture
def llm_client(llm_config):
    """Create LLM client"""
    return LLMClient(llm_config)

@pytest.mark.asyncio
async def test_simple_text_response(llm_client):
    """Test simple single-part text response"""
    response = await llm_client._generate_with_retry(
        "Say 'test' and nothing else."
    )
    assert response is not None
    assert len(response) > 0
    assert 'test' in response.lower()

@pytest.mark.asyncio
async def test_multi_part_response(llm_client):
    """Test multi-part response handling"""
    response = await llm_client._generate_with_retry(
        "Describe port scanning in exactly two sentences."
    )
    assert response is not None
    assert len(response) > 20  # Should be substantial

@pytest.mark.asyncio
async def test_code_response(llm_client):
    """Test response containing code blocks"""
    response = await llm_client._generate_with_retry(
        "Show a simple Python function that says hello. Use markdown code blocks."
    )
    assert response is not None
    assert 'def' in response or 'hello' in response.lower()

@pytest.mark.asyncio
async def test_json_response(llm_client):
    """Test JSON response parsing"""
    response = await llm_client._generate_with_retry(
        "Return this exact JSON: {\"status\": \"ok\", \"value\": 42}"
    )
    assert response is not None
    assert 'status' in response or 'ok' in response

@pytest.mark.asyncio
async def test_long_response(llm_client):
    """Test handling of long responses"""
    response = await llm_client._generate_with_retry(
        "List 10 common web vulnerabilities with brief descriptions."
    )
    assert response is not None
    assert len(response) > 100

