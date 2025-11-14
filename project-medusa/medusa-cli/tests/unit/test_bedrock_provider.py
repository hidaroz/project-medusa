"""
Unit tests for BedrockProvider
Tests cost tracking, model selection, error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


@pytest.fixture
def mock_config():
    """Create a mock LLMConfig"""
    from medusa.core.llm.config import LLMConfig
    config = LLMConfig()
    config.cloud_model = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    config.aws_region = "us-west-2"
    return config


def test_bedrock_provider_initialization(mock_config):
    """Test BedrockProvider initializes correctly"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(config=mock_config)
        assert provider.model == "anthropic.claude-3-5-sonnet-20241022-v2:0"
        assert provider.config == mock_config


def test_bedrock_cost_calculation_sonnet(mock_config):
    """Test cost calculation is accurate for Sonnet"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(config=mock_config)

        # Test Sonnet pricing: $3/$15 per 1M tokens
        cost = provider._calculate_cost(
            input_tokens=1000,  # 1K tokens
            output_tokens=500   # 0.5K tokens
        )

        # Expected: (1000/1M * $3) + (500/1M * $15) = $0.003 + $0.0075 = $0.0105
        expected = (1000/1_000_000 * 3.00) + (500/1_000_000 * 15.00)
        assert abs(cost - expected) < 0.0001, f"Expected {expected}, got {cost}"


def test_bedrock_cost_calculation_haiku():
    """Test Haiku has correct pricing"""
    from medusa.core.llm.providers.bedrock import BedrockProvider
    from medusa.core.llm.config import LLMConfig

    config = LLMConfig()
    config.cloud_model = "anthropic.claude-3-5-haiku-20241022-v1:0"

    with patch('boto3.client'):
        provider = BedrockProvider(config=config)

        # Test Haiku pricing: $0.80/$4 per 1M tokens
        cost = provider._calculate_cost(
            input_tokens=1000,
            output_tokens=500
        )

        # Expected: (1000/1M * $0.80) + (500/1M * $4) = $0.0008 + $0.002 = $0.0028
        expected = (1000/1_000_000 * 0.80) + (500/1_000_000 * 4.00)
        assert abs(cost - expected) < 0.0001, f"Expected {expected}, got {cost}"


def test_bedrock_cost_large_tokens(mock_config):
    """Test cost calculation with large token counts"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(config=mock_config)

        # Large token count
        cost = provider._calculate_cost(
            input_tokens=100_000,   # 100K tokens
            output_tokens=50_000    # 50K tokens
        )

        # Expected: (100K/1M * $3) + (50K/1M * $15) = $0.30 + $0.75 = $1.05
        expected = (100_000/1_000_000 * 3.00) + (50_000/1_000_000 * 15.00)
        assert abs(cost - expected) < 0.0001, f"Expected {expected}, got {cost}"


def test_bedrock_pricing_table_exists():
    """Test BedrockProvider has pricing table"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    assert hasattr(BedrockProvider, 'PRICING')
    assert isinstance(BedrockProvider.PRICING, dict)

    # Check Sonnet pricing exists
    assert "anthropic.claude-3-5-sonnet-20241022-v2:0" in BedrockProvider.PRICING
    sonnet_pricing = BedrockProvider.PRICING["anthropic.claude-3-5-sonnet-20241022-v2:0"]
    assert "input" in sonnet_pricing
    assert "output" in sonnet_pricing
    assert sonnet_pricing["input"] == 3.00
    assert sonnet_pricing["output"] == 15.00

    # Check Haiku pricing exists
    assert "anthropic.claude-3-5-haiku-20241022-v1:0" in BedrockProvider.PRICING
    haiku_pricing = BedrockProvider.PRICING["anthropic.claude-3-5-haiku-20241022-v1:0"]
    assert haiku_pricing["input"] == 0.80
    assert haiku_pricing["output"] == 4.00


def test_bedrock_handles_missing_model_in_pricing():
    """Test BedrockProvider handles unknown models gracefully"""
    from medusa.core.llm.providers.bedrock import BedrockProvider
    from medusa.core.llm.config import LLMConfig

    config = LLMConfig()
    config.cloud_model = "unknown-model-id"

    with patch('boto3.client'):
        provider = BedrockProvider(config=config)

        # Should return 0 cost for unknown models (fallback)
        cost = provider._calculate_cost(
            input_tokens=1000,
            output_tokens=500
        )

        assert cost == 0.0, "Unknown model should have 0 cost"


def test_bedrock_tracks_total_cost(mock_config):
    """Test BedrockProvider tracks cumulative cost"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(config=mock_config)

        # Initial cost should be 0
        assert provider.total_cost == 0.0
        assert provider.total_input_tokens == 0
        assert provider.total_output_tokens == 0


def test_bedrock_provider_name(mock_config):
    """Test BedrockProvider has correct provider name"""
    from medusa.core.llm.providers.bedrock import BedrockProvider

    with patch('boto3.client'):
        provider = BedrockProvider(config=mock_config)
        assert BedrockProvider.PROVIDER_NAME == "bedrock"


def test_bedrock_uses_config_region():
    """Test BedrockProvider uses region from config"""
    from medusa.core.llm.providers.bedrock import BedrockProvider
    from medusa.core.llm.config import LLMConfig

    config = LLMConfig()
    config.aws_region = "us-east-1"

    with patch('boto3.client') as mock_client:
        provider = BedrockProvider(config=config)

        # Should have called boto3.client with region
        mock_client.assert_called_once()
        call_kwargs = mock_client.call_args[1]
        assert call_kwargs['region_name'] == 'us-east-1'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])