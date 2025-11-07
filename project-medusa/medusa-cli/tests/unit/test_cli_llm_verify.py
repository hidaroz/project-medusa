"""
Unit tests for the CLI LLM verify command

Tests the `medusa llm verify` command with:
- Configuration checking
- LLM health check
- Provider-specific error messaging
- Proper exit codes
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typer.testing import CliRunner

from medusa.cli import app
from medusa.core.llm import LLMConfig, LLMClient


@pytest.fixture
def cli_runner():
    """Create a Typer CLI test runner"""
    return CliRunner()


class TestLLMVerifyCommand:
    """Test suite for llm verify command"""
    
    def test_llm_verify_without_configuration(self, cli_runner, temp_dir, monkeypatch):
        """Test that llm verify fails gracefully when config doesn't exist"""
        # Mock config to return non-existent path
        def mock_get_config():
            from medusa.config import Config
            config = Config(config_dir=temp_dir / "nonexistent")
            return config
        
        from medusa import cli
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        
        result = cli_runner.invoke(app, ["llm", "verify"])
        
        assert result.exit_code == 1
        assert "MEDUSA is not configured" in result.stdout
        assert "medusa setup" in result.stdout
    
    def test_llm_verify_successful_local_provider(self, cli_runner, temp_dir, monkeypatch):
        """Test llm verify with successful local provider health check"""
        # Create temporary config
        config_file = temp_dir / "config.yaml"
        config_content = """
llm:
  provider: local
  local_model: mistral:7b-instruct
  ollama_url: http://localhost:11434
"""
        config_file.write_text(config_content)
        
        # Mock get_config to use temp config
        def mock_get_config():
            from medusa.config import Config
            return Config(config_dir=temp_dir.parent)
        
        def mock_load(self):
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)
        
        from medusa import cli
        from medusa.config import Config
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        monkeypatch.setattr(Config, "exists", lambda self: True)
        monkeypatch.setattr(Config, "load", mock_load)
        
        # Mock LLMClient health check
        mock_health = {
            "healthy": True,
            "provider": "local",
            "model": "mistral:7b-instruct",
            "model_info": {}
        }
        
        async def mock_health_check():
            return mock_health
        
        with patch('medusa.cli.create_llm_client') as mock_create:
            mock_client = AsyncMock()
            mock_client.health_check = mock_health_check
            mock_client.close = AsyncMock()
            mock_create.return_value = mock_client
            
            result = cli_runner.invoke(app, ["llm", "verify"])
        
        assert result.exit_code == 0
        assert "Connected" in result.stdout
        assert "local" in result.stdout
        assert "mistral" in result.stdout
    
    def test_llm_verify_failed_local_provider(self, cli_runner, temp_dir, monkeypatch):
        """Test llm verify with failed local provider health check"""
        # Create temporary config
        config_file = temp_dir / "config.yaml"
        config_content = """
llm:
  provider: local
  local_model: mistral:7b-instruct
  ollama_url: http://localhost:11434
"""
        config_file.write_text(config_content)
        
        # Mock get_config to use temp config
        def mock_get_config():
            from medusa.config import Config
            return Config(config_dir=temp_dir.parent)
        
        def mock_load(self):
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)
        
        from medusa import cli
        from medusa.config import Config
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        monkeypatch.setattr(Config, "exists", lambda self: True)
        monkeypatch.setattr(Config, "load", mock_load)
        
        # Mock LLMClient health check failure
        mock_health = {
            "healthy": False,
            "provider": "local",
            "model": "mistral:7b-instruct",
            "error": "Connection refused"
        }
        
        async def mock_health_check():
            return mock_health
        
        with patch('medusa.cli.create_llm_client') as mock_create:
            mock_client = AsyncMock()
            mock_client.health_check = mock_health_check
            mock_client.close = AsyncMock()
            mock_create.return_value = mock_client
            
            result = cli_runner.invoke(app, ["llm", "verify"])
        
        assert result.exit_code == 1
        assert "Not Connected" in result.stdout
        assert "Ollama" in result.stdout or "ollama" in result.stdout
        assert "pull" in result.stdout or "install" in result.stdout
    
    def test_llm_verify_openai_provider_hint(self, cli_runner, temp_dir, monkeypatch):
        """Test that OpenAI provider failure shows correct hints"""
        # Create temporary config
        config_file = temp_dir / "config.yaml"
        config_content = """
llm:
  provider: openai
  cloud_model: gpt-4-turbo-preview
  cloud_api_key: fake-key
"""
        config_file.write_text(config_content)
        
        # Mock get_config
        def mock_get_config():
            from medusa.config import Config
            return Config(config_dir=temp_dir.parent)
        
        def mock_load(self):
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)
        
        from medusa import cli
        from medusa.config import Config
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        monkeypatch.setattr(Config, "exists", lambda self: True)
        monkeypatch.setattr(Config, "load", mock_load)
        
        mock_health = {
            "healthy": False,
            "provider": "openai",
            "model": "gpt-4-turbo-preview"
        }
        
        async def mock_health_check():
            return mock_health
        
        with patch('medusa.cli.create_llm_client') as mock_create:
            mock_client = AsyncMock()
            mock_client.health_check = mock_health_check
            mock_client.close = AsyncMock()
            mock_create.return_value = mock_client
            
            result = cli_runner.invoke(app, ["llm", "verify"])
        
        assert result.exit_code == 1
        assert "Not Connected" in result.stdout
        # Should show OpenAI-specific hints
        assert ("openai" in result.stdout.lower() or 
                "sdk" in result.stdout.lower() or 
                "api" in result.stdout.lower())
    
    def test_llm_verify_anthropic_provider_hint(self, cli_runner, temp_dir, monkeypatch):
        """Test that Anthropic provider failure shows correct hints"""
        # Create temporary config
        config_file = temp_dir / "config.yaml"
        config_content = """
llm:
  provider: anthropic
  cloud_model: claude-3-sonnet-20240229
  cloud_api_key: fake-key
"""
        config_file.write_text(config_content)
        
        # Mock get_config
        def mock_get_config():
            from medusa.config import Config
            return Config(config_dir=temp_dir.parent)
        
        def mock_load(self):
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)
        
        from medusa import cli
        from medusa.config import Config
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        monkeypatch.setattr(Config, "exists", lambda self: True)
        monkeypatch.setattr(Config, "load", mock_load)
        
        mock_health = {
            "healthy": False,
            "provider": "anthropic",
            "model": "claude-3-sonnet-20240229"
        }
        
        async def mock_health_check():
            return mock_health
        
        with patch('medusa.cli.create_llm_client') as mock_create:
            mock_client = AsyncMock()
            mock_client.health_check = mock_health_check
            mock_client.close = AsyncMock()
            mock_create.return_value = mock_client
            
            result = cli_runner.invoke(app, ["llm", "verify"])
        
        assert result.exit_code == 1
        assert "Not Connected" in result.stdout
        # Should show Anthropic-specific hints
        assert ("anthropic" in result.stdout.lower() or 
                "sdk" in result.stdout.lower())
    
    def test_llm_verify_exception_handling(self, cli_runner, temp_dir, monkeypatch):
        """Test that unexpected exceptions are handled gracefully"""
        # Create temporary config
        config_file = temp_dir / "config.yaml"
        config_content = """
llm:
  provider: local
  local_model: mistral:7b-instruct
"""
        config_file.write_text(config_content)
        
        def mock_get_config():
            from medusa.config import Config
            return Config(config_dir=temp_dir.parent)
        
        def mock_load(self):
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)
        
        from medusa import cli
        from medusa.config import Config
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        monkeypatch.setattr(Config, "exists", lambda self: True)
        monkeypatch.setattr(Config, "load", mock_load)
        
        # Mock create_llm_client to raise exception
        with patch('medusa.cli.create_llm_client') as mock_create:
            mock_create.side_effect = Exception("Unexpected error!")
            
            result = cli_runner.invoke(app, ["llm", "verify"])
        
        assert result.exit_code == 1
        assert "Unexpected error" in result.stdout or "error" in result.stdout.lower()
    
    def test_llm_verify_client_cleanup(self, cli_runner, temp_dir, monkeypatch):
        """Test that LLM client is properly closed even on success"""
        # Create temporary config
        config_file = temp_dir / "config.yaml"
        config_content = """
llm:
  provider: mock
"""
        config_file.write_text(config_content)
        
        def mock_get_config():
            from medusa.config import Config
            return Config(config_dir=temp_dir.parent)
        
        def mock_load(self):
            import yaml
            with open(config_file) as f:
                return yaml.safe_load(f)
        
        from medusa import cli
        from medusa.config import Config
        monkeypatch.setattr(cli, "get_config", mock_get_config)
        monkeypatch.setattr(Config, "exists", lambda self: True)
        monkeypatch.setattr(Config, "load", mock_load)
        
        mock_health = {
            "healthy": True,
            "provider": "mock",
            "model": "mock"
        }
        
        async def mock_health_check():
            return mock_health
        
        with patch('medusa.cli.create_llm_client') as mock_create:
            mock_client = AsyncMock()
            mock_client.health_check = mock_health_check
            mock_client.close = AsyncMock()
            mock_create.return_value = mock_client
            
            result = cli_runner.invoke(app, ["llm", "verify"])
        
        # Verify close was called
        mock_client.close.assert_called_once()
        assert result.exit_code == 0
    
    def test_llm_verify_help_text(self, cli_runner):
        """Test that help text is available and informative"""
        result = cli_runner.invoke(app, ["llm", "verify", "--help"])
        
        assert result.exit_code == 0
        assert "LLM" in result.stdout or "verify" in result.stdout.lower()
        assert "reachable" in result.stdout.lower() or "connectivity" in result.stdout.lower()


@pytest.mark.integration
class TestLLMVerifyIntegration:
    """Integration tests for llm verify (requires config)"""
    
    @pytest.mark.manual
    def test_llm_verify_with_real_mock_provider(self, cli_runner):
        """
        Manual test: Verify command works with real mock provider
        
        This test requires MEDUSA to be set up with a configuration.
        Run manually with: pytest tests/unit/test_cli_llm_verify.py::TestLLMVerifyIntegration::test_llm_verify_with_real_mock_provider -v
        """
        # This would use real config if available
        result = cli_runner.invoke(app, ["llm", "verify"])
        
        # Should exit with 0 or 1 depending on config, but not crash
        assert result.exit_code in [0, 1]
    
    @pytest.mark.manual
    @pytest.mark.requires_docker
    def test_llm_verify_with_ollama(self, cli_runner):
        """
        Manual test: Verify command works with real Ollama instance
        
        This test requires:
        - Ollama to be running: `ollama serve`
        - Mistral model: `ollama pull mistral:7b-instruct`
        - MEDUSA configured to use local provider
        
        Run manually with: pytest tests/unit/test_cli_llm_verify.py::TestLLMVerifyIntegration::test_llm_verify_with_ollama -v -m manual
        """
        result = cli_runner.invoke(app, ["llm", "verify"])
        
        # Should succeed if Ollama is running and configured
        assert result.exit_code == 0
        assert "Connected" in result.stdout

