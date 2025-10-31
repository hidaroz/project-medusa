"""
Unit tests for configuration management

Tests the config module in isolation without external dependencies
"""

import pytest
import yaml
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from medusa.config import Config, get_config


@pytest.mark.unit
class TestConfig:
    """Test suite for Config class"""
    
    def test_config_initialization_default(self):
        """Test that Config initializes with default values"""
        config = Config()
        assert config is not None
        assert config.config_dir == Path.home() / ".medusa"
        assert config.config_path == Path.home() / ".medusa" / "config.yaml"
        assert config.logs_dir == Path.home() / ".medusa" / "logs"
        assert config.reports_dir == Path.home() / ".medusa" / "reports"
    
    def test_config_initialization_custom_dir(self, temp_dir):
        """Test Config with custom directory"""
        config = Config(config_dir=temp_dir)
        assert config.config_dir == temp_dir
        assert config.config_path == temp_dir / "config.yaml"
    
    def test_ensure_directories(self, temp_dir):
        """Test that ensure_directories creates all required directories"""
        config = Config(config_dir=temp_dir)
        config.ensure_directories()
        
        assert config.config_dir.exists()
        assert config.logs_dir.exists()
        assert config.reports_dir.exists()
    
    def test_exists_returns_false_when_no_config(self, temp_dir):
        """Test exists() returns False when config file doesn't exist"""
        config = Config(config_dir=temp_dir)
        assert config.exists() is False
    
    def test_exists_returns_true_when_config_present(self, temp_dir):
        """Test exists() returns True when config file exists"""
        config = Config(config_dir=temp_dir)
        config.ensure_directories()
        config.config_path.touch()
        
        assert config.exists() is True
    
    def test_save_creates_config_file(self, temp_dir, mock_config):
        """Test save() creates config file with correct data"""
        config = Config(config_dir=temp_dir)
        config.save(mock_config)
        
        assert config.config_path.exists()
        
        # Verify content
        with open(config.config_path, "r") as f:
            saved_data = yaml.safe_load(f)
        
        assert saved_data["api_key"] == mock_config["api_key"]
        assert saved_data["llm"]["model"] == mock_config["llm"]["model"]
    
    def test_load_raises_error_when_no_config(self, temp_dir):
        """Test load() raises FileNotFoundError when config doesn't exist"""
        config = Config(config_dir=temp_dir)
        
        with pytest.raises(FileNotFoundError, match="Configuration not found"):
            config.load()
    
    def test_load_returns_config_data(self, temp_dir, mock_config):
        """Test load() returns correct configuration data"""
        config = Config(config_dir=temp_dir)
        config.save(mock_config)
        
        loaded_data = config.load()
        
        assert loaded_data["api_key"] == mock_config["api_key"]
        assert loaded_data["llm"]["model"] == mock_config["llm"]["model"]
    
    def test_get_returns_value(self, temp_dir, mock_config):
        """Test get() returns correct configuration value"""
        config = Config(config_dir=temp_dir)
        config.save(mock_config)
        
        api_key = config.get("api_key")
        assert api_key == mock_config["api_key"]
    
    def test_get_returns_default_when_key_missing(self, temp_dir):
        """Test get() returns default value for missing key"""
        config = Config(config_dir=temp_dir)
        config.save({"some_key": "some_value"})
        
        result = config.get("missing_key", "default_value")
        assert result == "default_value"
    
    def test_get_llm_config(self, temp_dir, mock_config):
        """Test get_llm_config() returns LLM configuration"""
        config = Config(config_dir=temp_dir)
        config.save(mock_config)
        
        llm_config = config.get_llm_config()
        
        assert llm_config["model"] == "gemini-pro"
        assert llm_config["temperature"] == 0.7
        assert llm_config["api_key"] == mock_config["api_key"]
    
    def test_get_llm_config_with_defaults(self, temp_dir):
        """Test get_llm_config() applies default values"""
        config = Config(config_dir=temp_dir)
        config.save({"api_key": "test-key", "llm": {}})
        
        llm_config = config.get_llm_config()
        
        # Should have defaults
        assert llm_config["model"] == "gemini-pro"
        assert llm_config["temperature"] == 0.7
        assert llm_config["max_tokens"] == 2048
        assert llm_config["api_key"] == "test-key"
    
    def test_get_llm_config_merges_with_defaults(self, temp_dir):
        """Test get_llm_config() merges user config with defaults"""
        config = Config(config_dir=temp_dir)
        config.save({
            "api_key": "test-key",
            "llm": {
                "model": "gemini-1.5-pro",
                "temperature": 0.9
            }
        })
        
        llm_config = config.get_llm_config()
        
        # User values override defaults
        assert llm_config["model"] == "gemini-1.5-pro"
        assert llm_config["temperature"] == 0.9
        # But defaults are still applied
        assert llm_config["max_tokens"] == 2048


@pytest.mark.unit
class TestSetupWizard:
    """Test setup wizard functionality"""
    
    @patch('medusa.config.Prompt.ask')
    @patch('medusa.config.Confirm.ask')
    @patch('medusa.config.console')
    def test_run_setup_wizard_creates_config(self, mock_console, mock_confirm, mock_prompt, temp_dir):
        """Test setup wizard creates valid configuration"""
        # Mock user inputs
        mock_prompt.side_effect = [
            "test-api-key-12345",  # API key
            "1",  # Docker environment
        ]
        mock_confirm.side_effect = [True, False, False]  # Risk tolerance
        
        config = Config(config_dir=temp_dir)
        result = config.run_setup_wizard()
        
        assert result is not None
        assert "api_key" in result
        assert "llm" in result
        assert "risk_tolerance" in result
    
    @patch('medusa.config.Prompt.ask')
    @patch('medusa.config.console')
    def test_setup_wizard_rejects_short_api_key(self, mock_console, mock_prompt, temp_dir):
        """Test setup wizard rejects invalid API key format"""
        mock_prompt.return_value = "short"
        
        config = Config(config_dir=temp_dir)
        result = config.run_setup_wizard()
        
        assert result == {}


@pytest.mark.unit
class TestGetConfig:
    """Test suite for get_config function"""
    
    def test_get_config_returns_singleton(self):
        """Test that get_config returns same instance"""
        # Reset singleton for test
        import medusa.config
        medusa.config._config_instance = None
        
        config1 = get_config()
        config2 = get_config()
        
        assert config1 is config2
    
    def test_get_config_creates_instance(self):
        """Test that get_config creates Config instance"""
        # Reset singleton for test
        import medusa.config
        medusa.config._config_instance = None
        
        config = get_config()
        
        assert isinstance(config, Config)


@pytest.mark.unit
class TestConfigValidation:
    """Test configuration validation"""
    
    @pytest.mark.parametrize("api_key,expected_valid", [
        ("valid-key-format-with-sufficient-length", True),
        ("test-mock-api-key-12345", True),
        ("short", False),
        ("", False),
    ])
    def test_api_key_length_validation(self, api_key, expected_valid):
        """Test API key length validation"""
        # API keys should be at least 20 characters based on setup wizard
        is_valid = len(api_key) >= 20
        assert is_valid == expected_valid
    
    def test_load_handles_empty_config_file(self, temp_dir):
        """Test load() handles empty configuration file"""
        config = Config(config_dir=temp_dir)
        config.ensure_directories()
        
        # Create empty file
        with open(config.config_path, "w") as f:
            f.write("")
        
        loaded_data = config.load()
        assert loaded_data == {}
    
    def test_load_handles_malformed_yaml(self, temp_dir):
        """Test load() handles malformed YAML"""
        config = Config(config_dir=temp_dir)
        config.ensure_directories()
        
        # Create malformed YAML
        with open(config.config_path, "w") as f:
            f.write("{\ninvalid yaml: [\n")
        
        with pytest.raises(yaml.YAMLError):
            config.load()


@pytest.mark.unit
class TestConfigPaths:
    """Test configuration path handling"""
    
    def test_config_file_constant(self):
        """Test CONFIG_FILE constant"""
        assert Config.CONFIG_FILE == "config.yaml"
    
    def test_logs_dir_constant(self):
        """Test LOGS_DIR constant"""
        assert Config.LOGS_DIR == "logs"
    
    def test_reports_dir_constant(self):
        """Test REPORTS_DIR constant"""
        assert Config.REPORTS_DIR == "reports"
    
    def test_default_config_dir_uses_home(self):
        """Test DEFAULT_CONFIG_DIR uses user home directory"""
        assert Config.DEFAULT_CONFIG_DIR == Path.home() / ".medusa"
    
    def test_default_llm_config_values(self):
        """Test DEFAULT_LLM_CONFIG has correct defaults"""
        defaults = Config.DEFAULT_LLM_CONFIG
        
        assert defaults["model"] == "gemini-pro"
        assert defaults["temperature"] == 0.7
        assert defaults["max_tokens"] == 2048
        assert defaults["timeout"] == 30
        assert defaults["max_retries"] == 3
        assert defaults["mock_mode"] is False


@pytest.mark.unit
class TestConfigFileOperations:
    """Test file I/O operations"""
    
    def test_save_preserves_data_types(self, temp_dir):
        """Test save() preserves data types"""
        config = Config(config_dir=temp_dir)
        
        test_data = {
            "string": "test",
            "integer": 42,
            "float": 3.14,
            "boolean": True,
            "list": [1, 2, 3],
            "dict": {"nested": "value"}
        }
        
        config.save(test_data)
        loaded_data = config.load()
        
        assert loaded_data["string"] == "test"
        assert loaded_data["integer"] == 42
        assert loaded_data["float"] == 3.14
        assert loaded_data["boolean"] is True
        assert loaded_data["list"] == [1, 2, 3]
        assert loaded_data["dict"]["nested"] == "value"
    
    def test_save_overwrites_existing_config(self, temp_dir):
        """Test save() overwrites existing configuration"""
        config = Config(config_dir=temp_dir)
        
        config.save({"version": 1})
        config.save({"version": 2})
        
        loaded_data = config.load()
        assert loaded_data["version"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

