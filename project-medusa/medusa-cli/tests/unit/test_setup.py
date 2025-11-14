"""
Tests for Setup Module
"""

import pytest
from pathlib import Path
import yaml
from unittest.mock import Mock, patch

from medusa.setup import SetupWizard, ConfigValidator, ProfileManager, ToolDetector


class TestConfigValidator:
    """Tests for ConfigValidator"""

    def test_validate_valid_config(self):
        """Test validation of a valid configuration"""
        validator = ConfigValidator()

        config = {
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "api_key": "test-key",
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            "databases": {
                "neo4j": {
                    "uri": "bolt://localhost:7687",
                    "user": "neo4j",
                    "password": "password",
                },
                "chromadb": {
                    "path": "/tmp/chromadb",
                    "collection": "test",
                },
            },
        }

        is_valid, errors = validator.validate(config)
        assert is_valid
        assert len(errors) == 0

    def test_validate_missing_llm_provider(self):
        """Test validation fails when LLM provider is missing"""
        validator = ConfigValidator()

        config = {
            "llm": {
                "model": "test-model",
            }
        }

        is_valid, errors = validator.validate(config)
        assert not is_valid
        assert any("provider" in error.lower() for error in errors)

    def test_validate_invalid_temperature(self):
        """Test validation fails for invalid temperature"""
        validator = ConfigValidator()

        config = {
            "llm": {
                "provider": "anthropic",
                "model": "test-model",
                "api_key": "test-key",
                "temperature": 1.5,  # Invalid
            }
        }

        is_valid, errors = validator.validate(config)
        assert not is_valid
        assert any("temperature" in error.lower() for error in errors)

    def test_validate_invalid_cidr(self):
        """Test validation fails for invalid CIDR notation"""
        validator = ConfigValidator()

        config = {
            "llm": {
                "provider": "anthropic",
                "model": "test-model",
                "api_key": "test-key",
            },
            "safety": {
                "authorized_scope": ["192.168.1.0/24", "invalid-cidr"],
            }
        }

        is_valid, errors = validator.validate(config)
        assert not is_valid
        assert any("cidr" in error.lower() for error in errors)

    def test_get_recommendations(self):
        """Test configuration recommendations"""
        validator = ConfigValidator()

        config = {
            "llm": {
                "provider": "anthropic",
                "model": "test-model",
                "api_key": "test-key",
                "temperature": 0.9,  # High temperature
            },
            "safety": {
                "require_authorization": False,  # Disabled
            }
        }

        recommendations = validator.get_recommendations(config)
        assert len(recommendations) > 0
        assert any("temperature" in rec.lower() for rec in recommendations)
        assert any("authorization" in rec.lower() for rec in recommendations)


class TestToolDetector:
    """Tests for ToolDetector"""

    def test_detect_tool_installed(self):
        """Test detection of installed tool"""
        detector = ToolDetector()

        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch.object(detector, '_get_version', return_value='7.91'):
                result = detector.detect_tool('nmap')

                assert result['installed']
                assert result['binary'] == 'nmap'
                assert result['version'] == '7.91'

    def test_detect_tool_not_installed(self):
        """Test detection of missing tool"""
        detector = ToolDetector()

        with patch('shutil.which', return_value=None):
            result = detector.detect_tool('nmap')

            assert not result['installed']
            assert result['binary'] == 'nmap'

    def test_detect_all_tools(self):
        """Test detection of all tools"""
        detector = ToolDetector()

        with patch('shutil.which', return_value='/usr/bin/tool'):
            with patch.object(detector, '_get_version', return_value='1.0'):
                results = detector.detect_all()

                assert len(results) > 0
                assert all(r['installed'] for r in results.values())

    def test_detect_by_category(self):
        """Test detection of tools by category"""
        detector = ToolDetector()

        with patch('shutil.which', return_value='/usr/bin/tool'):
            with patch.object(detector, '_get_version', return_value='1.0'):
                results = detector.detect_by_category('network')

                assert len(results) > 0
                assert all(r['category'] == 'network' for r in results.values())

    def test_get_missing_required(self):
        """Test getting missing required tools"""
        detector = ToolDetector()

        with patch('shutil.which', return_value=None):
            missing = detector.get_missing_required()

            # nmap is required
            assert 'nmap' in missing

    def test_get_installation_summary(self):
        """Test installation summary"""
        detector = ToolDetector()

        with patch('shutil.which', return_value='/usr/bin/tool'):
            with patch.object(detector, '_get_version', return_value='1.0'):
                summary = detector.get_installation_summary()

                assert 'total' in summary
                assert 'installed' in summary
                assert 'missing' in summary
                assert 'by_category' in summary


class TestProfileManager:
    """Tests for ProfileManager"""

    def test_load_builtin_profile(self):
        """Test loading built-in profile"""
        manager = ProfileManager()

        profile = manager.load_profile('stealth')

        assert profile['profile']['name'] == 'stealth'
        assert 'llm' in profile
        assert 'scanning' in profile

    def test_load_unknown_profile(self):
        """Test loading unknown profile raises error"""
        manager = ProfileManager()

        with pytest.raises(ValueError):
            manager.load_profile('nonexistent')

    def test_list_profiles(self):
        """Test listing profiles"""
        manager = ProfileManager()

        profiles = manager.list_profiles()

        assert len(profiles) >= 5  # At least 5 built-in profiles
        assert any(p['name'] == 'stealth' for p in profiles)
        assert any(p['name'] == 'aggressive' for p in profiles)

    def test_save_and_load_custom_profile(self, tmp_path):
        """Test saving and loading custom profile"""
        manager = ProfileManager(profiles_dir=tmp_path)

        config = {
            "profile": {
                "name": "custom",
                "description": "Test profile",
            },
            "llm": {
                "provider": "anthropic",
                "model": "test-model",
            }
        }

        # Save
        assert manager.save_profile('custom', config)

        # Load
        loaded = manager.load_profile('custom')
        assert loaded['profile']['name'] == 'custom'

    def test_delete_builtin_profile_fails(self):
        """Test that deleting built-in profile fails"""
        manager = ProfileManager()

        result = manager.delete_profile('stealth')
        assert not result

    def test_delete_custom_profile(self, tmp_path):
        """Test deleting custom profile"""
        manager = ProfileManager(profiles_dir=tmp_path)

        config = {"profile": {"name": "test"}}
        manager.save_profile('test', config)

        assert manager.delete_profile('test')
        assert not (tmp_path / "test.yaml").exists()

    def test_export_profile(self, tmp_path):
        """Test exporting profile"""
        manager = ProfileManager()

        output_path = tmp_path / "exported.yaml"
        assert manager.export_profile('stealth', output_path)
        assert output_path.exists()

    def test_import_profile(self, tmp_path):
        """Test importing profile"""
        manager = ProfileManager(profiles_dir=tmp_path)

        # Create a profile file
        profile_file = tmp_path / "import_test.yaml"
        config = {
            "profile": {"name": "imported"},
            "llm": {"provider": "anthropic"}
        }

        with open(profile_file, 'w') as f:
            yaml.dump(config, f)

        assert manager.import_profile('imported', profile_file)
        loaded = manager.load_profile('imported')
        assert loaded['profile']['name'] == 'imported'

    def test_create_custom_profile(self):
        """Test creating custom profile from base"""
        manager = ProfileManager()

        custom = manager.create_custom_profile('mycustom', 'safe')

        assert custom['profile']['name'] == 'mycustom'
        assert 'safe' in custom['profile']['description']


class TestSetupWizard:
    """Tests for SetupWizard"""

    def test_wizard_initialization(self, tmp_path):
        """Test wizard initialization"""
        config_path = tmp_path / "config.yaml"
        wizard = SetupWizard(config_path)

        assert wizard.config_path == config_path
        assert isinstance(wizard.validator, ConfigValidator)
        assert isinstance(wizard.detector, ToolDetector)
        assert isinstance(wizard.profile_manager, ProfileManager)

    def test_quick_setup(self, tmp_path):
        """Test quick setup mode"""
        config_path = tmp_path / "config.yaml"
        wizard = SetupWizard(config_path)

        with patch('questionary.password') as mock_password:
            mock_password.return_value.ask.return_value = "test-key"

            with patch.object(wizard.detector, 'detect_all', return_value={}):
                with patch.object(wizard, '_save_configuration', return_value=True):
                    result = wizard._quick_setup()

                    assert result
                    assert 'llm' in wizard.config
                    assert 'databases' in wizard.config

    def test_save_configuration(self, tmp_path):
        """Test saving configuration"""
        config_path = tmp_path / "config.yaml"
        wizard = SetupWizard(config_path)

        wizard.config = {
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "api_key": "test-key",
                "temperature": 0.3,
                "max_tokens": 4096,
            }
        }

        with patch.object(wizard.validator, 'validate', return_value=(True, [])):
            result = wizard._save_configuration()

            assert result
            assert config_path.exists()

            with open(config_path) as f:
                saved_config = yaml.safe_load(f)
                assert saved_config['llm']['provider'] == 'anthropic'

    def test_verify_setup_no_config(self, tmp_path):
        """Test verify setup when no config exists"""
        config_path = tmp_path / "nonexistent.yaml"
        wizard = SetupWizard(config_path)

        result = wizard.verify_setup()
        assert not result

    def test_reset_setup(self, tmp_path):
        """Test resetting setup"""
        config_path = tmp_path / "config.yaml"
        wizard = SetupWizard(config_path)

        # Create config file
        config_path.write_text("test: value")

        result = wizard.reset_setup()
        assert result
        assert not config_path.exists()
        assert (tmp_path / "config.yaml.bak").exists()
