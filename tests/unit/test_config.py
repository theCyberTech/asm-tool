"""
Unit tests for ASM Core Config module
"""

import pytest
import tempfile
import yaml
from pathlib import Path

from asm.core.config import Config
from tests.fixtures import MockConfig, TEST_CONFIG_DATA


class TestConfig:
    """Test cases for Config class"""

    def test_default_config(self):
        """Test default configuration values"""
        config = Config()

        assert config.domains == []
        assert config.slack_enabled is False
        assert config.email_enabled is False
        assert (
            config.default_ports
            == "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
        )
        assert config.nuclei_severity == "medium,high,critical"
        assert config.passive_only is False
        assert config.scan_rate_limit == 100
        assert config.shodan_enabled is False
        assert config.full_scan_cron == "0 6 * * *"
        assert config.cert_check_cron == "0 */6 * * *"

    def test_from_file_valid_yaml(self):
        """Test loading config from valid YAML file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(TEST_CONFIG_DATA, f)
            config_path = f.name

        try:
            config = Config.from_file(Path(config_path))

            assert config.domains == ["example.com"]
            assert config.slack_enabled is False
            assert config.email_enabled is False
            assert config.default_ports == "80,443,8080"
            assert config.nuclei_severity == "medium,high,critical"
            assert config.passive_only is False
            assert config.scan_rate_limit == 100
            assert config.shodan_enabled is False
        finally:
            Path(config_path).unlink()

    def test_from_file_empty_yaml(self):
        """Test loading config from empty YAML file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            config_path = f.name

        try:
            config = Config.from_file(Path(config_path))

            # Should use default values
            assert config.domains == []
            assert config.slack_enabled is False
            assert (
                config.default_ports
                == "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
            )
        finally:
            Path(config_path).unlink()

    def test_from_file_nonexistent(self):
        """Test loading config from non-existent file"""
        config = Config.from_file(Path("/nonexistent/config.yaml"))

        # Should use default values
        assert config.domains == []
        assert config.slack_enabled is False

    def test_from_file_partial_config(self):
        """Test loading config with only some fields set"""
        partial_data = {
            "domains": ["test.com"],
            "notifications": {
                "slack": {
                    "enabled": True,
                    "webhook_url": "https://hooks.slack.com/test",
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(partial_data, f)
            config_path = f.name

        try:
            config = Config.from_file(Path(config_path))

            assert config.domains == ["test.com"]
            assert config.slack_enabled is True
            assert config.slack_webhook == "https://hooks.slack.com/test"
            # Should use defaults for unset fields
            assert config.email_enabled is False
            assert (
                config.default_ports
                == "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
            )
        finally:
            Path(config_path).unlink()

    def test_from_file_invalid_yaml(self):
        """Test loading config from invalid YAML file"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            config_path = f.name

        try:
            with pytest.raises(yaml.YAMLError):
                Config.from_file(Path(config_path))
        finally:
            Path(config_path).unlink()

    def test_to_dict(self):
        """Test converting config to dictionary"""
        config = Config()
        config.domains = ["test.com"]
        config.slack_enabled = True
        config.slack_webhook = "https://hooks.slack.com/test"

        result = config.to_dict()

        assert isinstance(result, dict)
        assert result["domains"] == ["test.com"]
        assert result["notifications"]["slack"]["enabled"] is True
        assert (
            result["notifications"]["slack"]["webhook_url"]
            == "https://hooks.slack.com/test"
        )
        assert result["scanning"]["ports"] == config.default_ports
        assert result["scanning"]["nuclei_severity"] == config.nuclei_severity

    def test_to_dict_complete(self):
        """Test converting complete config to dictionary"""
        config = Config()
        config.domains = ["example.com"]
        config.slack_enabled = True
        config.slack_webhook = "https://hooks.slack.com/test"
        config.email_enabled = True
        config.email_smtp_host = "smtp.gmail.com"
        config.email_smtp_port = 587
        config.email_from = "test@example.com"
        config.email_to = "security@example.com"
        config.default_ports = "80,443"
        config.nuclei_severity = "high,critical"
        config.passive_only = True
        config.scan_rate_limit = 50
        config.shodan_enabled = True
        config.shodan_api_key = "test-key"
        config.full_scan_cron = "0 0 * * *"
        config.cert_check_cron = "0 */12 * * *"

        result = config.to_dict()

        # Verify all sections are present
        assert "domains" in result
        assert "notifications" in result
        assert "scanning" in result
        assert "shodan" in result
        assert "schedule" in result

        # Verify values
        assert result["domains"] == ["example.com"]
        assert result["notifications"]["slack"]["enabled"] is True
        assert result["notifications"]["email"]["enabled"] is True
        assert result["scanning"]["ports"] == "80,443"
        assert result["scanning"]["passive_only"] is True
        assert result["scanning"]["rate_limit"] == 50
        assert result["shodan"]["enabled"] is True
        assert result["shodan"]["api_key"] == "test-key"
        assert result["schedule"]["full_scan"] == "0 0 * * *"
        assert result["schedule"]["cert_check"] == "0 */12 * * *"

    def test_config_dataclass_behavior(self):
        """Test that Config behaves properly as a dataclass"""
        config1 = Config()
        config1.domains = ["test.com"]

        config2 = Config()
        config2.domains = ["test.com"]

        # Test equality
        assert config1.domains == config2.domains

        # Test that modifications don't affect other instances
        config1.domains.append("another.com")
        assert config1.domains != config2.domains

    def test_edge_case_empty_domains_list(self):
        """Test config with empty domains list"""
        config = Config()
        config.domains = []

        result = config.to_dict()
        assert result["domains"] == []

    def test_edge_case_very_long_ports_string(self):
        """Test config with very long ports string"""
        config = Config()
        config.default_ports = ",".join(str(i) for i in range(1, 1000))

        result = config.to_dict()
        assert len(result["scanning"]["ports"].split(",")) == 999

    def test_edge_case_special_characters_in_webhook(self):
        """Test config with special characters in webhook URL"""
        config = Config()
        config.slack_webhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

        result = config.to_dict()
        assert result["notifications"]["slack"]["webhook_url"] == config.slack_webhook
