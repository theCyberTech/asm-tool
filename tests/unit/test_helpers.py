import pytest
from unittest.mock import Mock, MagicMock
from asm.core.helpers import resolve_targets


class TestResolveTargets:
    def test_all_known(self, mock_db, mock_config):
        """Test resolving all known targets"""
        mock_db.get_all_subdomains.return_value = ["sub1.example.com", "sub2.example.com"]
        
        targets = resolve_targets(mock_db, mock_config, all_known=True)
        
        assert len(targets) == 2
        assert "sub1.example.com" in targets
        mock_db.get_all_subdomains.assert_called_once()

    def test_specific_domain(self, mock_db, mock_config):
        """Test resolving for a specific domain with subdomains"""
        mock_db.get_subdomains.return_value = ["sub1.test.com"]
        
        targets = resolve_targets(mock_db, mock_config, domain="test.com")
        
        assert targets == ["sub1.test.com"]
        mock_db.get_subdomains.assert_called_with("test.com")

    def test_specific_domain_no_subdomains(self, mock_db, mock_config):
        """Test resolving for a specific domain with no known subdomains (fallback)"""
        mock_db.get_subdomains.return_value = []
        
        targets = resolve_targets(mock_db, mock_config, domain="test.com")
        
        assert targets == ["test.com"]

    def test_default_configured_domains(self, mock_db, mock_config):
        """Test resolving default configured domains subdomains"""
        mock_config.domains = ["example.com", "test.com"]
        
        def get_subs_side_effect(domain):
            if domain == "example.com":
                return ["sub.example.com"]
            return []
            
        mock_db.get_subdomains.side_effect = get_subs_side_effect
        
        targets = resolve_targets(mock_db, mock_config)
        
        assert "sub.example.com" in targets
        # test.com has no subdomains, so it isn't included because 'targets' list was not empty
        assert len(targets) == 1
    
    def test_default_configured_domains_fallback(self, mock_db, mock_config):
        """Test fallback to configured domains if no subdomains found for any of them"""
        mock_config.domains = ["example.com", "test.com"]
        mock_db.get_subdomains.return_value = []
        
        targets = resolve_targets(mock_db, mock_config)
        
        assert len(targets) == 2
        assert "example.com" in targets
        assert "test.com" in targets
