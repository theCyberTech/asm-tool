"""
Unit tests for DNS Monitor module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import dns.resolver
import dns.exception

from asm.modules.dns_monitor import DNSMonitor


class TestDNSMonitor:
    """Test cases for DNSMonitor class"""

    def test_dns_monitor_initialization(self):
        config = Mock()
        monitor = DNSMonitor(config)

        assert monitor.config == config
        assert hasattr(monitor, "resolver")

    def test_get_records_all_types(self):
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_answer.__str__.return_value = "192.168.1.1"
        mock_resolver.resolve.return_value = [mock_answer]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_records("example.com")

        assert "A" in result
        assert result["A"] == ["192.168.1.1"]

    def test_get_records_specific_types(self):
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_answer.__str__.return_value = "ns1.example.com"
        mock_resolver.resolve.return_value = [mock_answer]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_records("example.com", ["A", "NS"])

        assert "A" in result
        assert "NS" in result
        assert result["A"] == ["192.168.1.1"]
        assert result["NS"] == ["ns1.example.com"]

    def test_get_records_nxdomain(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_records("example.com")

        assert result == {}

    def test_get_records_no_answer(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_records("example.com")

        assert "A" in result
        assert result["A"] == []

    def test_get_records_timeout(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.exception.Timeout()

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_records("example.com")

        assert "A" in result
        assert result["A"] == []

    def test_get_records_exception(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_records("example.com")

        assert "A" in result
        assert result["A"] == []

    def test_get_nameservers_success(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "ns1.example.com."
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_nameservers("example.com")

        assert len(result) == 1
        assert "ns1.example.com" in result

    def test_get_nameservers_exception(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_nameservers("example.com")

        assert result == []

    def test_get_mx_records_success(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange = MagicMock()
        mock_rdata.exchange.__str__.return_value = "mail.example.com"
        mock_rdata.exchange.rstrip.return_value = "mail.example.com"
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_mx_records("example.com")

        assert len(result) == 1
        assert result[0]["priority"] == 10
        assert result[0]["host"] == "mail.example.com"

    def test_get_mx_records_exception(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_mx_records("example.com")

        assert result == []

    def test_get_mx_records_sorted(self):
        mock_resolver = MagicMock()
        mock_rdata1 = MagicMock()
        mock_rdata1.preference = 20
        mock_rdata2 = MagicMock()
        mock_rdata2.preference = 10
        mock_rdata1.exchange = MagicMock()
        mock_rdata1.exchange.__str__.return_value = "mail1.example.com"
        mock_rdata2.exchange = MagicMock()
        mock_rdata2.exchange.__str__.return_value = "mail2.example.com"
        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_mx_records("example.com")

        assert len(result) == 2
        assert result[0]["priority"] == 20
        assert result[1]["priority"] == 10

    def test_get_txt_records_success(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=spf1 mx include:example.com"'
        mock_rdata.strip.return_value = '"v=spf1 mx include:example.com"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_txt_records("example.com")

        assert len(result) == 1
        assert "v=spf1 mx include:example.com" in result

    def test_get_txt_records_multiple(self):
        mock_resolver = MagicMock()
        mock_rdata1 = MagicMock()
        mock_rdata2 = MagicMock()
        mock_rdata1.__str__.return_value = '"v=spf1 mx include:example.com"'
        mock_rdata2.__str__.return_value = '"v=spf2 mx include:example.com"'
        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_txt_records("example.com")

        assert len(result) == 2

    def test_get_txt_records_exception(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_txt_records("example.com")

        assert result == []

    def test_check_spf_found(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=spf1 mx include:example.com"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_spf("example.com")

        assert result == "v=spf1 mx include:example.com"

    def test_check_spf_not_found(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"other text"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_spf("example.com")

        assert result is None

    def test_check_spf_multiple(self):
        mock_resolver = MagicMock()
        mock_rdata1 = MagicMock()
        mock_rdata2 = MagicMock()
        mock_rdata1.__str__.return_value = '"v=spf1 mx include:example.com"'
        mock_rdata2.__str__.return_value = '"v=spf1 mx include:example.com"'
        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_spf("example.com")

        assert result == "v=spf1 mx include:example.com"

    def test_check_dmarc_found(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=DMARC1; p=none"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dmarc("example.com")

        assert result == "v=DMARC1; p=none"

    def test_check_dmarc_not_found(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"other text"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dmarc("example.com")

        assert result is None

    def test_check_dkim_found(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=DKIM1; k=rsa; p=example.com"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dkim("example.com", "default")

        assert result == "v=DKIM1; k=rsa; p=example.com"

    def test_check_dkim_not_found(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"other text"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dkim("example.com", "default")

        assert result is None

    def test_check_dkim_with_selector(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"k=example"'
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dkim("example.com", "example")

        assert result == "k=example"

    def test_get_email_security_status(self):
        mock_resolver = MagicMock()

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            with patch.object(monitor, "get_txt_records") as mock_get_txt:
                mock_get_txt.return_value = []

            with patch.object(monitor, "get_mx_records") as mock_get_mx:
                mock_get_mx.return_value = [
                    {"priority": 10, "host": "mail1.example.com"}
                ]

            with patch.object(monitor, "check_spf") as mock_check_spf:
                mock_check_spf.return_value = "v=spf1 mx include:example.com"

            with patch.object(monitor, "check_dmarc") as mock_check_dmarc:
                mock_check_dmarc.return_value = "v=DMARC1; p=none"

            with patch.object(monitor, "check_dkim") as mock_check_dkim:
                mock_check_dkim.return_value = "v=DKIM1; k=rsa; p=example.com"

            result = monitor.get_email_security_status("example.com")

        assert "spf" in result
        assert "dmarc" in result
        assert "dkim_default" in result
        assert "mx_records" in result

    def test_check_dnssec_enabled(self):
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_resolver.resolve.return_value = [mock_answer, mock_answer]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dnssec("example.com")

        assert result is True

    def test_check_dnssec_disabled(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.exception.Timeout()

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.check_dnssec("example.com")

        assert result is False

    def test_resolve_host_ipv4(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "192.168.1.1"
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.resolve_host("example.com")

        assert len(result) == 1
        assert "192.168.1.1" in result

    def test_resolve_host_ipv6(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "2001:db8::1"
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.resolve_host("example.com")

        assert len(result) == 1
        assert "2001:db8::1" in result

    def test_resolve_host_both_types(self):
        mock_resolver = MagicMock()
        mock_rdata1 = MagicMock()
        mock_rdata1.__str__.return_value = "192.168.1.1"
        mock_rdata2 = MagicMock()
        mock_rdata2.__str__.return_value = "2001:db8::1"
        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.resolve_host("example.com")

        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "2001:db8::1" in result

    def test_resolve_host_exception(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.resolve_host("example.com")

        assert result == []

    def test_reverse_lookup_success(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "mail.example.com."
        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.reverse_lookup("192.168.1.1")

        assert result == "mail.example.com"

    def test_reverse_lookup_not_found(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.reverse_lookup("192.168.1.1")

        assert result is None

    def test_get_caa_records_success(self):
        mock_resolver = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.flags = 128
        mock_rdata.tag = MagicMock()
        mock_rdata.tag.decode.return_value = "issue"
        mock_rdata.value = MagicMock()
        mock_rdata.value.decode.return_value = "letsencrypt"

        mock_rdata = MagicMock()
        mock_rdata.__setattr__("flags", 128)
        mock_rdata.__setattr__("tag", mock_rdata.tag)
        mock_rdata.__setattr__("value", mock_rdata.value)

        mock_resolver.resolve.return_value = [mock_rdata]

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_caa_records("example.com")

        assert len(result) == 1
        assert result[0]["flags"] == 128
        assert result[0]["tag"] == "issue"
        assert result[0]["value"] == "letsencrypt"

    def test_get_caa_records_exception(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")

        config = Mock()
        monitor = DNSMonitor(config)

        with patch.object(monitor, "__init__", return_value=None):
            monitor.__init__(config)
            monitor.resolver = mock_resolver

            result = monitor.get_caa_records("example.com")

        assert result == []
