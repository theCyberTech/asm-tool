"""
Unit tests for DNS Monitor module
"""

from unittest.mock import Mock, patch, MagicMock
import dns.resolver
import dns.exception

from asm.modules.dns_monitor import DNSMonitor


class TestDNSMonitor:
    """Test cases for DNSMonitor class"""

    def test_dns_monitor_initialization(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        assert monitor.config == config
        assert hasattr(monitor, "resolver")

    def test_get_records_all_types(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_answer = MagicMock()
        mock_answer.__str__.return_value = "192.168.1.1"

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_answer]
        monitor.resolver = mock_resolver

        result = monitor.get_records("example.com")

        assert "A" in result
        assert result["A"] == ["192.168.1.1"]

    def test_get_records_specific_types(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_answer_a = MagicMock()
        mock_answer_a.__str__.return_value = "192.168.1.1"
        mock_answer_ns = MagicMock()
        mock_answer_ns.__str__.return_value = "ns1.example.com"

        # Configure resolver to return different values for different record types
        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                return [mock_answer_a]
            elif rtype == "NS":
                return [mock_answer_ns]
            else:
                raise dns.resolver.NoAnswer()

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = resolve_side_effect
        monitor.resolver = mock_resolver

        result = monitor.get_records("example.com", ["A", "NS"])

        assert "A" in result
        assert "NS" in result
        assert result["A"] == ["192.168.1.1"]
        assert result["NS"] == ["ns1.example.com"]

    def test_get_records_nxdomain(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        monitor.resolver = mock_resolver

        result = monitor.get_records("example.com")

        assert result == {}

    def test_get_records_no_answer(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        monitor.resolver = mock_resolver

        # When NoAnswer for all types, the result should be empty dict
        # (continue in the loop, never adding any records)
        result = monitor.get_records("example.com")

        # The function catches NoAnswer and continues, so result is empty
        assert result == {}

    def test_get_records_timeout(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        monitor.resolver = mock_resolver

        # Timeout is caught and continues, so no records returned
        result = monitor.get_records("example.com")

        assert result == {}

    def test_get_records_exception(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        # Generic exception is caught and continues
        result = monitor.get_records("example.com")

        assert result == {}

    def test_get_nameservers_success(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "ns1.example.com."

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.get_nameservers("example.com")

        assert len(result) == 1
        assert "ns1.example.com" in result

    def test_get_nameservers_exception(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        result = monitor.get_nameservers("example.com")

        assert result == []

    def test_get_mx_records_success(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.preference = 10
        mock_rdata.exchange = MagicMock()
        mock_rdata.exchange.__str__.return_value = "mail.example.com."

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.get_mx_records("example.com")

        assert len(result) == 1
        assert result[0]["priority"] == 10
        assert result[0]["host"] == "mail.example.com"

    def test_get_mx_records_exception(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        result = monitor.get_mx_records("example.com")

        assert result == []

    def test_get_mx_records_sorted(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata1 = MagicMock()
        mock_rdata1.preference = 20
        mock_rdata1.exchange = MagicMock()
        mock_rdata1.exchange.__str__.return_value = "mail1.example.com."

        mock_rdata2 = MagicMock()
        mock_rdata2.preference = 10
        mock_rdata2.exchange = MagicMock()
        mock_rdata2.exchange.__str__.return_value = "mail2.example.com."

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]
        monitor.resolver = mock_resolver

        result = monitor.get_mx_records("example.com")

        assert len(result) == 2
        # MX records are sorted by preference (ascending)
        assert result[0]["priority"] == 10  # Lower priority comes first
        assert result[1]["priority"] == 20

    def test_get_txt_records_success(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=spf1 mx include:example.com"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.get_txt_records("example.com")

        assert len(result) == 1
        assert "v=spf1 mx include:example.com" in result

    def test_get_txt_records_multiple(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata1 = MagicMock()
        mock_rdata2 = MagicMock()
        mock_rdata1.__str__.return_value = '"v=spf1 mx include:example.com"'
        mock_rdata2.__str__.return_value = '"v=spf2 mx include:example.com"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata1, mock_rdata2]
        monitor.resolver = mock_resolver

        result = monitor.get_txt_records("example.com")

        assert len(result) == 2

    def test_get_txt_records_exception(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        result = monitor.get_txt_records("example.com")

        assert result == []

    def test_check_spf_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=spf1 mx include:example.com"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_spf("example.com")

        assert result == "v=spf1 mx include:example.com"

    def test_check_spf_not_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"other text"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_spf("example.com")

        assert result is None

    def test_check_dmarc_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=DMARC1; p=none"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_dmarc("example.com")

        assert result == "v=DMARC1; p=none"

    def test_check_dmarc_not_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"other text"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_dmarc("example.com")

        assert result is None

    def test_check_dkim_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"v=DKIM1; k=rsa; p=example.com"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_dkim("example.com", "default")

        assert result == "v=DKIM1; k=rsa; p=example.com"

    def test_check_dkim_not_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"other text"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_dkim("example.com", "default")

        assert result is None

    def test_check_dkim_with_k_equals(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = '"k=rsa; p=example"'

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.check_dkim("example.com", "example")

        assert result == "k=rsa; p=example"

    def test_get_email_security_status(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        # Mock resolver to return empty for all queries (simpler test)
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        monitor.resolver = mock_resolver

        result = monitor.get_email_security_status("example.com")

        assert "spf" in result
        assert "dmarc" in result
        assert "dkim_default" in result
        assert "mx_records" in result

    def test_check_dnssec_enabled(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_answer = MagicMock()
        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_answer, mock_answer]
        monitor.resolver = mock_resolver

        result = monitor.check_dnssec("example.com")

        assert result is True

    def test_check_dnssec_disabled(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        monitor.resolver = mock_resolver

        result = monitor.check_dnssec("example.com")

        assert result is False

    def test_resolve_host_ipv4(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "192.168.1.1"

        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                return [mock_rdata]
            else:
                raise dns.resolver.NoAnswer()

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = resolve_side_effect
        monitor.resolver = mock_resolver

        result = monitor.resolve_host("example.com")

        assert len(result) == 1
        assert "192.168.1.1" in result

    def test_resolve_host_ipv6(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "2001:db8::1"

        def resolve_side_effect(domain, rtype):
            if rtype == "AAAA":
                return [mock_rdata]
            else:
                raise dns.resolver.NoAnswer()

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = resolve_side_effect
        monitor.resolver = mock_resolver

        result = monitor.resolve_host("example.com")

        assert len(result) == 1
        assert "2001:db8::1" in result

    def test_resolve_host_both_types(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata_a = MagicMock()
        mock_rdata_a.__str__.return_value = "192.168.1.1"
        mock_rdata_aaaa = MagicMock()
        mock_rdata_aaaa.__str__.return_value = "2001:db8::1"

        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                return [mock_rdata_a]
            elif rtype == "AAAA":
                return [mock_rdata_aaaa]
            else:
                raise dns.resolver.NoAnswer()

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = resolve_side_effect
        monitor.resolver = mock_resolver

        result = monitor.resolve_host("example.com")

        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "2001:db8::1" in result

    def test_resolve_host_exception(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        result = monitor.resolve_host("example.com")

        assert result == []

    def test_reverse_lookup_success(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.__str__.return_value = "mail.example.com."

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.reverse_lookup("192.168.1.1")

        assert result == "mail.example.com"

    def test_reverse_lookup_not_found(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        result = monitor.reverse_lookup("192.168.1.1")

        assert result is None

    def test_get_caa_records_success(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_rdata = MagicMock()
        mock_rdata.flags = 128
        # Use bytes for tag and value since the implementation handles both
        mock_rdata.tag = b"issue"
        mock_rdata.value = b"letsencrypt"

        mock_resolver = MagicMock()
        mock_resolver.resolve.return_value = [mock_rdata]
        monitor.resolver = mock_resolver

        result = monitor.get_caa_records("example.com")

        assert len(result) == 1
        assert result[0]["flags"] == 128
        assert result[0]["tag"] == "issue"
        assert result[0]["value"] == "letsencrypt"

    def test_get_caa_records_exception(self):
        config = Mock()
        config.timeout_dns = 5
        monitor = DNSMonitor(config)

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("DNS Error")
        monitor.resolver = mock_resolver

        result = monitor.get_caa_records("example.com")

        assert result == []
