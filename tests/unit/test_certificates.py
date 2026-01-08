import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta
from asm.modules.certificates import CertificateMonitor, CertificateChainChecker
from cryptography import x509
from cryptography.x509.oid import NameOID

class TestCertificateMonitor:
    
    @pytest.fixture
    def monitor(self, mock_config):
        return CertificateMonitor(mock_config)

    @patch("asm.modules.certificates.CertificateMonitor._get_certificate_pem")
    @patch("asm.modules.certificates.x509.load_pem_x509_certificate")
    def test_check_certificate_success(self, mock_load, mock_get_pem, monitor):
        # Setup mock cert
        mock_cert = MagicMock()
        mock_cert.serial_number = 123456789
        
        # Dates
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(days=30)
        mock_cert.not_valid_before_utc = now
        mock_cert.not_valid_after_utc = expiry
        
        # Subject/Issuer
        # We need to mock _format_name behavior or just format subject to be compatible
        # _format_name calls .get_attributes_for_oid
        mock_subject_attr = MagicMock()
        mock_subject_attr.value = "example.com"
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.issuer.get_attributes_for_oid.return_value = [mock_subject_attr]
        
        mock_cert.fingerprint.return_value.hex.return_value = "aabbcc"
        mock_cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"
        mock_cert.version.name = "v3"
        
        # Mock valid PEM return
        mock_get_pem.return_value = "-----BEGIN CERTIFICATE-----..."
        mock_load.return_value = mock_cert
        
        # Mock _get_san (it calls extensions)
        with patch.object(monitor, "_get_san", return_value=["example.com"]):
            info = monitor.check_certificate("example.com")
        
        assert info is not None
        assert info["host"] == "example.com"
        assert info["days_until_expiry"] >= 29 # Float precision
        assert info["fingerprint"] == "aabbcc"
        assert info["san"] == ["example.com"]

    @patch("asm.modules.certificates.CertificateMonitor._get_certificate_pem")
    def test_check_certificate_failure(self, mock_get_pem, monitor):
        mock_get_pem.return_value = None
        assert monitor.check_certificate("example.com") is None

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    @patch("OpenSSL.crypto")
    def test_get_certificate_pem(self, mock_openssl, mock_socket, mock_ssl, monitor):
        # Setup socket chain
        mock_sock = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        mock_ssock = MagicMock()
        mock_ctx = MagicMock()
        mock_ssl.return_value = mock_ctx
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        # Mock DER return
        mock_ssock.getpeercert.return_value = b"der_data"
        
        # Mock OpenSSL conversion
        mock_openssl.dump_certificate.return_value = b"pem_data"
        
        pem = monitor._get_certificate_pem("example.com", 443, 10)
        
        assert pem == "pem_data"
        mock_ssock.getpeercert.assert_called_with(binary_form=True)

    @patch("requests.get")
    def test_check_ct_logs(self, mock_get, monitor):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = [
            {
                "id": 123,
                "serial_number": "aabb",
                "name_value": "example.com",
                "issuer_name": "Let's Encrypt"
            },
            {
                 # Duplicate serial, should be deduped
                "id": 124,
                "serial_number": "aabb",
                "name_value": "example.com"
            }
        ]
        mock_get.return_value = mock_response

        certs = monitor.check_ct_logs("example.com")

        assert len(certs) == 1
        assert certs[0]["serial_number"] == "aabb"

    def test_check_certificates_batch_empty(self, monitor):
        """Test batch check with empty host list"""
        results = monitor.check_certificates_batch([])
        assert results == []

    def test_check_certificates_batch_single_host(self, monitor):
        """Test batch check with single host skips thread overhead"""
        with patch.object(monitor, "check_certificate") as mock_check:
            mock_check.return_value = {"host": "example.com", "days_until_expiry": 30}
            results = monitor.check_certificates_batch(["example.com"])

            assert len(results) == 1
            assert results[0]["host"] == "example.com"
            mock_check.assert_called_once_with("example.com", 443, 10)

    def test_check_certificates_batch_single_host_failure(self, monitor):
        """Test batch check with single host that fails"""
        with patch.object(monitor, "check_certificate") as mock_check:
            mock_check.return_value = None
            results = monitor.check_certificates_batch(["example.com"])

            assert len(results) == 1
            assert results[0]["host"] == "example.com"
            assert "error" in results[0]

    def test_check_certificates_batch_multiple_hosts(self, monitor):
        """Test batch check runs multiple hosts in parallel"""
        def mock_check(host, port=443, timeout=10):
            return {"host": host, "days_until_expiry": 30, "issuer": "Test CA"}

        with patch.object(monitor, "check_certificate", side_effect=mock_check):
            hosts = ["host1.example.com", "host2.example.com", "host3.example.com"]
            results = monitor.check_certificates_batch(hosts, workers=3)

            assert len(results) == 3
            result_hosts = {r["host"] for r in results}
            assert result_hosts == set(hosts)

    def test_check_certificates_batch_handles_exceptions(self, monitor):
        """Test batch check handles exceptions gracefully"""
        def mock_check(host, port=443, timeout=10):
            if host == "bad.example.com":
                raise Exception("Connection refused")
            return {"host": host, "days_until_expiry": 30}

        with patch.object(monitor, "check_certificate", side_effect=mock_check):
            hosts = ["good.example.com", "bad.example.com"]
            results = monitor.check_certificates_batch(hosts, workers=2)

            assert len(results) == 2

            good_result = next(r for r in results if r["host"] == "good.example.com")
            assert "error" not in good_result

            bad_result = next(r for r in results if r["host"] == "bad.example.com")
            assert "error" in bad_result
            assert "Connection refused" in bad_result["error"]

    def test_check_certificates_batch_handles_none_results(self, monitor):
        """Test batch check handles None results from check_certificate"""
        def mock_check(host, port=443, timeout=10):
            if host == "nocert.example.com":
                return None
            return {"host": host, "days_until_expiry": 30}

        with patch.object(monitor, "check_certificate", side_effect=mock_check):
            hosts = ["valid.example.com", "nocert.example.com"]
            results = monitor.check_certificates_batch(hosts, workers=2)

            assert len(results) == 2

            valid_result = next(r for r in results if r["host"] == "valid.example.com")
            assert "error" not in valid_result

            nocert_result = next(r for r in results if r["host"] == "nocert.example.com")
            assert "error" in nocert_result


class TestCertificateChainChecker:
    
    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_check_chain_valid(self, mock_socket, mock_ssl):
        # Setup mocks
        mock_ctx = MagicMock()
        mock_ssl.return_value = mock_ctx
        
        mock_ssock = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssock
        
        # Mock getpeercert dict return
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "CA"),),),
            "notBefore": "date",
            "notAfter": "date"
        }
        
        result = CertificateChainChecker.check_chain("example.com")
        
        assert result["chain_valid"] is True
        assert len(result["certificates"]) == 1
        assert result["issues"] == []

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_check_chain_invalid(self, mock_socket, mock_ssl):
        import ssl
        mock_ctx = MagicMock()
        mock_ssl.return_value = mock_ctx
        
        # Raise SSLCertVerificationError
        mock_ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("Verification failed")
        
        result = CertificateChainChecker.check_chain("example.com")
        
        assert result["chain_valid"] is False
        assert len(result["issues"]) > 0
        assert "Verification failed" in result["issues"][0]
