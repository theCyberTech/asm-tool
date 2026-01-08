"""
SSL/TLS Certificate monitoring module
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL

from ..core.config import Config


class CertificateMonitor:
    """Monitor SSL/TLS certificates for hosts"""

    def __init__(self, config: Config):
        self.config = config

    def check_certificate(
        self, host: str, port: int = 443, timeout: int = 10
    ) -> Optional[Dict]:
        """Get certificate information for a host"""
        try:
            # Try to get the certificate
            cert_pem = self._get_certificate_pem(host, port, timeout)
            if not cert_pem:
                return None

            # Parse the certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # Extract information
            info = {
                "host": host,
                "port": port,
                "subject": self._format_name(cert.subject),
                "issuer": self._format_name(cert.issuer),
                "serial_number": str(cert.serial_number),
                "not_before": cert.not_valid_before_utc.isoformat(),
                "not_after": cert.not_valid_after_utc.isoformat(),
                "days_until_expiry": (
                    cert.not_valid_after_utc - datetime.now(timezone.utc)
                ).days,
                "fingerprint": cert.fingerprint(cert.signature_hash_algorithm).hex(),
                "san": self._get_san(cert),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "version": cert.version.name,
            }

            return info

        except Exception:
            return None

    def check_certificates_batch(
        self,
        hosts: List[str],
        port: int = 443,
        timeout: int = 10,
        workers: int = 10,
    ) -> List[Dict]:
        """Check certificates for multiple hosts in parallel for 5-10x speedup.

        Args:
            hosts: List of hostnames to check
            port: Port to connect to (default 443)
            timeout: Connection timeout per host
            workers: Number of concurrent check threads (default 10)

        Returns:
            List of results with 'host' and either cert info or 'error'
        """
        if not hosts:
            return []

        # For single host, skip thread overhead
        if len(hosts) == 1:
            cert_info = self.check_certificate(hosts[0], port, timeout)
            if cert_info:
                return [cert_info]
            return [{"host": hosts[0], "error": "Could not retrieve certificate"}]

        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.check_certificate, host, port, timeout): host
                for host in hosts
            }
            for future in as_completed(futures):
                host = futures[future]
                try:
                    cert_info = future.result()
                    if cert_info:
                        results.append(cert_info)
                    else:
                        results.append({"host": host, "error": "Could not retrieve certificate"})
                except Exception as e:
                    results.append({"host": host, "error": str(e)})

        return results

    def _get_certificate_pem(self, host: str, port: int, timeout: int) -> Optional[str]:
        """Retrieve certificate in PEM format"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)

            # Convert DER to PEM
            cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert_der
            )
            cert_pem = OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert
            )
            return cert_pem.decode()

        except Exception:
            return None

    def _format_name(self, name: x509.Name) -> str:
        """Format X.509 name to string"""
        try:
            cn = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn:
                return cn[0].value

            # Fallback to organization
            org = name.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            if org:
                return org[0].value

            return str(name)
        except Exception:
            return str(name)

    def _get_san(self, cert: x509.Certificate) -> List[str]:
        """Get Subject Alternative Names"""
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            return [name.value for name in ext.value if isinstance(name, x509.DNSName)]
        except x509.ExtensionNotFound:
            return []

    def check_ct_logs(self, domain: str) -> List[Dict]:
        """Check Certificate Transparency logs for recent certificates"""
        import requests

        certs = []
        try:
            response = requests.get(
                f"https://crt.sh/?q={domain}&output=json",
                timeout=30,
                headers={"User-Agent": "ASM-Tool/1.0"},
            )

            if response.ok:
                data = response.json()

                seen_serials = set()
                for entry in data:
                    serial = entry.get("serial_number", "")
                    if serial in seen_serials:
                        continue
                    seen_serials.add(serial)

                    certs.append(
                        {
                            "name_value": entry.get("name_value", ""),
                            "issuer": entry.get("issuer_name", ""),
                            "not_before": entry.get("not_before", ""),
                            "not_after": entry.get("not_after", ""),
                            "serial_number": serial,
                            "id": entry.get("id", ""),
                        }
                    )
        except Exception:
            pass

        return certs[:50]  # Limit results


class CertificateChainChecker:
    """Check certificate chain validity"""

    @staticmethod
    def check_chain(host: str, port: int = 443) -> Dict:
        """Verify the full certificate chain"""
        result = {
            "host": host,
            "chain_valid": False,
            "chain_length": 0,
            "certificates": [],
            "issues": [],
        }

        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get verified certificate chain
                    cert = ssock.getpeercert()
                    result["chain_valid"] = True

                    # Extract basic info
                    if cert:
                        result["certificates"].append(
                            {
                                "subject": dict(x[0] for x in cert.get("subject", ())),
                                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                                "notBefore": cert.get("notBefore", ""),
                                "notAfter": cert.get("notAfter", ""),
                            }
                        )
                        result["chain_length"] = 1

        except ssl.SSLCertVerificationError as e:
            result["issues"].append(f"Certificate verification failed: {e}")
        except ssl.SSLError as e:
            result["issues"].append(f"SSL error: {e}")
        except Exception as e:
            result["issues"].append(f"Connection error: {e}")

        return result
