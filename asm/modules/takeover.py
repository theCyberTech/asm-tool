"""
Subdomain takeover detection module.
Detects dangling CNAME records pointing to unclaimed services.
Fingerprints based on can-i-take-over-xyz project.
"""

import subprocess
import dns.resolver
import requests
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..core.config import Config
from ..core.validation import validate_domain, validate_subdomain
from ..constants.takeover_fingerprints import TakeoverFingerprint, FINGERPRINTS


class TakeoverDetector:
    """Detect potential subdomain takeover vulnerabilities"""

    def __init__(self, config: Config):
        self.config = config
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.timeout_dns
        self.resolver.lifetime = config.timeout_dns * 2

    def check_domain(self, domain: str) -> Optional[Dict]:
        """
        Check a single domain for takeover vulnerability.
        Returns finding dict if vulnerable, None otherwise.
        """
        validated_domain = validate_domain(domain)
        # Get CNAME record
        cname = self._get_cname(validated_domain)
        if not cname:
            return None

        # Check against fingerprints
        for fp in FINGERPRINTS:
            if self._matches_cname(cname, fp.cnames):
                # Check if actually vulnerable
                vulnerability = self._verify_vulnerability(domain, cname, fp)
                if vulnerability:
                    return vulnerability

        return None

    def check_subdomains(self, subdomains: List[str], workers: int = 10) -> List[Dict]:
        """
        Check multiple subdomains for takeover vulnerabilities.
        Returns list of vulnerable findings.
        """
        validated_subdomains = [validate_subdomain(sub) for sub in subdomains]
        vulnerabilities = []

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.check_domain, subdomain): subdomain
                for subdomain in validated_subdomains
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                except Exception:
                    pass  # Silently skip errors

        return vulnerabilities

    def _get_cname(self, domain: str) -> Optional[str]:
        """Get CNAME record for domain"""
        try:
            answers = self.resolver.resolve(domain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            pass
        except Exception:
            pass
        return None

    def _matches_cname(self, cname: str, patterns: List[str]) -> bool:
        """Check if CNAME matches any of the patterns"""
        cname_lower = cname.lower()
        return any(pattern.lower() in cname_lower for pattern in patterns)

    def _verify_vulnerability(
        self, domain: str, cname: str, fingerprint: TakeoverFingerprint
    ) -> Optional[Dict]:
        """Verify if the domain is actually vulnerable"""

        # Check NXDOMAIN vulnerability
        if fingerprint.nxdomain:
            if self._check_nxdomain(cname):
                return {
                    "subdomain": domain,
                    "cname": cname,
                    "service": fingerprint.service,
                    "type": "NXDOMAIN",
                    "confidence": "HIGH",
                    "evidence": f"CNAME target {cname} does not resolve (NXDOMAIN)",
                    "documentation": fingerprint.documentation,
                }

        # Check HTTP response fingerprints
        http_result = self._check_http_fingerprint(domain, fingerprint)
        if http_result:
            return {
                "subdomain": domain,
                "cname": cname,
                "service": fingerprint.service,
                "type": "HTTP_FINGERPRINT",
                "confidence": "HIGH",
                "evidence": http_result,
                "documentation": fingerprint.documentation,
            }

        return None

    def _check_nxdomain(self, cname: str) -> bool:
        """Check if CNAME target returns NXDOMAIN"""
        try:
            self.resolver.resolve(cname, "A")
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    def _check_http_fingerprint(
        self, domain: str, fingerprint: TakeoverFingerprint
    ) -> Optional[str]:
        """Check HTTP response for vulnerability fingerprints"""
        for protocol in ["https", "http"]:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(
                    url,
                    timeout=self.config.timeout_http,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 ASM-Tool/1.0"},
                )

                # Check status code if specified
                if (
                    fingerprint.http_status
                    and response.status_code != fingerprint.http_status
                ):
                    continue

                # Check response body for fingerprints
                body = response.text
                for fp_string in fingerprint.fingerprints:
                    if fp_string.lower() in body.lower():
                        return f'Found "{fp_string}" in HTTP response'

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        return None

    def run_subjack(self, subdomains: List[str]) -> List[Dict]:
        """
        Run subjack tool if available for additional detection.
        Returns list of findings.
        """
        try:
            validated_subdomains = [validate_subdomain(sub) for sub in subdomains]
            # Write subdomains to temp file
            import tempfile

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                for sub in validated_subdomains:
                    f.write(f"{sub}\n")
                temp_file = f.name

            result = subprocess.run(
                [
                    "subjack",
                    "-w",
                    temp_file,
                    "-t",
                    "20",
                    "-timeout",
                    "30",
                    "-o",
                    "/dev/stdout",
                    "-ssl",
                ],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_subfinder,
            )

            findings = []
            for line in result.stdout.splitlines():
                if "[Vulnerable]" in line or "Vulnerable" in line:
                    # Parse subjack output
                    parts = line.split()
                    if parts:
                        findings.append(
                            {
                                "subdomain": parts[0] if parts else "unknown",
                                "service": "Unknown (subjack)",
                                "type": "SUBJACK",
                                "confidence": "MEDIUM",
                                "evidence": line,
                                "documentation": "",
                            }
                        )

            # Cleanup
            import os

            os.unlink(temp_file)

            return findings

        except FileNotFoundError:
            return []  # subjack not installed
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []

    def get_all_fingerprints(self) -> List[Dict]:
        """Return all known fingerprints for reference"""
        return [
            {
                "service": fp.service,
                "cnames": fp.cnames,
                "nxdomain": fp.nxdomain,
                "documentation": fp.documentation,
            }
            for fp in FINGERPRINTS
        ]
