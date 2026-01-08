"""
Nuclei vulnerability scanner integration
"""

import subprocess
import json
import tempfile
import os
from typing import Dict, List, Optional

from ..core.config import Config
from ..core.validation import validate_domain


class NucleiScanner:
    """Vulnerability scanning using Nuclei"""

    def __init__(self, config: Config):
        self.config = config
        self.nuclei_available = self._check_nuclei()

    def _check_nuclei(self) -> bool:
        """Check if nuclei is available"""
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, timeout=10)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(
        self,
        targets: List[str],
        severity: str = "medium,high,critical",
        tags: str = "",
        templates: str = "",
        exclude_tags: str = "",
    ) -> List[Dict]:
        """Run nuclei scan on targets"""
        if not self.nuclei_available:
            return []

        validated_targets = [validate_domain(target) for target in targets]
        findings = []

        # Create temp file for targets
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for target in validated_targets:
                # Add protocol if not present
                if not target.startswith(("http://", "https://")):
                    f.write(f"https://{target}\n")
                    f.write(f"http://{target}\n")
                else:
                    f.write(f"{target}\n")
            targets_file = f.name

        # Create temp file for output
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_file = f.name

        try:
            cmd = [
                "nuclei",
                "-l",
                targets_file,
                "-jsonl",
                "-o",
                output_file,
                "-severity",
                severity,
                "-silent",
                "-rate-limit",
                str(self.config.scan_rate_limit),
                "-timeout",
                "10",
                "-retries",
                str(self.config.nuclei_retries),
                "-no-update-templates",
                # Optimization flags for 2-4x speedup
                "-c",
                str(self.config.nuclei_concurrency),  # concurrent templates
                "-bs",
                str(self.config.nuclei_batch_size),  # batch size
            ]

            if tags:
                cmd.extend(["-tags", tags])

            if templates:
                cmd.extend(["-t", templates])

            # Apply exclude_tags: use param if provided, otherwise use config default
            effective_exclude_tags = exclude_tags or self.config.nuclei_exclude_tags
            if effective_exclude_tags:
                cmd.extend(["-exclude-tags", effective_exclude_tags])

            # Run nuclei
            subprocess.run(cmd, capture_output=True, timeout=self.config.timeout_nuclei)

            # Parse results
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                findings.append(self._parse_finding(data))
                            except json.JSONDecodeError:
                                pass

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            print(f"Nuclei scan error: {e}")
        finally:
            # Cleanup
            if os.path.exists(targets_file):
                os.unlink(targets_file)
            if os.path.exists(output_file):
                os.unlink(output_file)

        return findings

    def _parse_finding(self, data: Dict) -> Dict:
        """Parse nuclei JSON output into standardized format"""
        info = data.get("info", {})

        return {
            "template_id": data.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", "unknown"),
            "description": info.get("description", ""),
            "reference": info.get("reference", []),
            "tags": info.get("tags", []),
            "host": data.get("host", ""),
            "matched_at": data.get("matched-at", ""),
            "matcher_name": data.get("matcher-name", ""),
            "extracted_results": data.get("extracted-results", []),
            "curl_command": data.get("curl-command", ""),
            "type": data.get("type", ""),
            "ip": data.get("ip", ""),
            "timestamp": data.get("timestamp", ""),
        }

    def scan_single(self, target: str, template_id: str) -> Optional[Dict]:
        """Run a single template against a target"""
        if not self.nuclei_available:
            return None

        try:
            cmd = ["nuclei", "-u", target, "-t", template_id, "-jsonl", "-silent"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            if result.stdout.strip():
                data = json.loads(result.stdout.strip())
                return self._parse_finding(data)

        except Exception:
            pass

        return None

    def update_templates(self) -> bool:
        """Update nuclei templates"""
        if not self.nuclei_available:
            return False

        try:
            subprocess.run(["nuclei", "-update-templates"], timeout=300)
            return True
        except Exception:
            return False

    def list_templates(self, tags: str = "") -> List[str]:
        """List available nuclei templates"""
        if not self.nuclei_available:
            return []

        try:
            cmd = ["nuclei", "-tl"]
            if tags:
                cmd.extend(["-tags", tags])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except Exception:
            return []


class CustomScanner:
    """Run custom security checks"""

    def __init__(self, config: Config):
        self.config = config

    def check_security_headers(self, url: str) -> Dict:
        """Check for security headers"""
        import requests

        results = {
            "url": url,
            "headers_present": [],
            "headers_missing": [],
            "recommendations": [],
        }

        required_headers = {
            "Strict-Transport-Security": "HSTS not set - enable HSTS",
            "X-Content-Type-Options": 'X-Content-Type-Options not set - add "nosniff"',
            "X-Frame-Options": "X-Frame-Options not set - prevents clickjacking",
            "X-XSS-Protection": "X-XSS-Protection not set",
            "Content-Security-Policy": "CSP not set - helps prevent XSS",
            "Referrer-Policy": "Referrer-Policy not set",
            "Permissions-Policy": "Permissions-Policy not set",
        }

        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = {k.lower(): v for k, v in response.headers.items()}

            for header, recommendation in required_headers.items():
                if header.lower() in headers:
                    results["headers_present"].append(header)
                else:
                    results["headers_missing"].append(header)
                    results["recommendations"].append(recommendation)

        except Exception as e:
            results["error"] = str(e)

        return results

    def check_cors(self, url: str) -> Dict:
        """Check CORS configuration"""
        import requests

        results = {
            "url": url,
            "cors_enabled": False,
            "allows_any_origin": False,
            "allows_credentials": False,
            "issues": [],
        }

        try:
            # Test with arbitrary origin
            headers = {"Origin": "https://evil.com"}
            response = requests.options(url, headers=headers, timeout=10, verify=False)

            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")

            if acao:
                results["cors_enabled"] = True

                if acao == "*":
                    results["allows_any_origin"] = True
                    results["issues"].append("CORS allows any origin (*)")

                if acao == "https://evil.com":
                    results["issues"].append("CORS reflects arbitrary origin")

                if acac.lower() == "true":
                    results["allows_credentials"] = True
                    if results["allows_any_origin"]:
                        results["issues"].append(
                            "Critical: CORS allows credentials with any origin"
                        )

        except Exception as e:
            results["error"] = str(e)

        return results
