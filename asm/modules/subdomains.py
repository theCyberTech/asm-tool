"""
Subdomain enumeration module
Uses multiple sources: subfinder, assetfinder, certificate transparency, etc.
"""

import subprocess
import json
import requests
from typing import Set, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.config import Config
from ..core.validation import validate_domain


class SubdomainEnumerator:
    """Enumerate subdomains using multiple techniques"""

    def __init__(self, config: Config):
        self.config = config

    def enumerate(self, domain: str, passive_only: bool = False) -> List[str]:
        """Run subdomain enumeration and return unique results"""
        validated_domain = validate_domain(domain)
        results: Set[str] = set()

        # Always run passive techniques
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self._run_subfinder, validated_domain): "subfinder",
                executor.submit(self._run_assetfinder, validated_domain): "assetfinder",
                executor.submit(self._query_crtsh, validated_domain): "crt.sh",
                executor.submit(
                    self._query_hackertarget, validated_domain
                ): "hackertarget",
            }

            for future in as_completed(futures):
                source = futures[future]
                try:
                    found = future.result()
                    results.update(found)
                except Exception as e:
                    print(f"  [!] {source} failed: {e}")

        # Filter and validate results
        valid_results = self._filter_results(results, validated_domain)

        return sorted(valid_results)

    def _run_subfinder(self, domain: str) -> Set[str]:
        """Run subfinder for subdomain enumeration"""
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-all"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            return set(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        except FileNotFoundError:
            return set()
        except subprocess.TimeoutExpired:
            return set()

    def _run_assetfinder(self, domain: str) -> Set[str]:
        """Run assetfinder for subdomain enumeration"""
        try:
            result = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                capture_output=True,
                text=True,
                timeout=120,
            )
            return set(
                line.strip() for line in result.stdout.splitlines() if line.strip()
            )
        except FileNotFoundError:
            return set()
        except subprocess.TimeoutExpired:
            return set()

    def _query_crtsh(self, domain: str) -> Set[str]:
        """Query certificate transparency logs via crt.sh"""
        results = set()
        try:
            response = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30,
                headers={"User-Agent": "ASM-Tool/1.0"},
            )
            if response.ok:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Handle wildcard and multi-line entries
                    for line in name.split("\n"):
                        line = line.strip().lstrip("*.")
                        if line and domain in line:
                            results.add(line.lower())
        except Exception:
            pass
        return results

    def _query_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API for subdomains"""
        results = set()
        try:
            response = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=30,
                headers={"User-Agent": "ASM-Tool/1.0"},
            )
            if response.ok and "error" not in response.text.lower():
                for line in response.text.splitlines():
                    if "," in line:
                        subdomain = line.split(",")[0].strip()
                        if subdomain:
                            results.add(subdomain.lower())
        except Exception:
            pass
        return results

    def _query_shodan(self, domain: str) -> Set[str]:
        """Query Shodan for subdomains (requires API key)"""
        if not self.config.shodan_enabled or not self.config.shodan_api_key:
            return set()

        results = set()
        try:
            import shodan

            api = shodan.Shodan(self.config.shodan_api_key)

            # Search for SSL certificates
            query = f"ssl.cert.subject.cn:{domain}"
            for banner in api.search_cursor(query):
                hostnames = banner.get("hostnames", [])
                results.update(h.lower() for h in hostnames if domain in h.lower())
        except Exception:
            pass
        return results

    def _filter_results(self, results: Set[str], domain: str) -> Set[str]:
        """Filter and validate subdomain results"""
        valid = set()
        domain_lower = domain.lower()

        for subdomain in results:
            subdomain = subdomain.lower().strip()

            # Must end with the target domain
            if not subdomain.endswith(domain_lower):
                continue

            # Remove wildcards
            if "*" in subdomain:
                continue

            # Basic validation
            if len(subdomain) > 253:
                continue

            # Check for valid characters
            if not all(c.isalnum() or c in ".-" for c in subdomain):
                continue

            valid.add(subdomain)

        return valid
