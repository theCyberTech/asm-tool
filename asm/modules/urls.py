"""
URL enumeration module using GAU (GetAllURLs)
Discovers historical URLs from Wayback Machine, Common Crawl, and other sources.
"""

import subprocess
import json
import re
from typing import Set, List, Dict, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.config import Config
from ..core.validation import validate_domain


class URLEnumerator:
    """Enumerate historical URLs using GAU and other sources"""

    # File extensions to filter by category
    EXTENSIONS = {
        "js": [".js", ".mjs", ".jsx", ".ts", ".tsx"],
        "api": [".json", ".xml", ".graphql"],
        "config": [".env", ".config", ".yaml", ".yml", ".toml", ".ini", ".conf"],
        "backup": [".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp"],
        "archive": [".zip", ".tar", ".gz", ".rar", ".7z"],
        "data": [".sql", ".csv", ".xlsx", ".db", ".sqlite"],
        "docs": [".pdf", ".doc", ".docx", ".txt", ".md"],
        "media": [".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".mp4", ".webp"],
    }

    # Patterns that might indicate sensitive endpoints
    INTERESTING_PATTERNS = [
        r"/api/",
        r"/v[0-9]+/",
        r"/admin",
        r"/dashboard",
        r"/login",
        r"/auth",
        r"/oauth",
        r"/graphql",
        r"/swagger",
        r"/docs",
        r"/debug",
        r"/test",
        r"/dev",
        r"/staging",
        r"/internal",
        r"/private",
        r"/config",
        r"/backup",
        r"/\.env",
        r"/\.git",
        r"/wp-admin",
        r"/wp-content",
        r"/phpinfo",
        r"/actuator",
        r"/console",
        r"/manager",
        r"/jenkins",
        r"\.(json|xml|yaml|yml)$",
        r"\?.*=(http|https|ftp)",  # Potential SSRF
        r"\?.*=\.\.",  # Path traversal
        r"redirect",
        r"callback",
        r"return",
        r"next=",
        r"url=",
        r"dest=",
        r"file=",
        r"path=",
        r"include=",
        r"page=",
        r"document=",
    ]

    def __init__(self, config: Config):
        self.config = config

    def enumerate(
        self,
        domain: str,
        include_subdomains: bool = True,
        providers: Optional[List[str]] = None,
    ) -> Dict:
        """
        Run URL enumeration and return categorized results.

        Args:
            domain: Target domain to enumerate
            include_subdomains: Whether to include subdomains in results
            providers: List of providers to use (wayback, commoncrawl, otx, urlscan)

        Returns:
            Dict with 'urls', 'interesting', 'by_extension', and 'parameters'
        """
        validated_domain = validate_domain(domain)
        results: Set[str] = set()

        # Run GAU
        gau_results = self._run_gau(validated_domain, include_subdomains, providers)
        results.update(gau_results)

        # Filter and validate results
        valid_results = self._filter_results(results, validated_domain)

        # Categorize results
        categorized = self._categorize_urls(valid_results, domain)

        return categorized

    def _run_gau(
        self,
        domain: str,
        include_subdomains: bool = True,
        providers: Optional[List[str]] = None,
    ) -> Set[str]:
        """Run GAU for URL enumeration"""
        try:
            cmd = [
                "gau",
                "--blacklist",
                "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css",
            ]

            if include_subdomains:
                cmd.append("--subs")

            if providers:
                cmd.extend(["--providers", ",".join(providers)])

            cmd.append(domain)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
            )

            urls = set()
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and line.startswith(("http://", "https://")):
                    urls.add(line)

            return urls

        except FileNotFoundError:
            print(
                "  [!] gau not found. Please install: go install github.com/lc/gau/v2/cmd/gau@latest"
            )
            return set()
        except subprocess.TimeoutExpired:
            print("  [!] gau timed out after 10 minutes")
            return set()
        except Exception as e:
            print(f"  [!] gau error: {e}")
            return set()

    def _filter_results(self, results: Set[str], domain: str) -> Set[str]:
        """Filter and validate URL results"""
        valid = set()
        domain_lower = domain.lower()

        for url in results:
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lower()

                # Must be related to target domain
                if not host.endswith(domain_lower):
                    continue

                # Skip empty paths
                if not parsed.path or parsed.path == "/":
                    # Only skip if no query string
                    if not parsed.query:
                        continue

                # Skip obviously invalid URLs
                if len(url) > 2000:
                    continue

                valid.add(url)

            except Exception:
                continue

        return valid

    def _categorize_urls(self, urls: Set[str], domain: str) -> Dict:
        """Categorize URLs by type, extension, and interestingness"""
        result = {
            "total": len(urls),
            "urls": sorted(urls),
            "interesting": [],
            "by_extension": {},
            "parameters": {},
            "unique_paths": set(),
            "endpoints": set(),
        }

        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()
                query = parsed.query

                # Track unique paths (without query strings)
                base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                result["unique_paths"].add(base_path)

                # Extract endpoint (path without file)
                endpoint = (
                    "/".join(path.split("/")[:-1])
                    if "." in path.split("/")[-1]
                    else path
                )
                if endpoint:
                    result["endpoints"].add(endpoint)

                # Categorize by extension
                for category, extensions in self.EXTENSIONS.items():
                    if any(path.endswith(ext) for ext in extensions):
                        if category not in result["by_extension"]:
                            result["by_extension"][category] = []
                        result["by_extension"][category].append(url)
                        break

                # Extract parameters
                if query:
                    params = query.split("&")
                    for param in params:
                        if "=" in param:
                            key = param.split("=")[0]
                            if key not in result["parameters"]:
                                result["parameters"][key] = []
                            if len(result["parameters"][key]) < 5:  # Limit examples
                                result["parameters"][key].append(url)

                # Check for interesting patterns
                for pattern in self.INTERESTING_PATTERNS:
                    if re.search(pattern, url, re.IGNORECASE):
                        if url not in result["interesting"]:
                            result["interesting"].append(url)
                        break

            except Exception:
                continue

        # Convert sets to sorted lists for JSON serialization
        result["unique_paths"] = sorted(result["unique_paths"])
        result["endpoints"] = sorted(result["endpoints"])

        return result

    def get_js_files(self, domain: str) -> List[str]:
        """Convenience method to get only JavaScript files"""
        results = self.enumerate(domain)
        return results.get("by_extension", {}).get("js", [])

    def get_api_endpoints(self, domain: str) -> List[str]:
        """Convenience method to get potential API endpoints"""
        results = self.enumerate(domain)
        api_urls = []

        for url in results.get("urls", []):
            if re.search(r"/api/|/v[0-9]+/|\.json|graphql", url, re.IGNORECASE):
                api_urls.append(url)

        return sorted(set(api_urls))

    def get_parameters(self, domain: str) -> Dict[str, List[str]]:
        """Convenience method to get discovered parameters"""
        results = self.enumerate(domain)
        return results.get("parameters", {})
