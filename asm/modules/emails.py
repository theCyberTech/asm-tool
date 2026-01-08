"""
Email enumeration module.
Discovers corporate email addresses using Hunter.io, Phonebook.cz, and other sources.
"""

import requests
import re
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

from ..core.config import Config


class EmailEnumerator:
    """Enumerate email addresses for a domain"""

    def __init__(self, config: Config):
        self.config = config
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36"
            ),
            "Accept": "application/json, text/html, */*",
        }

    def enumerate(self, domain: str) -> Dict:
        """
        Enumerate emails for a domain using multiple sources in parallel.

        Runs Hunter, Phonebook, Skymem, and CT logs queries concurrently
        for 2-3x speedup over sequential execution.

        Returns:
            Dict with 'emails', 'sources', and metadata
        """
        results = {
            "domain": domain,
            "emails": [],
            "by_source": {},
            "patterns": [],
            "total": 0,
        }

        all_emails: Set[str] = set()
        sources_used = []

        # Build list of source query tasks
        hunter_key = getattr(self.config, "hunter_api_key", "") or ""

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {}

            # Submit all source queries in parallel
            if hunter_key:
                futures[executor.submit(
                    self._query_hunter, domain, hunter_key
                )] = "hunter.io"

            futures[executor.submit(
                self._query_phonebook, domain
            )] = "phonebook.cz"

            futures[executor.submit(
                self._query_skymem, domain
            )] = "skymem.info"

            futures[executor.submit(
                self._search_ct_logs, domain
            )] = "ct_logs"

            # Collect results as they complete
            for future in as_completed(futures):
                source = futures[future]
                try:
                    result = future.result()

                    # Hunter returns (emails, meta) tuple
                    if source == "hunter.io":
                        emails, meta = result
                        if emails:
                            all_emails.update(emails)
                            results["by_source"][source] = list(emails)
                            sources_used.append(source)
                            if meta.get("pattern"):
                                results["patterns"].append(meta["pattern"])
                    else:
                        # Other sources return just a set of emails
                        if result:
                            all_emails.update(result)
                            results["by_source"][source] = list(result)
                            sources_used.append(source)

                except Exception:
                    # Source failed, continue with others
                    pass

        # Infer email pattern from discovered emails
        if all_emails and not results["patterns"]:
            pattern = self._detect_pattern(all_emails, domain)
            if pattern:
                results["patterns"].append(pattern)

        results["emails"] = sorted(all_emails)
        results["total"] = len(all_emails)
        results["sources"] = sources_used

        return results

    def _query_hunter(self, domain: str, api_key: str) -> tuple:
        """Query Hunter.io API for domain emails"""
        emails = set()
        meta = {}

        try:
            # Domain search endpoint
            url = "https://api.hunter.io/v2/domain-search"
            params = {
                "domain": domain,
                "api_key": api_key,
                "limit": 100,
            }

            response = requests.get(
                url, params=params, timeout=self.config.timeout_http, headers=self.headers
            )

            if response.status_code == 200:
                data = response.json()
                if "data" in data:
                    # Get email pattern
                    meta["pattern"] = data["data"].get("pattern", "")
                    meta["organization"] = data["data"].get("organization", "")

                    # Extract emails
                    for email_data in data["data"].get("emails", []):
                        email = email_data.get("value", "").lower()
                        if email and self._is_valid_email(email):
                            emails.add(email)

            elif response.status_code == 401:
                print("  [!] Hunter.io: Invalid API key")
            elif response.status_code == 429:
                print("  [!] Hunter.io: Rate limit exceeded")

        except Exception:
            pass

        return emails, meta

    def _query_phonebook(self, domain: str) -> Set[str]:
        """Query Phonebook.cz for emails"""
        emails = set()

        try:
            # Phonebook.cz API endpoint
            url = "https://phonebook.cz/api/v1/search"

            # Try the intelligence X phonebook
            url = f"https://phonebook.cz/search?query={quote(domain)}&target=email"

            response = requests.get(
                url,
                timeout=self.config.timeout_http,
                headers={
                    **self.headers,
                    "Accept": "text/html,application/json",
                },
            )

            if response.status_code == 200:
                # Extract emails from response
                content = response.text
                found = self._extract_emails_from_text(content, domain)
                emails.update(found)

        except Exception:
            pass

        # Alternative: Try IntelX phonebook API
        try:
            url = "https://phonebook.cz/api.php"
            data = {
                "input": domain,
                "type": "email",
            }
            response = requests.post(
                url, data=data, timeout=self.config.timeout_http, headers=self.headers
            )
            if response.status_code == 200:
                found = self._extract_emails_from_text(response.text, domain)
                emails.update(found)
        except Exception:
            pass

        return emails

    def _query_skymem(self, domain: str) -> Set[str]:
        """Query Skymem.info for emails"""
        emails = set()

        try:
            # Search for domain
            url = f"https://www.skymem.info/srch?q={quote(domain)}"

            response = requests.get(url, timeout=self.config.timeout_http, headers=self.headers)

            if response.status_code == 200:
                found = self._extract_emails_from_text(response.text, domain)
                emails.update(found)

        except Exception:
            pass

        return emails

    def _search_ct_logs(self, domain: str) -> Set[str]:
        """Search Certificate Transparency logs for emails in cert fields"""
        emails = set()

        try:
            # Query crt.sh for certificates
            url = f"https://crt.sh/?q=%.{domain}&output=json"

            response = requests.get(
                url, timeout=self.config.timeout_http, headers={"User-Agent": "ASM-Tool/1.0"}
            )

            if response.status_code == 200:
                data = response.json()
                for entry in data[:100]:  # Limit entries
                    # Check common_name and name_value for email patterns
                    for field in ["common_name", "name_value", "issuer_name"]:
                        value = entry.get(field, "")
                        if value:
                            found = self._extract_emails_from_text(str(value), domain)
                            emails.update(found)

        except Exception:
            pass

        return emails

    def _extract_emails_from_text(self, text: str, domain: str) -> Set[str]:
        """Extract emails belonging to a domain from text"""
        emails = set()

        # Email regex pattern
        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

        matches = re.findall(pattern, text, re.IGNORECASE)

        for email in matches:
            email = email.lower().strip()
            # Only include emails for target domain
            if email.endswith(f"@{domain.lower()}"):
                if self._is_valid_email(email):
                    emails.add(email)

        return emails

    def _is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        if not email or "@" not in email:
            return False

        # Basic validation
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            return False

        # Filter out obvious non-emails
        invalid_patterns = [
            "example.com",
            "test@",
            "admin@admin",
            "no-reply",
            "noreply",
            "mailer-daemon",
            "postmaster",
            ".png",
            ".jpg",
            ".gif",
        ]

        for invalid in invalid_patterns:
            if invalid in email.lower():
                return False

        return True

    def _detect_pattern(self, emails: Set[str], domain: str) -> str:
        """Detect email naming pattern from discovered emails"""
        if not emails:
            return ""

        patterns = {
            "first": 0,  # john@
            "last": 0,  # smith@
            "firstlast": 0,  # johnsmith@
            "first.last": 0,  # john.smith@
            "first_last": 0,  # john_smith@
            "flast": 0,  # jsmith@
            "firstl": 0,  # johns@
            "f.last": 0,  # j.smith@
            "last.first": 0,  # smith.john@
        }

        for email in emails:
            local = email.split("@")[0].lower()

            if "." in local:
                parts = local.split(".")
                if len(parts) == 2:
                    if len(parts[0]) == 1:
                        patterns["f.last"] += 1
                    elif len(parts[1]) == 1:
                        patterns["firstl"] += 1
                    else:
                        # Could be first.last or last.first
                        patterns["first.last"] += 1
            elif "_" in local:
                patterns["first_last"] += 1
            elif len(local) <= 15:
                # Short could be firstlast, flast, etc
                if len(local) < 8:
                    patterns["flast"] += 1
                else:
                    patterns["firstlast"] += 1

        # Return most common pattern
        if max(patterns.values()) > 0:
            best = max(patterns, key=patterns.get)
            return f"{{{best}}}@{domain}"

        return ""

    def verify_email(self, email: str) -> Dict:
        """Verify if an email exists (basic check)"""
        # Note: Full verification requires SMTP checks which can be intrusive
        # This just does basic format validation
        result = {
            "email": email,
            "valid_format": self._is_valid_email(email),
            "disposable": False,
            "role_account": False,
        }

        # Check for role accounts
        role_prefixes = [
            "admin",
            "info",
            "support",
            "sales",
            "contact",
            "help",
            "billing",
            "hr",
            "jobs",
            "careers",
            "press",
            "media",
            "marketing",
            "legal",
            "abuse",
            "security",
            "privacy",
            "compliance",
            "feedback",
        ]

        local = email.split("@")[0].lower()
        result["role_account"] = any(local.startswith(p) for p in role_prefixes)

        return result

    def enumerate_multiple(self, domains: List[str], workers: int = 5) -> Dict:
        """Enumerate emails for multiple domains in parallel"""
        all_results = {
            "domains": {},
            "total_emails": 0,
            "all_emails": [],
        }

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.enumerate, domain): domain for domain in domains
            }

            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    all_results["domains"][domain] = result
                    all_results["total_emails"] += result["total"]
                    all_results["all_emails"].extend(result["emails"])
                except Exception:
                    pass

        return all_results
