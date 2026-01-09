"""
Cloud storage detection module for discovering exposed S3, Azure Blob, and GCS buckets.

Supports both passive extraction from discovered URLs and active probing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import httpx

from ..core.config import Config
from ..constants.cloud_storage import (
    BUCKET_NAME_SUFFIXES,
    CLOUD_STORAGE_PATTERNS,
    SENSITIVE_KEYWORDS,
)


class CloudStorageDetector:
    """Detect misconfigured cloud storage buckets through passive and active methods."""

    def __init__(self, config: Config):
        self.config = config

    def extract_from_urls(self, urls: List[str]) -> List[Dict]:
        """
        Extract cloud storage bucket references from a list of URLs.

        Performs passive detection by matching URL patterns against known
        S3, Azure Blob, and GCS URL formats.

        Args:
            urls: List of URLs to scan for cloud storage references.

        Returns:
            List of dicts with keys: url, provider, bucket_name, source
        """
        results = []
        seen_buckets = set()

        for url in urls:
            for provider, patterns in CLOUD_STORAGE_PATTERNS.items():
                for pattern in patterns:
                    match = pattern.search(url)
                    if match:
                        bucket_name = match.group(1)
                        bucket_url = self._normalize_bucket_url(
                            url, provider, bucket_name
                        )

                        if bucket_url not in seen_buckets:
                            seen_buckets.add(bucket_url)
                            results.append(
                                {
                                    "url": bucket_url,
                                    "provider": provider,
                                    "bucket_name": bucket_name,
                                    "source": "url_extraction",
                                }
                            )
                        break

        return results

    def _normalize_bucket_url(
        self, original_url: str, provider: str, bucket_name: str
    ) -> str:
        """
        Normalize bucket URL to a canonical form for deduplication.

        Args:
            original_url: The original URL where the bucket was found.
            provider: Cloud provider (s3, azure, gcs).
            bucket_name: Extracted bucket name.

        Returns:
            Normalized canonical URL for the bucket.
        """
        if provider == "s3":
            return f"https://{bucket_name}.s3.amazonaws.com"
        elif provider == "azure":
            return f"https://{bucket_name}.blob.core.windows.net"
        elif provider == "gcs":
            return f"https://storage.googleapis.com/{bucket_name}"
        return original_url

    def probe_buckets(self, domain: str, workers: int = 10) -> List[Dict]:
        """
        Actively probe for common bucket naming patterns based on a domain.

        Generates bucket name permutations using the domain base name and common
        suffixes, then probes for existence across S3, Azure, and GCS.

        Args:
            domain: Target domain to derive bucket names from.
            workers: Number of parallel workers for probing (default 10).

        Returns:
            List of dicts with keys: url, provider, bucket_name, source
        """
        base_name = self._extract_base_name(domain)
        bucket_urls = self._generate_bucket_urls(base_name)

        results = []
        seen_buckets = set()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_bucket = {
                executor.submit(self._probe_url, url): (url, provider, bucket_name)
                for url, provider, bucket_name in bucket_urls
            }

            for future in as_completed(future_to_bucket):
                url, provider, bucket_name = future_to_bucket[future]
                try:
                    exists = future.result()
                    if exists and url not in seen_buckets:
                        seen_buckets.add(url)
                        results.append(
                            {
                                "url": url,
                                "provider": provider,
                                "bucket_name": bucket_name,
                                "source": "active_probe",
                            }
                        )
                except Exception:
                    pass

        return results

    def _extract_base_name(self, domain: str) -> str:
        """
        Extract the base name from a domain for bucket permutation.

        Args:
            domain: Domain name (e.g., 'example.com', 'sub.example.co.uk').

        Returns:
            Base name suitable for bucket permutations (e.g., 'example').
        """
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            if parts[-1] in ("uk", "au", "jp") and parts[-2] in ("co", "com", "org"):
                return parts[-3] if len(parts) >= 3 else parts[0]
            return parts[-2]
        return parts[0]

    def _generate_bucket_urls(
        self, base_name: str
    ) -> List[tuple[str, str, str]]:
        """
        Generate all bucket URL permutations to probe.

        Args:
            base_name: Base name extracted from the domain.

        Returns:
            List of (url, provider, bucket_name) tuples to probe.
        """
        bucket_urls = []

        bucket_names = [base_name]
        for suffix in BUCKET_NAME_SUFFIXES:
            bucket_names.append(f"{base_name}-{suffix}")
            bucket_names.append(f"{base_name}_{suffix}")

        for bucket_name in bucket_names:
            bucket_urls.append(
                (f"https://{bucket_name}.s3.amazonaws.com", "s3", bucket_name)
            )
            bucket_urls.append(
                (
                    f"https://{bucket_name}.blob.core.windows.net",
                    "azure",
                    bucket_name,
                )
            )
            bucket_urls.append(
                (
                    f"https://storage.googleapis.com/{bucket_name}",
                    "gcs",
                    bucket_name,
                )
            )

        return bucket_urls

    def _probe_url(self, url: str) -> bool:
        """
        Probe a single bucket URL to check if it exists.

        Args:
            url: Bucket URL to probe.

        Returns:
            True if the bucket exists (returns non-404/non-DNS-error), False otherwise.
        """
        try:
            response = httpx.head(url, timeout=5.0, follow_redirects=True)
            return response.status_code != 404
        except (httpx.RequestError, httpx.TimeoutException):
            return False

    def check_access(self, bucket_url: str, provider: str) -> Dict:
        """
        Check the public access level of a cloud storage bucket.

        Probes the bucket to determine if it allows listing, public read,
        or requires authentication.

        Args:
            bucket_url: The bucket URL to check.
            provider: Cloud provider (s3, azure, gcs).

        Returns:
            Dict with keys: access_level, evidence
            access_level is one of: 'listing_enabled', 'public_read',
                                    'authenticated_only', 'not_found'
        """
        if provider == "s3":
            return self._check_s3_access(bucket_url)
        elif provider == "azure":
            return self._check_azure_access(bucket_url)
        elif provider == "gcs":
            return self._check_gcs_access(bucket_url)
        return {"access_level": "not_found", "evidence": "Unknown provider"}

    def _check_s3_access(self, bucket_url: str) -> Dict:
        """
        Check S3 bucket access level.

        Args:
            bucket_url: S3 bucket URL (e.g., https://bucket.s3.amazonaws.com).

        Returns:
            Dict with access_level and evidence.
        """
        try:
            list_response = httpx.get(
                f"{bucket_url}/?list-type=2", timeout=5.0, follow_redirects=True
            )

            if list_response.status_code == 200:
                snippet = list_response.text[:500] if list_response.text else ""
                return {
                    "access_level": "listing_enabled",
                    "evidence": f"Status {list_response.status_code}: {snippet}",
                }

            if list_response.status_code == 404:
                return {
                    "access_level": "not_found",
                    "evidence": f"Status {list_response.status_code}",
                }

            read_response = httpx.get(
                bucket_url, timeout=5.0, follow_redirects=True
            )

            if read_response.status_code == 200:
                snippet = read_response.text[:500] if read_response.text else ""
                return {
                    "access_level": "public_read",
                    "evidence": f"Status {read_response.status_code}: {snippet}",
                }

            return {
                "access_level": "authenticated_only",
                "evidence": f"List status {list_response.status_code}, Read status {read_response.status_code}",
            }

        except (httpx.RequestError, httpx.TimeoutException) as e:
            return {
                "access_level": "not_found",
                "evidence": f"Request error: {str(e)}",
            }

    def _check_azure_access(self, bucket_url: str) -> Dict:
        """
        Check Azure Blob storage container access level.

        Args:
            bucket_url: Azure Blob URL (e.g., https://account.blob.core.windows.net).

        Returns:
            Dict with access_level and evidence.
        """
        try:
            list_response = httpx.get(
                f"{bucket_url}/?restype=container&comp=list",
                timeout=5.0,
                follow_redirects=True,
            )

            if list_response.status_code == 200:
                snippet = list_response.text[:500] if list_response.text else ""
                return {
                    "access_level": "listing_enabled",
                    "evidence": f"Status {list_response.status_code}: {snippet}",
                }

            if list_response.status_code == 404:
                return {
                    "access_level": "not_found",
                    "evidence": f"Status {list_response.status_code}",
                }

            read_response = httpx.get(
                bucket_url, timeout=5.0, follow_redirects=True
            )

            if read_response.status_code == 200:
                snippet = read_response.text[:500] if read_response.text else ""
                return {
                    "access_level": "public_read",
                    "evidence": f"Status {read_response.status_code}: {snippet}",
                }

            return {
                "access_level": "authenticated_only",
                "evidence": f"List status {list_response.status_code}, Read status {read_response.status_code}",
            }

        except (httpx.RequestError, httpx.TimeoutException) as e:
            return {
                "access_level": "not_found",
                "evidence": f"Request error: {str(e)}",
            }

    def _check_gcs_access(self, bucket_url: str) -> Dict:
        """
        Check Google Cloud Storage bucket access level.

        Args:
            bucket_url: GCS bucket URL (e.g., https://storage.googleapis.com/bucket).

        Returns:
            Dict with access_level and evidence.
        """
        bucket_name = bucket_url.rstrip("/").split("/")[-1]

        try:
            list_response = httpx.get(
                f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o",
                timeout=5.0,
                follow_redirects=True,
            )

            if list_response.status_code == 200:
                snippet = list_response.text[:500] if list_response.text else ""
                return {
                    "access_level": "listing_enabled",
                    "evidence": f"Status {list_response.status_code}: {snippet}",
                }

            if list_response.status_code == 404:
                return {
                    "access_level": "not_found",
                    "evidence": f"Status {list_response.status_code}",
                }

            read_response = httpx.get(
                bucket_url, timeout=5.0, follow_redirects=True
            )

            if read_response.status_code == 200:
                snippet = read_response.text[:500] if read_response.text else ""
                return {
                    "access_level": "public_read",
                    "evidence": f"Status {read_response.status_code}: {snippet}",
                }

            return {
                "access_level": "authenticated_only",
                "evidence": f"List status {list_response.status_code}, Read status {read_response.status_code}",
            }

        except (httpx.RequestError, httpx.TimeoutException) as e:
            return {
                "access_level": "not_found",
                "evidence": f"Request error: {str(e)}",
            }

    def classify_severity(self, access_level: str, bucket_name: str) -> str:
        """
        Classify the severity of a cloud storage finding.

        Severity is based on access level and whether the bucket name
        contains keywords indicating sensitive content.

        Args:
            access_level: The access level from check_access() - one of
                'listing_enabled', 'public_read', 'authenticated_only', 'not_found'.
            bucket_name: The name of the bucket to check for sensitive keywords.

        Returns:
            Severity level: 'critical', 'high', 'medium', or 'low'.
        """
        bucket_lower = bucket_name.lower()
        has_sensitive_keyword = any(
            keyword in bucket_lower for keyword in SENSITIVE_KEYWORDS
        )

        if access_level == "listing_enabled":
            if has_sensitive_keyword:
                return "critical"
            return "high"
        elif access_level == "public_read":
            return "medium"
        else:
            return "low"
