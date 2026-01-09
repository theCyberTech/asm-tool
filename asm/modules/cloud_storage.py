"""
Cloud storage detection module for discovering exposed S3, Azure Blob, and GCS buckets.

Supports both passive extraction from discovered URLs and active probing.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import httpx

from ..core.config import Config
from ..constants.cloud_storage import BUCKET_NAME_SUFFIXES, CLOUD_STORAGE_PATTERNS


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
