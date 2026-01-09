"""
Cloud storage detection module for discovering exposed S3, Azure Blob, and GCS buckets.

Supports both passive extraction from discovered URLs and active probing.
"""

from typing import Dict, List

from ..core.config import Config
from ..constants.cloud_storage import CLOUD_STORAGE_PATTERNS


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
