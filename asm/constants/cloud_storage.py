"""
Cloud storage URL patterns and naming conventions for bucket detection.
"""
import re

# S3 bucket URL patterns
S3_PATTERNS = [
    re.compile(r"https?://([a-zA-Z0-9.-]+)\.s3\.amazonaws\.com"),
    re.compile(r"https?://([a-zA-Z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com"),
    re.compile(r"https?://s3\.amazonaws\.com/([a-zA-Z0-9.-]+)"),
    re.compile(r"https?://s3-([a-z0-9-]+)\.amazonaws\.com/([a-zA-Z0-9.-]+)"),
    re.compile(r"s3://([a-zA-Z0-9.-]+)"),
]

# Azure Blob storage URL patterns
AZURE_PATTERNS = [
    re.compile(r"https?://([a-zA-Z0-9-]+)\.blob\.core\.windows\.net"),
]

# Google Cloud Storage URL patterns
GCS_PATTERNS = [
    re.compile(r"https?://([a-zA-Z0-9._-]+)\.storage\.googleapis\.com"),
    re.compile(r"https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)"),
    re.compile(r"https?://storage\.cloud\.google\.com/([a-zA-Z0-9._-]+)"),
    re.compile(r"gs://([a-zA-Z0-9._-]+)"),
]

# All patterns grouped by provider
CLOUD_STORAGE_PATTERNS = {
    "s3": S3_PATTERNS,
    "azure": AZURE_PATTERNS,
    "gcs": GCS_PATTERNS,
}

# Common bucket name suffixes for active probing
BUCKET_NAME_SUFFIXES = [
    "backup",
    "dev",
    "prod",
    "staging",
    "assets",
    "media",
    "uploads",
    "data",
    "public",
    "private",
    "logs",
    "config",
]

# Keywords in bucket names that indicate sensitive content
SENSITIVE_KEYWORDS = [
    "backup",
    "db",
    "database",
    "config",
    "credentials",
    "secret",
    "key",
    "private",
]
