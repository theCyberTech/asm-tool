"""
Unit tests for CloudStorageDetector module
"""

from unittest.mock import Mock, patch, MagicMock
import pytest
import httpx

from asm.modules.cloud_storage import CloudStorageDetector


class TestCloudStorageDetectorInitialization:
    """Test cases for CloudStorageDetector initialization"""

    def test_detector_initialization(self, mock_config):
        """Test detector initialization with config"""
        detector = CloudStorageDetector(mock_config)
        assert detector.config == mock_config


class TestExtractFromUrls:
    """Test cases for passive URL extraction"""

    def test_extract_s3_subdomain_style(self, mock_config):
        """Test S3 bucket extraction from subdomain-style URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://mybucket.s3.amazonaws.com/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "s3"
        assert result[0]["source"] == "url_extraction"

    def test_extract_s3_regional_style(self, mock_config):
        """Test S3 bucket extraction from regional URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://mybucket.s3-us-west-2.amazonaws.com/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "s3"

    def test_extract_s3_path_style(self, mock_config):
        """Test S3 bucket extraction from path-style URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://s3.amazonaws.com/mybucket/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "s3"

    def test_extract_s3_protocol_style(self, mock_config):
        """Test S3 bucket extraction from s3:// protocol URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["s3://mybucket/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "s3"

    def test_extract_azure_blob(self, mock_config):
        """Test Azure Blob extraction"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://myaccount.blob.core.windows.net/container/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "myaccount"
        assert result[0]["provider"] == "azure"
        assert result[0]["source"] == "url_extraction"

    def test_extract_gcs_subdomain_style(self, mock_config):
        """Test GCS bucket extraction from subdomain-style URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://mybucket.storage.googleapis.com/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "gcs"

    def test_extract_gcs_path_style(self, mock_config):
        """Test GCS bucket extraction from path-style URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://storage.googleapis.com/mybucket/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "gcs"

    def test_extract_gcs_cloud_storage_style(self, mock_config):
        """Test GCS bucket extraction from cloud.google.com style URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["https://storage.cloud.google.com/mybucket/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "gcs"

    def test_extract_gcs_protocol_style(self, mock_config):
        """Test GCS bucket extraction from gs:// protocol URL"""
        detector = CloudStorageDetector(mock_config)
        urls = ["gs://mybucket/file.txt"]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"
        assert result[0]["provider"] == "gcs"

    def test_extract_multiple_providers(self, mock_config):
        """Test extraction of multiple cloud providers from URL list"""
        detector = CloudStorageDetector(mock_config)
        urls = [
            "https://s3bucket.s3.amazonaws.com/file.txt",
            "https://azureacct.blob.core.windows.net/file.txt",
            "https://storage.googleapis.com/gcsbucket/file.txt",
        ]

        result = detector.extract_from_urls(urls)

        assert len(result) == 3
        providers = {r["provider"] for r in result}
        assert providers == {"s3", "azure", "gcs"}

    def test_extract_deduplicates_same_bucket(self, mock_config):
        """Test that duplicate bucket URLs are deduplicated"""
        detector = CloudStorageDetector(mock_config)
        urls = [
            "https://mybucket.s3.amazonaws.com/file1.txt",
            "https://mybucket.s3.amazonaws.com/file2.txt",
            "https://mybucket.s3.amazonaws.com/dir/file3.txt",
        ]

        result = detector.extract_from_urls(urls)

        assert len(result) == 1
        assert result[0]["bucket_name"] == "mybucket"

    def test_extract_empty_url_list(self, mock_config):
        """Test extraction with empty URL list"""
        detector = CloudStorageDetector(mock_config)
        result = detector.extract_from_urls([])
        assert result == []

    def test_extract_no_cloud_urls(self, mock_config):
        """Test extraction with URLs that don't match cloud storage patterns"""
        detector = CloudStorageDetector(mock_config)
        urls = [
            "https://example.com/page.html",
            "https://api.service.io/v1/data",
            "http://localhost:8080/test",
        ]

        result = detector.extract_from_urls(urls)
        assert result == []


class TestNormalizeBucketUrl:
    """Test cases for bucket URL normalization"""

    def test_normalize_s3_url(self, mock_config):
        """Test S3 URL normalization"""
        detector = CloudStorageDetector(mock_config)
        result = detector._normalize_bucket_url(
            "https://s3.amazonaws.com/mybucket/file.txt", "s3", "mybucket"
        )
        assert result == "https://mybucket.s3.amazonaws.com"

    def test_normalize_azure_url(self, mock_config):
        """Test Azure URL normalization"""
        detector = CloudStorageDetector(mock_config)
        result = detector._normalize_bucket_url(
            "https://myaccount.blob.core.windows.net/container/file",
            "azure",
            "myaccount",
        )
        assert result == "https://myaccount.blob.core.windows.net"

    def test_normalize_gcs_url(self, mock_config):
        """Test GCS URL normalization"""
        detector = CloudStorageDetector(mock_config)
        result = detector._normalize_bucket_url(
            "https://mybucket.storage.googleapis.com/file.txt", "gcs", "mybucket"
        )
        assert result == "https://storage.googleapis.com/mybucket"

    def test_normalize_unknown_provider(self, mock_config):
        """Test normalization with unknown provider returns original URL"""
        detector = CloudStorageDetector(mock_config)
        original = "https://unknown.storage.example.com/file.txt"
        result = detector._normalize_bucket_url(original, "unknown", "bucket")
        assert result == original


class TestExtractBaseName:
    """Test cases for domain base name extraction"""

    def test_extract_simple_domain(self, mock_config):
        """Test base name extraction from simple domain"""
        detector = CloudStorageDetector(mock_config)
        result = detector._extract_base_name("example.com")
        assert result == "example"

    def test_extract_subdomain(self, mock_config):
        """Test base name extraction from subdomain"""
        detector = CloudStorageDetector(mock_config)
        result = detector._extract_base_name("www.example.com")
        assert result == "example"

    def test_extract_deep_subdomain(self, mock_config):
        """Test base name extraction from deep subdomain"""
        detector = CloudStorageDetector(mock_config)
        result = detector._extract_base_name("api.staging.example.com")
        assert result == "example"

    def test_extract_cctld_uk(self, mock_config):
        """Test base name extraction from .co.uk domain"""
        detector = CloudStorageDetector(mock_config)
        result = detector._extract_base_name("example.co.uk")
        assert result == "example"

    def test_extract_cctld_australia(self, mock_config):
        """Test base name extraction from .com.au domain"""
        detector = CloudStorageDetector(mock_config)
        result = detector._extract_base_name("example.com.au")
        assert result == "example"

    def test_extract_single_part(self, mock_config):
        """Test base name extraction from single-part domain"""
        detector = CloudStorageDetector(mock_config)
        result = detector._extract_base_name("localhost")
        assert result == "localhost"


class TestGenerateBucketUrls:
    """Test cases for bucket URL permutation generation"""

    def test_generate_base_name_only(self, mock_config):
        """Test that base name alone is included in permutations"""
        detector = CloudStorageDetector(mock_config)
        result = detector._generate_bucket_urls("example")

        urls = [url for url, _, _ in result]
        assert "https://example.s3.amazonaws.com" in urls
        assert "https://example.blob.core.windows.net" in urls
        assert "https://storage.googleapis.com/example" in urls

    def test_generate_suffix_variants(self, mock_config):
        """Test that suffix variants are generated with hyphens and underscores"""
        detector = CloudStorageDetector(mock_config)
        result = detector._generate_bucket_urls("example")

        urls = [url for url, _, _ in result]
        # Check hyphen variants
        assert "https://example-backup.s3.amazonaws.com" in urls
        assert "https://example-dev.s3.amazonaws.com" in urls
        # Check underscore variants
        assert "https://example_backup.s3.amazonaws.com" in urls
        assert "https://example_dev.s3.amazonaws.com" in urls

    def test_generate_all_providers(self, mock_config):
        """Test that all three providers are included for each bucket name"""
        detector = CloudStorageDetector(mock_config)
        result = detector._generate_bucket_urls("test")

        providers = {provider for _, provider, _ in result}
        assert providers == {"s3", "azure", "gcs"}

    def test_generate_returns_tuples(self, mock_config):
        """Test that result is list of (url, provider, bucket_name) tuples"""
        detector = CloudStorageDetector(mock_config)
        result = detector._generate_bucket_urls("example")

        assert len(result) > 0
        for item in result:
            assert isinstance(item, tuple)
            assert len(item) == 3
            url, provider, bucket_name = item
            assert isinstance(url, str)
            assert provider in ("s3", "azure", "gcs")
            assert isinstance(bucket_name, str)


class TestProbeUrl:
    """Test cases for single URL probing"""

    @patch("asm.modules.cloud_storage.httpx.head")
    def test_probe_url_exists(self, mock_head, mock_config):
        """Test probe returns True when bucket exists (non-404)"""
        mock_response = MagicMock()
        mock_response.status_code = 403  # Access denied but exists
        mock_head.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector._probe_url("https://mybucket.s3.amazonaws.com")

        assert result is True
        mock_head.assert_called_once_with(
            "https://mybucket.s3.amazonaws.com", timeout=5.0, follow_redirects=True
        )

    @patch("asm.modules.cloud_storage.httpx.head")
    def test_probe_url_not_found(self, mock_head, mock_config):
        """Test probe returns False when bucket returns 404"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_head.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector._probe_url("https://nonexistent.s3.amazonaws.com")

        assert result is False

    @patch("asm.modules.cloud_storage.httpx.head")
    def test_probe_url_request_error(self, mock_head, mock_config):
        """Test probe returns False on request error"""
        mock_head.side_effect = httpx.RequestError("DNS resolution failed")

        detector = CloudStorageDetector(mock_config)
        result = detector._probe_url("https://invalid.s3.amazonaws.com")

        assert result is False

    @patch("asm.modules.cloud_storage.httpx.head")
    def test_probe_url_timeout(self, mock_head, mock_config):
        """Test probe returns False on timeout"""
        mock_head.side_effect = httpx.TimeoutException("Connection timed out")

        detector = CloudStorageDetector(mock_config)
        result = detector._probe_url("https://slow.s3.amazonaws.com")

        assert result is False


class TestProbeBuckets:
    """Test cases for active bucket probing"""

    @patch.object(CloudStorageDetector, "_probe_url")
    @patch.object(CloudStorageDetector, "_generate_bucket_urls")
    def test_probe_buckets_finds_existing(
        self, mock_generate, mock_probe, mock_config
    ):
        """Test probe_buckets returns found buckets"""
        mock_generate.return_value = [
            ("https://example.s3.amazonaws.com", "s3", "example"),
            ("https://example-backup.s3.amazonaws.com", "s3", "example-backup"),
        ]
        mock_probe.side_effect = [True, False]

        detector = CloudStorageDetector(mock_config)
        result = detector.probe_buckets("example.com", workers=1)

        assert len(result) == 1
        assert result[0]["url"] == "https://example.s3.amazonaws.com"
        assert result[0]["source"] == "active_probe"

    @patch.object(CloudStorageDetector, "_probe_url")
    @patch.object(CloudStorageDetector, "_generate_bucket_urls")
    def test_probe_buckets_none_found(self, mock_generate, mock_probe, mock_config):
        """Test probe_buckets returns empty list when no buckets exist"""
        mock_generate.return_value = [
            ("https://example.s3.amazonaws.com", "s3", "example"),
        ]
        mock_probe.return_value = False

        detector = CloudStorageDetector(mock_config)
        result = detector.probe_buckets("example.com", workers=1)

        assert result == []

    @patch.object(CloudStorageDetector, "_probe_url")
    @patch.object(CloudStorageDetector, "_generate_bucket_urls")
    def test_probe_buckets_deduplicates(
        self, mock_generate, mock_probe, mock_config
    ):
        """Test probe_buckets deduplicates found buckets"""
        mock_generate.return_value = [
            ("https://example.s3.amazonaws.com", "s3", "example"),
            ("https://example.s3.amazonaws.com", "s3", "example"),  # duplicate
        ]
        mock_probe.return_value = True

        detector = CloudStorageDetector(mock_config)
        result = detector.probe_buckets("example.com", workers=1)

        # Should only have one result due to deduplication
        assert len(result) == 1

    @patch.object(CloudStorageDetector, "_generate_bucket_urls")
    def test_probe_buckets_handles_future_exception(
        self, mock_generate, mock_config
    ):
        """Test probe_buckets handles exceptions from futures gracefully"""
        mock_generate.return_value = [
            ("https://example.s3.amazonaws.com", "s3", "example"),
        ]

        detector = CloudStorageDetector(mock_config)

        # Patch _probe_url to raise an exception
        with patch.object(detector, "_probe_url", side_effect=Exception("Unexpected error")):
            result = detector.probe_buckets("example.com", workers=1)

        # Should return empty list, not crash
        assert result == []


class TestCheckAccess:
    """Test cases for access level checking"""

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_s3_listing_enabled(self, mock_get, mock_config):
        """Test S3 access check when listing is enabled"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<ListBucketResult>...</ListBucketResult>"
        mock_get.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access("https://mybucket.s3.amazonaws.com", "s3")

        assert result["access_level"] == "listing_enabled"
        assert "Status 200" in result["evidence"]

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_s3_not_found(self, mock_get, mock_config):
        """Test S3 access check when bucket not found"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access("https://mybucket.s3.amazonaws.com", "s3")

        assert result["access_level"] == "not_found"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_s3_public_read(self, mock_get, mock_config):
        """Test S3 access check when public read is enabled"""
        # First call (listing) returns 403, second call (read) returns 200
        mock_list_response = MagicMock()
        mock_list_response.status_code = 403

        mock_read_response = MagicMock()
        mock_read_response.status_code = 200
        mock_read_response.text = "Some content"

        mock_get.side_effect = [mock_list_response, mock_read_response]

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access("https://mybucket.s3.amazonaws.com", "s3")

        assert result["access_level"] == "public_read"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_s3_authenticated_only(self, mock_get, mock_config):
        """Test S3 access check when authentication is required"""
        mock_list_response = MagicMock()
        mock_list_response.status_code = 403

        mock_read_response = MagicMock()
        mock_read_response.status_code = 403

        mock_get.side_effect = [mock_list_response, mock_read_response]

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access("https://mybucket.s3.amazonaws.com", "s3")

        assert result["access_level"] == "authenticated_only"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_s3_request_error(self, mock_get, mock_config):
        """Test S3 access check handles request errors"""
        mock_get.side_effect = httpx.RequestError("Network error")

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access("https://mybucket.s3.amazonaws.com", "s3")

        assert result["access_level"] == "not_found"
        assert "Request error" in result["evidence"]

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_azure_listing_enabled(self, mock_get, mock_config):
        """Test Azure access check when listing is enabled"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<EnumerationResults>...</EnumerationResults>"
        mock_get.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://myaccount.blob.core.windows.net", "azure"
        )

        assert result["access_level"] == "listing_enabled"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_azure_not_found(self, mock_get, mock_config):
        """Test Azure access check when container not found"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://myaccount.blob.core.windows.net", "azure"
        )

        assert result["access_level"] == "not_found"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_azure_public_read(self, mock_get, mock_config):
        """Test Azure access check when public read is enabled"""
        mock_list_response = MagicMock()
        mock_list_response.status_code = 403

        mock_read_response = MagicMock()
        mock_read_response.status_code = 200
        mock_read_response.text = "Some content"

        mock_get.side_effect = [mock_list_response, mock_read_response]

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://myaccount.blob.core.windows.net", "azure"
        )

        assert result["access_level"] == "public_read"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_azure_authenticated_only(self, mock_get, mock_config):
        """Test Azure access check when authentication is required"""
        mock_list_response = MagicMock()
        mock_list_response.status_code = 403

        mock_read_response = MagicMock()
        mock_read_response.status_code = 403

        mock_get.side_effect = [mock_list_response, mock_read_response]

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://myaccount.blob.core.windows.net", "azure"
        )

        assert result["access_level"] == "authenticated_only"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_azure_request_error(self, mock_get, mock_config):
        """Test Azure access check handles request errors"""
        mock_get.side_effect = httpx.RequestError("Network error")

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://myaccount.blob.core.windows.net", "azure"
        )

        assert result["access_level"] == "not_found"
        assert "Request error" in result["evidence"]

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_gcs_listing_enabled(self, mock_get, mock_config):
        """Test GCS access check when listing is enabled"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"items": []}'
        mock_get.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://storage.googleapis.com/mybucket", "gcs"
        )

        assert result["access_level"] == "listing_enabled"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_gcs_not_found(self, mock_get, mock_config):
        """Test GCS access check when bucket not found"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://storage.googleapis.com/mybucket", "gcs"
        )

        assert result["access_level"] == "not_found"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_gcs_public_read(self, mock_get, mock_config):
        """Test GCS access check when public read is enabled"""
        mock_list_response = MagicMock()
        mock_list_response.status_code = 403

        mock_read_response = MagicMock()
        mock_read_response.status_code = 200
        mock_read_response.text = "Some content"

        mock_get.side_effect = [mock_list_response, mock_read_response]

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://storage.googleapis.com/mybucket", "gcs"
        )

        assert result["access_level"] == "public_read"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_gcs_authenticated_only(self, mock_get, mock_config):
        """Test GCS access check when authentication is required"""
        mock_list_response = MagicMock()
        mock_list_response.status_code = 403

        mock_read_response = MagicMock()
        mock_read_response.status_code = 403

        mock_get.side_effect = [mock_list_response, mock_read_response]

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://storage.googleapis.com/mybucket", "gcs"
        )

        assert result["access_level"] == "authenticated_only"

    @patch("asm.modules.cloud_storage.httpx.get")
    def test_check_access_gcs_request_error(self, mock_get, mock_config):
        """Test GCS access check handles request errors"""
        mock_get.side_effect = httpx.RequestError("Network error")

        detector = CloudStorageDetector(mock_config)
        result = detector.check_access(
            "https://storage.googleapis.com/mybucket", "gcs"
        )

        assert result["access_level"] == "not_found"
        assert "Request error" in result["evidence"]

    def test_check_access_unknown_provider(self, mock_config):
        """Test access check with unknown provider"""
        detector = CloudStorageDetector(mock_config)
        result = detector.check_access("https://unknown.storage.io/bucket", "unknown")

        assert result["access_level"] == "not_found"
        assert "Unknown provider" in result["evidence"]


class TestClassifySeverity:
    """Test cases for severity classification"""

    def test_severity_critical_listing_with_sensitive_keyword(self, mock_config):
        """Test critical severity for listing with sensitive keyword"""
        detector = CloudStorageDetector(mock_config)

        # Test various sensitive keywords
        assert detector.classify_severity("listing_enabled", "company-backup") == "critical"
        assert detector.classify_severity("listing_enabled", "db-dump") == "critical"
        assert detector.classify_severity("listing_enabled", "production-database") == "critical"
        assert detector.classify_severity("listing_enabled", "app-config") == "critical"
        assert detector.classify_severity("listing_enabled", "credentials-store") == "critical"
        assert detector.classify_severity("listing_enabled", "secret-files") == "critical"
        assert detector.classify_severity("listing_enabled", "api-key-storage") == "critical"
        assert detector.classify_severity("listing_enabled", "private-data") == "critical"

    def test_severity_high_listing_without_sensitive_keyword(self, mock_config):
        """Test high severity for listing without sensitive keyword"""
        detector = CloudStorageDetector(mock_config)

        assert detector.classify_severity("listing_enabled", "public-assets") == "high"
        assert detector.classify_severity("listing_enabled", "company-images") == "high"
        assert detector.classify_severity("listing_enabled", "media-files") == "high"

    def test_severity_medium_public_read(self, mock_config):
        """Test medium severity for public read access"""
        detector = CloudStorageDetector(mock_config)

        assert detector.classify_severity("public_read", "company-backup") == "medium"
        assert detector.classify_severity("public_read", "public-assets") == "medium"

    def test_severity_low_authenticated_only(self, mock_config):
        """Test low severity for authenticated only access"""
        detector = CloudStorageDetector(mock_config)

        assert detector.classify_severity("authenticated_only", "company-backup") == "low"
        assert detector.classify_severity("authenticated_only", "public-assets") == "low"

    def test_severity_low_not_found(self, mock_config):
        """Test low severity for not found buckets"""
        detector = CloudStorageDetector(mock_config)

        assert detector.classify_severity("not_found", "company-backup") == "low"

    def test_severity_case_insensitive_keyword_matching(self, mock_config):
        """Test severity classification is case-insensitive"""
        detector = CloudStorageDetector(mock_config)

        assert detector.classify_severity("listing_enabled", "COMPANY-BACKUP") == "critical"
        assert detector.classify_severity("listing_enabled", "Company-Database") == "critical"


class TestScan:
    """Test cases for the main scan method"""

    @patch.object(CloudStorageDetector, "extract_from_urls")
    @patch.object(CloudStorageDetector, "probe_buckets")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_passive_only(
        self, mock_check, mock_probe, mock_extract, mock_config
    ):
        """Test scan with passive_only flag"""
        mock_extract.return_value = [
            {
                "url": "https://mybucket.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "mybucket",
                "source": "url_extraction",
            }
        ]
        mock_check.return_value = {
            "access_level": "listing_enabled",
            "evidence": "Status 200",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(
            targets=["example.com"],
            urls=["https://mybucket.s3.amazonaws.com/file.txt"],
            passive_only=True,
        )

        assert len(result) == 1
        assert result[0]["url"] == "https://mybucket.s3.amazonaws.com"
        assert result[0]["severity"] == "high"
        assert result[0]["status"] == "open"
        mock_probe.assert_not_called()

    @patch.object(CloudStorageDetector, "extract_from_urls")
    @patch.object(CloudStorageDetector, "probe_buckets")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_passive_and_active(
        self, mock_check, mock_probe, mock_extract, mock_config
    ):
        """Test scan with both passive and active probing"""
        mock_extract.return_value = [
            {
                "url": "https://bucket1.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "bucket1",
                "source": "url_extraction",
            }
        ]
        mock_probe.return_value = [
            {
                "url": "https://bucket2.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "bucket2",
                "source": "active_probe",
            }
        ]
        mock_check.return_value = {
            "access_level": "authenticated_only",
            "evidence": "Status 403",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(
            targets=["example.com"],
            urls=["https://bucket1.s3.amazonaws.com/file.txt"],
            passive_only=False,
        )

        assert len(result) == 2
        mock_extract.assert_called_once()
        mock_probe.assert_called_once()

    @patch.object(CloudStorageDetector, "extract_from_urls")
    @patch.object(CloudStorageDetector, "probe_buckets")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_deduplicates_results(
        self, mock_check, mock_probe, mock_extract, mock_config
    ):
        """Test scan deduplicates buckets found by both methods"""
        # Same bucket found by both passive and active
        mock_extract.return_value = [
            {
                "url": "https://mybucket.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "mybucket",
                "source": "url_extraction",
            }
        ]
        mock_probe.return_value = [
            {
                "url": "https://mybucket.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "mybucket",
                "source": "active_probe",
            }
        ]
        mock_check.return_value = {
            "access_level": "listing_enabled",
            "evidence": "Status 200",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(
            targets=["example.com"],
            urls=["https://mybucket.s3.amazonaws.com/file.txt"],
        )

        # Should only have one result due to deduplication
        assert len(result) == 1

    @patch.object(CloudStorageDetector, "probe_buckets")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_without_urls(self, mock_check, mock_probe, mock_config):
        """Test scan without providing URLs (active probing only)"""
        mock_probe.return_value = [
            {
                "url": "https://mybucket.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "mybucket",
                "source": "active_probe",
            }
        ]
        mock_check.return_value = {
            "access_level": "public_read",
            "evidence": "Status 200",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(targets=["example.com"])

        assert len(result) == 1
        assert result[0]["status"] == "open"
        assert result[0]["severity"] == "medium"

    @patch.object(CloudStorageDetector, "probe_buckets")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_multiple_targets(self, mock_check, mock_probe, mock_config):
        """Test scan with multiple target domains"""
        mock_probe.side_effect = [
            [
                {
                    "url": "https://example.s3.amazonaws.com",
                    "provider": "s3",
                    "bucket_name": "example",
                    "source": "active_probe",
                }
            ],
            [
                {
                    "url": "https://test.s3.amazonaws.com",
                    "provider": "s3",
                    "bucket_name": "test",
                    "source": "active_probe",
                }
            ],
        ]
        mock_check.return_value = {
            "access_level": "not_found",
            "evidence": "Status 404",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(targets=["example.com", "test.com"])

        assert len(result) == 2
        assert mock_probe.call_count == 2

    @patch.object(CloudStorageDetector, "extract_from_urls")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_status_open_for_listing(
        self, mock_check, mock_extract, mock_config
    ):
        """Test scan sets status to 'open' for listing_enabled"""
        mock_extract.return_value = [
            {
                "url": "https://mybucket.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "mybucket",
                "source": "url_extraction",
            }
        ]
        mock_check.return_value = {
            "access_level": "listing_enabled",
            "evidence": "Status 200",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(
            targets=["example.com"],
            urls=["https://mybucket.s3.amazonaws.com/file"],
            passive_only=True,
        )

        assert result[0]["status"] == "open"

    @patch.object(CloudStorageDetector, "extract_from_urls")
    @patch.object(CloudStorageDetector, "check_access")
    def test_scan_status_closed_for_authenticated(
        self, mock_check, mock_extract, mock_config
    ):
        """Test scan sets status to 'closed' for authenticated_only"""
        mock_extract.return_value = [
            {
                "url": "https://mybucket.s3.amazonaws.com",
                "provider": "s3",
                "bucket_name": "mybucket",
                "source": "url_extraction",
            }
        ]
        mock_check.return_value = {
            "access_level": "authenticated_only",
            "evidence": "Status 403",
        }

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(
            targets=["example.com"],
            urls=["https://mybucket.s3.amazonaws.com/file"],
            passive_only=True,
        )

        assert result[0]["status"] == "closed"

    @patch.object(CloudStorageDetector, "probe_buckets")
    def test_scan_empty_results(self, mock_probe, mock_config):
        """Test scan returns empty list when nothing is found"""
        mock_probe.return_value = []

        detector = CloudStorageDetector(mock_config)
        result = detector.scan(targets=["example.com"])

        assert result == []
