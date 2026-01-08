import pytest
from unittest.mock import patch, MagicMock, mock_open
import os
import tempfile
import json
from asm.modules.nuclei_scanner import NucleiScanner, CustomScanner

class TestNucleiScanner:

    @pytest.fixture
    def scanner(self, mock_config):
        with patch("asm.modules.nuclei_scanner.NucleiScanner._check_nuclei", return_value=True):
            return NucleiScanner(mock_config)

    def test_init(self, mock_config):
        with patch("asm.modules.nuclei_scanner.NucleiScanner._check_nuclei", return_value=True):
            s = NucleiScanner(mock_config)
            assert s.nuclei_available is True
            
        with patch("asm.modules.nuclei_scanner.NucleiScanner._check_nuclei", return_value=False):
            s = NucleiScanner(mock_config)
            assert s.nuclei_available is False

    @patch("subprocess.run")
    def test_check_nuclei(self, mock_run, scanner):
        mock_run.return_value.returncode = 0
        assert scanner._check_nuclei() is True
        
        mock_run.side_effect = FileNotFoundError
        assert scanner._check_nuclei() is False

    @patch("subprocess.run")
    def test_scan_execution(self, mock_run, scanner):
        # Mock file operations for targets output
        # The scan method creates two temp files: targets and output
        # It writes to output (via subprocess) and reads from it (via python)
        
        # We need to ensure the python read sees data.
        # We can write a real temp file in the test and mock the tempfile creation to return it?
        # Or mock open? 'scan' uses 'open(output_file)'
        
        mock_findings = [
            {"template-id": "test-template", "info": {"name": "Test Vuln", "severity": "high"}, "host": "example.com"}
        ]
        
        # We'll use real tempfiles for IO mocking simplicity within the test process, 
        # but intercept the subprocess call so it doesn't run nuclei
        
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            # Pre-populate output file as if nuclei wrote it
            json.dump(mock_findings[0], tf)
            tf.write("\n")
            output_fname = tf.name
            
        try:
            # We need to patch tempfile.NamedTemporaryFile to control the filenames?
            # Creating 2 temp files. 
            # Easier approach: Patch os.path.exists and open() specifically?
            # But NamedTemporaryFile is context manager.
            
            # Let's just mock subprocess and assume it writes the file, but we PRE-WRITE it 
            # by patching where the file path comes from is hard.
            
            # Valid approach: Mock 'subprocess.run' and also mock the 'open' call that reads results.
            # But the code generates random temp filename.
            
            # We can mock the Parse Finding logic instead? No, we want to test flow.
            
            # Use 'side_effect' on subprocess.run to write into the output file?
            # subprocess.run args contains the output filename!
            
            def side_effect(*args, **kwargs):
                cmd = args[0]
                # cmd = [..., "-o", output_file, ...]
                try:
                    idx = cmd.index("-o")
                    out_file = cmd[idx+1]
                    with open(out_file, "w") as f:
                        json.dump(mock_findings[0], f)
                        f.write("\n")
                except (ValueError, IndexError):
                    pass
                return MagicMock()

            mock_run.side_effect = side_effect
            
            results = scanner.scan(["example.com"])
            
            assert len(results) == 1
            assert results[0]["template_id"] == "test-template"
            
        finally:
            # Cleanup happen in code, but side_effect wrote real file?
            # The code cleans up 'output_file', so we are good.
            pass

    def test_scan_parameters(self, scanner):
        # Verify CLI args construction
        with patch("subprocess.run") as mock_run:
            scanner.scan(
                ["example.com"],
                severity="critical",
                tags="cve",
                templates="cves/",
                exclude_tags="dos"
            )

            args, _ = mock_run.call_args
            cmd = args[0]

            assert "-severity" in cmd
            assert cmd[cmd.index("-severity")+1] == "critical"

            assert "-tags" in cmd
            assert cmd[cmd.index("-tags")+1] == "cve"

            assert "-t" in cmd
            assert cmd[cmd.index("-t")+1] == "cves/"

            assert "-exclude-tags" in cmd
            assert cmd[cmd.index("-exclude-tags")+1] == "dos"

    def test_scan_optimization_flags(self, scanner):
        """Test that nuclei optimization flags are included in command"""
        with patch("subprocess.run") as mock_run:
            scanner.scan(["example.com"])

            args, _ = mock_run.call_args
            cmd = args[0]

            # Verify concurrency flag (-c)
            assert "-c" in cmd
            c_idx = cmd.index("-c")
            assert cmd[c_idx + 1] == "25"  # default from mock_config

            # Verify batch size flag (-bs)
            assert "-bs" in cmd
            bs_idx = cmd.index("-bs")
            assert cmd[bs_idx + 1] == "25"  # default from mock_config

            # Verify retries flag
            assert "-retries" in cmd
            retries_idx = cmd.index("-retries")
            assert cmd[retries_idx + 1] == "1"  # default from mock_config

    def test_scan_default_exclude_tags(self, scanner):
        """Test that default exclude_tags from config is applied"""
        with patch("subprocess.run") as mock_run:
            # Don't pass exclude_tags - should use config default
            scanner.scan(["example.com"])

            args, _ = mock_run.call_args
            cmd = args[0]

            # Should include config default exclude_tags
            assert "-exclude-tags" in cmd
            exclude_idx = cmd.index("-exclude-tags")
            assert cmd[exclude_idx + 1] == "dos,fuzz,brute"

    def test_scan_override_exclude_tags(self, scanner):
        """Test that param exclude_tags overrides config default"""
        with patch("subprocess.run") as mock_run:
            # Pass custom exclude_tags - should override config
            scanner.scan(["example.com"], exclude_tags="sqli,xss")

            args, _ = mock_run.call_args
            cmd = args[0]

            assert "-exclude-tags" in cmd
            exclude_idx = cmd.index("-exclude-tags")
            assert cmd[exclude_idx + 1] == "sqli,xss"

    def test_scan_custom_config_values(self, mock_config):
        """Test that custom config values are used"""
        mock_config.nuclei_concurrency = 50
        mock_config.nuclei_batch_size = 100
        mock_config.nuclei_retries = 3
        mock_config.nuclei_exclude_tags = "custom,tags"

        with patch("asm.modules.nuclei_scanner.NucleiScanner._check_nuclei", return_value=True):
            scanner = NucleiScanner(mock_config)

        with patch("subprocess.run") as mock_run:
            scanner.scan(["example.com"])

            args, _ = mock_run.call_args
            cmd = args[0]

            assert cmd[cmd.index("-c") + 1] == "50"
            assert cmd[cmd.index("-bs") + 1] == "100"
            assert cmd[cmd.index("-retries") + 1] == "3"
            assert cmd[cmd.index("-exclude-tags") + 1] == "custom,tags"

    def test_parse_finding(self, scanner):
        raw = {
            "template-id": "id",
            "info": {
                "name": "name",
                "severity": "high",
                "description": "desc",
                "reference": ["ref"],
                "tags": ["tag"]
            },
            "host": "host",
            "matched-at": "url",
            "timestamp": "time"
        }
        
        parsed = scanner._parse_finding(raw)
        
        assert parsed["template_id"] == "id"
        assert parsed["name"] == "name"
        assert parsed["severity"] == "high"
        assert parsed["host"] == "host"

    @patch("subprocess.run")
    def test_scan_single(self, mock_run, scanner):
        mock_run.return_value.stdout = json.dumps({
            "template-id": "test",
            "info": {"name": "Test"}
        })
        
        result = scanner.scan_single("example.com", "test-template")
        
        assert result is not None
        assert result["template_id"] == "test"
        
        # Test failure
        mock_run.return_value.stdout = ""
        assert scanner.scan_single("example.com", "test") is None


class TestCustomScanner:
    
    @pytest.fixture
    def scanner(self, mock_config):
        return CustomScanner(mock_config)

    @patch("requests.get")
    def test_check_security_headers(self, mock_get, scanner):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            # Missing others
        }
        mock_get.return_value = mock_resp
        
        result = scanner.check_security_headers("https://example.com")
        
        assert "Strict-Transport-Security" in result["headers_present"]
        assert "X-Frame-Options" in result["headers_missing"]
        
    @patch("requests.options")
    def test_check_cors_vulnerable(self, mock_options, scanner):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        }
        mock_options.return_value = mock_resp
        
        result = scanner.check_cors("https://example.com")
        
        assert result["cors_enabled"] is True
        assert result["allows_any_origin"] is True
        assert result["allows_credentials"] is True
        assert len(result["issues"]) > 0

    @patch("requests.options")
    def test_check_cors_safe(self, mock_options, scanner):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_options.return_value = mock_resp
        
        result = scanner.check_cors("https://example.com")
        
        assert result["cors_enabled"] is False
