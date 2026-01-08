import pytest
from unittest.mock import patch, MagicMock, mock_open
import os
import tempfile
import socket
from asm.modules.ports import PortScanner, QuickScanner

# Sample Nmap XML Output
SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -v -A -oX output.xml scanme.nmap.org" start="1614000000" startstr="Mon Feb 22 10:00:00 2021" version="7.91" xmloutputversion="1.05">
<host starttime="1614000000" endtime="1614000010">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="45.33.32.156" addrtype="ipv4"/>
<hostnames>
<hostname name="scanme.nmap.org" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="Apache httpd" version="2.4.7" extrainfo="(Ubuntu)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.7</cpe></service></port>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="6.6.1p1" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:6.6.1p1</cpe></service></port>
<port protocol="tcp" portid="9929"><state state="filtered" reason="no-response" reason_ttl="0"/><service name="nping-echo" method="table" conf="3"/></port>
</ports>
<times srtt="122000" rttvar="7000" to="150000"/>
</host>
</nmaprun>
"""

# Sample Nmap XML with multiple hosts for batch scanning tests
SAMPLE_NMAP_XML_MULTI = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1614000000" version="7.91" xmloutputversion="1.05">
<host starttime="1614000000" endtime="1614000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames>
<hostname name="host1.example.com" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
<host starttime="1614000000" endtime="1614000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.2" addrtype="ipv4"/>
<hostnames>
<hostname name="host2.example.com" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports>
</host>
<host starttime="1614000000" endtime="1614000010">
<status state="up" reason="syn-ack"/>
<address addr="192.168.1.3" addrtype="ipv4"/>
<ports>
</ports>
</host>
</nmaprun>
"""

class TestPortScanner:
    
    @pytest.fixture
    def scanner(self, mock_config):
        # Patch check_nmap to avoid actual subprocess calls during init
        with patch("asm.modules.ports.PortScanner._check_nmap", return_value=True):
            return PortScanner(mock_config)

    def test_init(self, mock_config):
        with patch("asm.modules.ports.PortScanner._check_nmap", return_value=True):
            scanner = PortScanner(mock_config)
            assert scanner.nmap_available is True
            
        with patch("asm.modules.ports.PortScanner._check_nmap", return_value=False):
            scanner = PortScanner(mock_config)
            assert scanner.nmap_available is False

    @patch("subprocess.run")
    def test_check_nmap_success(self, mock_run, scanner):
        mock_run.return_value.returncode = 0
        assert scanner._check_nmap() is True
        
    @patch("subprocess.run")
    def test_check_nmap_failure(self, mock_run, scanner):
        mock_run.side_effect = FileNotFoundError 
        assert scanner._check_nmap() is False

    @patch("asm.modules.ports.PortScanner._nmap_scan")
    def test_scan_uses_nmap_if_available(self, mock_nmap_scan, scanner):
        scanner.nmap_available = True
        scanner.scan("example.com", [80, 443])
        mock_nmap_scan.assert_called_once()

    @patch("asm.modules.ports.PortScanner._socket_scan")
    def test_scan_falls_back_to_socket(self, mock_socket_scan, scanner):
        scanner.nmap_available = False
        scanner.scan("example.com", [80, 443])
        mock_socket_scan.assert_called_once()

    def test_parse_nmap_xml(self, scanner):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(SAMPLE_NMAP_XML)
            fname = f.name

        try:
            results = scanner._parse_nmap_xml(fname)
            assert len(results) == 2 
            
            p80 = next(p for p in results if p["port"] == 80)
            assert p80["state"] == "open"
            assert p80["service"] == "http"
            assert p80["product"] == "Apache httpd"
            assert p80["version"] == "2.4.7"

            p22 = next(p for p in results if p["port"] == 22)
            assert p22["service"] == "ssh"
            
            # Port 9929 is filtered, so shouldn't be in results (code filters for state="open")
            assert not any(p["port"] == 9929 for p in results)

        finally:
            os.unlink(fname)

    @patch("subprocess.run")
    def test_nmap_scan_execution(self, mock_run, scanner):
        # Mock nmap execution and XML parsing
        with patch.object(scanner, "_parse_nmap_xml", return_value=[{"port": 80}]) as mock_parse:
            # We need to ensure the temp file exists, code checks os.path.exists
            # The code creates temp file, passes name to nmap, then reads it.
            # We can mock tempfile.NamedTemporaryFile to return a known path, 
            # and verify check exists is patched or handled.
            
            # Since subprocess is mocked, it won't write the file.
            # We need to mock os.path.exists to return True for the xml file
            
            with patch("os.path.exists", return_value=True):
                 # Also need to patch os.unlink so we don't try to delete phantom file
                 with patch("os.unlink"):
                     result = scanner._nmap_scan("example.com", [80])
            
            assert result["scan_type"] == "nmap"
            assert result["open_ports"] == [{"port": 80}]
            mock_run.assert_called_once()

    def test_guess_service(self, scanner):
        assert scanner._guess_service(80) == "http"
        assert scanner._guess_service(443) == "https"
        assert scanner._guess_service(12345) == "unknown"

    @patch("socket.socket")
    def test_socket_scan(self, mock_socket_cls, scanner):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Scenario: Port 80 open (0), Port 443 closed (1)
        mock_sock.connect_ex.side_effect = [0, 1]

        result = scanner._socket_scan("example.com", [80, 443])

        assert result["scan_type"] == "socket"
        assert len(result["open_ports"]) == 1
        assert result["open_ports"][0]["port"] == 80
        assert result["open_ports"][0]["service"] == "http"

    def test_scan_batch_empty_targets(self, scanner):
        """Test scan_batch with empty target list"""
        results = scanner.scan_batch([], [80, 443])
        assert results == []

    def test_scan_batch_single_target(self, scanner):
        """Test scan_batch with single target skips thread overhead"""
        with patch.object(scanner, "scan") as mock_scan:
            mock_scan.return_value = {"target": "example.com", "open_ports": []}
            results = scanner.scan_batch(["example.com"], [80, 443])

            assert len(results) == 1
            mock_scan.assert_called_once_with("example.com", [80, 443])

    def test_scan_batch_multiple_targets(self, scanner):
        """Test scan_batch runs multiple targets in parallel"""
        def mock_scan(target, ports):
            return {"target": target, "open_ports": [{"port": 80}]}

        with patch.object(scanner, "scan", side_effect=mock_scan):
            targets = ["host1.example.com", "host2.example.com", "host3.example.com"]
            results = scanner.scan_batch(targets, [80, 443], workers=3)

            assert len(results) == 3
            result_targets = {r["target"] for r in results}
            assert result_targets == set(targets)

    def test_scan_batch_handles_exceptions(self, scanner):
        """Test scan_batch handles scan exceptions gracefully"""
        def mock_scan(target, ports):
            if target == "bad.example.com":
                raise Exception("Connection refused")
            return {"target": target, "open_ports": []}

        # Disable nmap to use fallback path
        scanner.nmap_available = False
        with patch.object(scanner, "scan", side_effect=mock_scan):
            targets = ["good.example.com", "bad.example.com"]
            results = scanner.scan_batch(targets, [80], workers=2)

            assert len(results) == 2

            good_result = next(r for r in results if r["target"] == "good.example.com")
            assert "error" not in good_result

            bad_result = next(r for r in results if r["target"] == "bad.example.com")
            assert "error" in bad_result
            assert "Connection refused" in bad_result["error"]

    def test_parse_nmap_xml_multi(self, scanner):
        """Test parsing nmap XML with multiple hosts"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(SAMPLE_NMAP_XML_MULTI)
            fname = f.name

        try:
            results = scanner._parse_nmap_xml_multi(fname)

            # Should have 3 hosts (one with hostname, one with hostname, one with IP only)
            assert "host1.example.com" in results
            assert "host2.example.com" in results
            assert "192.168.1.3" in results  # Falls back to IP

            # Check host1 ports
            host1_ports = results["host1.example.com"]
            assert len(host1_ports) == 2
            assert any(p["port"] == 80 for p in host1_ports)
            assert any(p["port"] == 443 for p in host1_ports)

            # Check host2 ports
            host2_ports = results["host2.example.com"]
            assert len(host2_ports) == 1
            assert host2_ports[0]["port"] == 22

            # Check host3 (no open ports)
            host3_ports = results["192.168.1.3"]
            assert len(host3_ports) == 0

        finally:
            os.unlink(fname)

    @patch("subprocess.run")
    def test_nmap_batch_scan_execution(self, mock_run, scanner):
        """Test _nmap_batch_scan runs single nmap with all targets"""
        with patch.object(scanner, "_parse_nmap_xml_multi") as mock_parse:
            mock_parse.return_value = {
                "host1.example.com": [{"port": 80}],
                "host2.example.com": [{"port": 22}],
            }

            with patch("os.path.exists", return_value=True):
                with patch("os.unlink"):
                    targets = ["host1.example.com", "host2.example.com"]
                    results = scanner._nmap_batch_scan(targets, [80, 443])

            # Verify single nmap call with all targets
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "host1.example.com" in cmd
            assert "host2.example.com" in cmd
            assert "--min-hostgroup" in cmd
            assert "32" in cmd
            assert "--min-parallelism" in cmd

            # Verify results
            assert len(results) == 2
            assert results[0]["target"] == "host1.example.com"
            assert results[0]["open_ports"] == [{"port": 80}]
            assert results[1]["target"] == "host2.example.com"
            assert results[1]["open_ports"] == [{"port": 22}]

    @patch("subprocess.run")
    def test_nmap_batch_scan_preserves_order(self, mock_run, scanner):
        """Test _nmap_batch_scan returns results in input order"""
        with patch.object(scanner, "_parse_nmap_xml_multi") as mock_parse:
            # Return in different order than input
            mock_parse.return_value = {
                "z.example.com": [],
                "a.example.com": [],
                "m.example.com": [],
            }

            with patch("os.path.exists", return_value=True):
                with patch("os.unlink"):
                    targets = ["a.example.com", "m.example.com", "z.example.com"]
                    results = scanner._nmap_batch_scan(targets, [80])

            # Results should be in same order as input
            assert [r["target"] for r in results] == targets

    @patch("subprocess.run")
    def test_nmap_batch_scan_timeout(self, mock_run, scanner):
        """Test _nmap_batch_scan handles timeout"""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nmap", timeout=300)

        with patch("os.path.exists", return_value=False):
            targets = ["host1.example.com", "host2.example.com"]
            results = scanner._nmap_batch_scan(targets, [80])

        # All targets should have error
        assert len(results) == 2
        assert all("error" in r for r in results)
        assert all("timed out" in r["error"] for r in results)

    def test_scan_batch_uses_nmap_batch(self, scanner):
        """Test scan_batch uses _nmap_batch_scan when nmap available"""
        scanner.nmap_available = True

        with patch.object(scanner, "_nmap_batch_scan") as mock_batch:
            mock_batch.return_value = [
                {"target": "host1.example.com", "open_ports": []},
                {"target": "host2.example.com", "open_ports": []},
            ]

            targets = ["host1.example.com", "host2.example.com"]
            results = scanner.scan_batch(targets, [80, 443])

            mock_batch.assert_called_once()
            assert len(results) == 2

    def test_scan_batch_fallback_without_nmap(self, scanner):
        """Test scan_batch falls back to parallel scans when nmap unavailable"""
        scanner.nmap_available = False

        with patch.object(scanner, "scan") as mock_scan:
            mock_scan.return_value = {"target": "test", "open_ports": []}

            targets = ["host1.example.com", "host2.example.com"]
            scanner.scan_batch(targets, [80, 443], workers=2)

            # Should call individual scan for each target
            assert mock_scan.call_count == 2


class TestQuickScanner:
    
    @patch("socket.socket")
    def test_is_alive_true(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        
        # 80 closed, 443 open
        mock_sock.connect_ex.side_effect = [1, 0, 1] 
        
        assert QuickScanner.is_alive("example.com") is True
        
    @patch("socket.socket")
    def test_is_alive_false(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1 # All closed
        
        assert QuickScanner.is_alive("example.com") is False
