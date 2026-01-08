"""
Port scanning module using nmap
"""

import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
from typing import Dict, List
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.config import Config
from ..core.validation import validate_domain, validate_port_list


class PortScanner:
    """Port scanning using nmap or fallback methods"""

    def __init__(self, config: Config):
        self.config = config
        self.nmap_available = self._check_nmap()

    def _check_nmap(self) -> bool:
        """Check if nmap is available"""
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def scan(self, target: str, ports: List[int]) -> Dict:
        """Scan target for open ports"""
        validated_target = validate_domain(target)
        validated_ports = validate_port_list(ports)

        if self.nmap_available:
            return self._nmap_scan(validated_target, validated_ports)
        else:
            return self._socket_scan(validated_target, validated_ports)

    def scan_batch(
        self, targets: List[str], ports: List[int], workers: int = 5
    ) -> List[Dict]:
        """Scan multiple targets efficiently.

        When nmap is available, passes all targets to a single nmap invocation
        with --min-hostgroup for 2-3x speedup over individual scans.

        Args:
            targets: List of hostnames/IPs to scan
            ports: List of ports to scan on each target
            workers: Number of concurrent scan threads (fallback mode only)

        Returns:
            List of scan results, one per target
        """
        if not targets:
            return []

        # Validate all targets
        validated_targets = [validate_domain(t) for t in targets]

        # For single target, use regular scan
        if len(validated_targets) == 1:
            return [self.scan(validated_targets[0], ports)]

        # Use batch nmap if available (2-3x faster than individual scans)
        if self.nmap_available:
            return self._nmap_batch_scan(validated_targets, ports)

        # Fallback: parallel individual scans
        results = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.scan, t, ports): t for t in validated_targets}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    target = futures[future]
                    results.append({"target": target, "open_ports": [], "error": str(e)})

        return results

    def _nmap_batch_scan(self, targets: List[str], ports: List[int]) -> List[Dict]:
        """Run single nmap scan against multiple targets.

        Uses --min-hostgroup to scan hosts in parallel within nmap,
        which is 2-3x faster than running separate nmap processes.
        """
        validated_ports = validate_port_list(ports)
        port_str = ",".join(str(p) for p in validated_ports)

        # Initialize results for all targets
        results_map = {t: {"target": t, "open_ports": [], "scan_type": "nmap"} for t in targets}

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            xml_output = f.name

        try:
            # Build nmap command with batch optimization flags
            cmd = [
                "nmap",
                "-sT",
                "-sV",
                "--version-light",
                "-p", port_str,
                "-oX", xml_output,
                "--host-timeout", "60s",
                "-T4",
                "--min-hostgroup", "32",  # Scan hosts in parallel
                "--min-parallelism", "10",  # Minimum parallel probes
            ] + targets

            subprocess.run(cmd, capture_output=True, timeout=self.config.timeout_nmap)

            # Parse XML output for all hosts
            if os.path.exists(xml_output):
                host_results = self._parse_nmap_xml_multi(xml_output)
                for hostname, open_ports in host_results.items():
                    if hostname in results_map:
                        results_map[hostname]["open_ports"] = open_ports

        except subprocess.TimeoutExpired:
            for t in targets:
                results_map[t]["error"] = "Scan timed out"
        except Exception as e:
            for t in targets:
                results_map[t]["error"] = str(e)
        finally:
            if os.path.exists(xml_output):
                os.unlink(xml_output)

        # Return results in same order as input targets
        return [results_map[t] for t in targets]

    def _parse_nmap_xml_multi(self, xml_file: str) -> Dict[str, List[Dict]]:
        """Parse nmap XML output for multiple hosts.

        Returns:
            Dict mapping hostname/IP to list of open ports
        """
        host_ports = {}

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall(".//host"):
                # Get hostname or IP address
                hostname = None

                # Try hostnames first
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name")

                # Fall back to IP address
                if not hostname:
                    addr_elem = host.find("address")
                    if addr_elem is not None:
                        hostname = addr_elem.get("addr")

                if not hostname:
                    continue

                ports = []
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        if port_id is not None:
                            port_info = {
                                "port": int(port_id),
                                "protocol": port.get("protocol", "tcp"),
                                "state": "open",
                            }

                            service = port.find("service")
                            if service is not None:
                                port_info["service"] = service.get("name", "unknown")
                                port_info["version"] = service.get("version", "")
                                port_info["product"] = service.get("product", "")
                                port_info["extra_info"] = service.get("extrainfo", "")

                            ports.append(port_info)

                host_ports[hostname] = ports

        except Exception:
            pass

        return host_ports

    def _nmap_scan(self, target: str, ports: List[int]) -> Dict:
        """Run nmap scan with service detection"""
        result = {"target": target, "open_ports": [], "scan_type": "nmap"}

        port_str = ",".join(str(p) for p in ports)

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            xml_output = f.name

        try:
            cmd = [
                "nmap",
                "-sT",
                "-sV",
                "--version-light",
                "-p",
                port_str,
                "-oX",
                xml_output,
                "--host-timeout",
                "60s",
                "-T4",
                target,
            ]

            subprocess.run(cmd, capture_output=True, timeout=self.config.timeout_nmap)

            # Parse XML output
            if os.path.exists(xml_output):
                result["open_ports"] = self._parse_nmap_xml(xml_output)

        except subprocess.TimeoutExpired:
            result["error"] = "Scan timed out"
        except Exception as e:
            result["error"] = str(e)
        finally:
            if os.path.exists(xml_output):
                os.unlink(xml_output)

        return result

    def _parse_nmap_xml(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output"""
        ports = []

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        if port_id is not None:
                            port_info = {
                                "port": int(port_id),
                                "protocol": port.get("protocol", "tcp"),
                                "state": "open",
                            }

                            service = port.find("service")
                            if service is not None:
                                port_info["service"] = service.get("name", "unknown")
                                port_info["version"] = service.get("version", "")
                                port_info["product"] = service.get("product", "")
                                port_info["extra_info"] = service.get("extrainfo", "")

                            ports.append(port_info)
        except Exception:
            pass

        return ports

    def _socket_scan(self, target: str, ports: List[int]) -> Dict:
        """Fallback socket-based port scan"""
        result = {"target": target, "open_ports": [], "scan_type": "socket"}

        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)

                if sock.connect_ex((target, port)) == 0:
                    result["open_ports"].append(
                        {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": self._guess_service(port),
                            "version": "",
                        }
                    )

                sock.close()
            except Exception:
                pass

        return result

    def _guess_service(self, port: int) -> str:
        """Guess service name from common port numbers"""
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "microsoft-ds",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            1521: "oracle",
            1723: "pptp",
            3306: "mysql",
            3389: "ms-wbt-server",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
        }
        return common_ports.get(port, "unknown")


class QuickScanner:
    """Quick connectivity check without full port scanning"""

    @staticmethod
    def is_alive(target: str, timeout: int = 3) -> bool:
        """Check if target responds on common ports"""
        for port in [80, 443, 22]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    return True
            except Exception:
                pass
        return False
