"""
DNS Record monitoring module
"""

import dns.resolver
import dns.exception
from typing import Dict, List, Optional

from ..core.config import Config


class DNSMonitor:
    """Monitor DNS records for changes"""

    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

    def __init__(self, config: Config):
        self.config = config
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.timeout_dns
        self.resolver.lifetime = config.timeout_dns * 2

    def get_records(
        self, domain: str, record_types: List[str] = None
    ) -> Dict[str, List]:
        """Get all DNS records for a domain"""
        if record_types is None:
            record_types = self.RECORD_TYPES

        records = {}

        for rtype in record_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist
                break
            except dns.resolver.NoAnswer:
                # No records of this type
                continue
            except dns.exception.Timeout:
                continue
            except Exception:
                continue

        return records

    def get_nameservers(self, domain: str) -> List[str]:
        """Get authoritative nameservers for a domain"""
        try:
            answers = self.resolver.resolve(domain, "NS")
            return [str(rdata).rstrip(".") for rdata in answers]
        except Exception:
            return []

    def get_mx_records(self, domain: str) -> List[Dict]:
        """Get MX records with priorities"""
        mx_records = []
        try:
            answers = self.resolver.resolve(domain, "MX")
            for rdata in answers:
                mx_records.append(
                    {
                        "priority": rdata.preference,
                        "host": str(rdata.exchange).rstrip("."),
                    }
                )
            mx_records.sort(key=lambda x: x["priority"])
        except Exception:
            pass
        return mx_records

    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records (useful for SPF, DKIM, DMARC)"""
        txt_records = []
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_records.append(str(rdata).strip('"'))
        except Exception:
            pass
        return txt_records

    def check_spf(self, domain: str) -> Optional[str]:
        """Check for SPF record"""
        txt_records = self.get_txt_records(domain)
        for record in txt_records:
            if record.startswith("v=spf1"):
                return record
        return None

    def check_dmarc(self, domain: str) -> Optional[str]:
        """Check for DMARC record"""
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = self.get_txt_records(dmarc_domain)
        for record in txt_records:
            if record.startswith("v=DMARC1"):
                return record
        return None

    def check_dkim(self, domain: str, selector: str = "default") -> Optional[str]:
        """Check for DKIM record"""
        dkim_domain = f"{selector}._domainkey.{domain}"
        txt_records = self.get_txt_records(dkim_domain)
        for record in txt_records:
            if "DKIM" in record.upper() or "k=" in record:
                return record
        return None

    def get_caa_records(self, domain: str) -> List[Dict]:
        """Get CAA records (Certificate Authority Authorization)"""
        caa_records = []
        try:
            answers = self.resolver.resolve(domain, "CAA")
            for rdata in answers:
                caa_records.append(
                    {
                        "flags": rdata.flags,
                        "tag": rdata.tag.decode()
                        if isinstance(rdata.tag, bytes)
                        else rdata.tag,
                        "value": rdata.value.decode()
                        if isinstance(rdata.value, bytes)
                        else rdata.value,
                    }
                )
        except Exception:
            pass
        return caa_records

    def check_dnssec(self, domain: str) -> bool:
        """Check if DNSSEC is enabled"""
        try:
            answers = self.resolver.resolve(domain, "DNSKEY")
            return len(list(answers)) > 0
        except Exception:
            return False

    def get_email_security_status(self, domain: str) -> Dict:
        """Get comprehensive email security status"""
        return {
            "spf": self.check_spf(domain),
            "dmarc": self.check_dmarc(domain),
            "dkim_default": self.check_dkim(domain, "default"),
            "dkim_google": self.check_dkim(domain, "google"),
            "dkim_selector1": self.check_dkim(domain, "selector1"),
            "mx_records": self.get_mx_records(domain),
        }

    def resolve_host(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses"""
        ips = []
        for rtype in ["A", "AAAA"]:
            try:
                answers = self.resolver.resolve(hostname, rtype)
                ips.extend([str(rdata) for rdata in answers])
            except Exception:
                pass
        return ips

    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            from dns.reversename import from_address

            rev_name = from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            if answers:
                return str(answers[0]).rstrip(".")
        except Exception:
            pass
        return None
