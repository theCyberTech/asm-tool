"""
Technology fingerprinting module
Uses httpx and custom detection
"""

import subprocess
import json
import re
import requests
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import urllib3

from ..core.validation import validate_domain
from ..core.config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechnologyFingerprinter:
    """Identify technologies running on web servers"""

    def __init__(self, config: Config):
        self.config = config
        self.httpx_available = self._check_httpx()

    def _check_httpx(self) -> bool:
        """Check if httpx is available"""
        try:
            subprocess.run(["httpx", "-version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def fingerprint(self, target: str) -> Optional[Dict]:
        """Fingerprint a target host"""
        validated_target = validate_domain(target)
        if self.httpx_available:
            return self._httpx_fingerprint(validated_target)
        else:
            return self._requests_fingerprint(validated_target)

    def fingerprint_many(self, targets: List[str]) -> List[Dict]:
        """Fingerprint multiple targets efficiently"""
        validated_targets = [validate_domain(t) for t in targets]
        if self.httpx_available:
            return self._httpx_fingerprint_batch(validated_targets)
        else:
            results = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(self._requests_fingerprint, t): t for t in targets
                }
                for future in futures:
                    result = future.result()
                    if result:
                        results.append(result)
            return results

    def _httpx_fingerprint(self, target: str) -> Optional[Dict]:
        """Use httpx for fingerprinting"""
        try:
            cmd = [
                "httpx",
                "-u",
                target,
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-web-server",
                "-follow-redirects",
                "-timeout",
                "10",
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.stdout.strip():
                data = json.loads(result.stdout.strip())
                return {
                    "host": target,
                    "url": data.get("url", f"https://{target}"),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "technologies": data.get("tech", []),
                    "server": data.get("webserver", ""),
                    "content_length": data.get("content_length", 0),
                    "redirect_url": data.get("final_url", ""),
                    "headers": {},
                }
        except Exception:
            pass

        return self._requests_fingerprint(target)

    def _httpx_fingerprint_batch(self, targets: List[str]) -> List[Dict]:
        """Batch fingerprint using httpx stdin"""
        results = []

        try:
            cmd = [
                "httpx",
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-web-server",
                "-follow-redirects",
                "-timeout",
                "10",
                "-threads",
                "50",
            ]

            input_data = "\n".join(targets)
            result = subprocess.run(
                cmd, input=input_data, capture_output=True, text=True, timeout=300
            )

            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        results.append(
                            {
                                "host": data.get("input", ""),
                                "url": data.get("url", ""),
                                "status_code": data.get("status_code"),
                                "title": data.get("title", ""),
                                "technologies": data.get("tech", []),
                                "server": data.get("webserver", ""),
                                "content_length": data.get("content_length", 0),
                                "redirect_url": data.get("final_url", ""),
                                "headers": {},
                            }
                        )
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

        return results

    def _requests_fingerprint(self, target: str) -> Optional[Dict]:
        """Fallback fingerprinting using requests"""
        result = {
            "host": target,
            "url": "",
            "status_code": None,
            "title": "",
            "technologies": [],
            "server": "",
            "content_length": 0,
            "redirect_url": "",
            "headers": {},
        }

        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}"
            try:
                response = requests.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; ASM-Tool/1.0)"},
                )

                result["url"] = url
                result["status_code"] = response.status_code
                result["content_length"] = len(response.content)
                result["redirect_url"] = response.url if response.url != url else ""
                result["headers"] = dict(response.headers)

                title_match = re.search(
                    r"<title[^>]*>([^<]+)</title>", response.text, re.IGNORECASE
                )
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

                result["server"] = response.headers.get("Server", "")
                result["technologies"] = self._detect_technologies(response)

                return result

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue

        return None

    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies from response"""
        techs = []

        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text[:50000].lower()

        server = headers.get("server", "").lower()
        if "nginx" in server:
            techs.append("nginx")
        if "apache" in server:
            techs.append("Apache")
        if "cloudflare" in server:
            techs.append("Cloudflare")
        if "iis" in server:
            techs.append("IIS")

        if "x-powered-by" in headers:
            powered = headers["x-powered-by"]
            if "php" in powered.lower():
                techs.append("PHP")
            if "asp.net" in powered.lower():
                techs.append("ASP.NET")
            if "express" in powered.lower():
                techs.append("Express")

        cookies = headers.get("set-cookie", "")
        if "wordpress" in cookies.lower() or "wp-" in cookies.lower():
            techs.append("WordPress")
        if "laravel" in cookies.lower():
            techs.append("Laravel")
        if "django" in cookies.lower():
            techs.append("Django")

        if "wp-content" in body or "wordpress" in body:
            if "WordPress" not in techs:
                techs.append("WordPress")
        if "drupal" in body:
            techs.append("Drupal")
        if "joomla" in body:
            techs.append("Joomla")
        if "react" in body or "reactjs" in body:
            techs.append("React")
        if "vue" in body or "vuejs" in body:
            techs.append("Vue.js")
        if "angular" in body:
            techs.append("Angular")
        if "next.js" in body or "_next" in body:
            techs.append("Next.js")
        if "shopify" in body:
            techs.append("Shopify")
        if "wix.com" in body:
            techs.append("Wix")
        if "squarespace" in body:
            techs.append("Squarespace")

        if "cloudflare" in headers.get("cf-ray", "").lower() or "cloudflare" in str(
            headers
        ):
            if "Cloudflare" not in techs:
                techs.append("Cloudflare")
        if "x-amz" in str(headers).lower() or "amazonaws" in body:
            techs.append("AWS")
        if "x-azure" in str(headers).lower():
            techs.append("Azure")
        if "x-goog" in str(headers).lower():
            techs.append("Google Cloud")

        return list(set(techs))
