"""
API endpoint discovery module.
Discovers OpenAPI/Swagger specs, GraphQL endpoints, and API documentation.
"""

import requests
import json
import re
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from ..core.config import Config
from ..constants.api_paths import (
    SWAGGER_PATHS,
    OPENAPI_PATHS,
    GRAPHQL_PATHS,
    API_DOC_PATHS,
    COMMON_API_PATHS,
    GRAPHQL_INTROSPECTION_QUERY,
)


class APIDiscovery:
    """Discover API endpoints, documentation, and specifications"""

    def __init__(self, config: Config):
        self.config = config
        self.headers = {
            "User-Agent": "Mozilla/5.0 ASM-Tool/1.0",
            "Accept": "application/json, text/html, */*",
        }

    def discover(self, targets: List[str], workers: int = 10) -> Dict:
        """
        Discover API endpoints across multiple targets.

        Args:
            targets: List of domains/subdomains to check
            workers: Number of parallel workers

        Returns:
            Dict with discovered APIs, specs, and GraphQL endpoints
        """
        results = {
            "swagger_specs": [],
            "openapi_specs": [],
            "graphql_endpoints": [],
            "api_docs": [],
            "api_endpoints": [],
            "total_targets": len(targets),
        }

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._check_target, target): target
                for target in targets
            }

            for future in as_completed(futures):
                try:
                    target_results = future.result()
                    if target_results:
                        results["swagger_specs"].extend(
                            target_results.get("swagger", [])
                        )
                        results["openapi_specs"].extend(
                            target_results.get("openapi", [])
                        )
                        results["graphql_endpoints"].extend(
                            target_results.get("graphql", [])
                        )
                        results["api_docs"].extend(target_results.get("docs", []))
                        results["api_endpoints"].extend(
                            target_results.get("endpoints", [])
                        )
                except Exception:
                    pass

        return results

    def _check_target(self, target: str) -> Optional[Dict]:
        """Check a single target for API endpoints"""
        results = {
            "swagger": [],
            "openapi": [],
            "graphql": [],
            "docs": [],
            "endpoints": [],
        }

        # Normalize target to URL
        if not target.startswith(("http://", "https://")):
            base_urls = [f"https://{target}", f"http://{target}"]
        else:
            base_urls = [target]

        for base_url in base_urls:
            # Check Swagger endpoints
            for path in SWAGGER_PATHS:
                result = self._check_swagger(base_url, path)
                if result:
                    results["swagger"].append(result)

            # Check OpenAPI endpoints
            for path in OPENAPI_PATHS:
                result = self._check_openapi(base_url, path)
                if result:
                    results["openapi"].append(result)

            # Check GraphQL endpoints
            for path in GRAPHQL_PATHS:
                result = self._check_graphql(base_url, path)
                if result:
                    results["graphql"].append(result)

            # Check API documentation
            for path in API_DOC_PATHS:
                result = self._check_api_docs(base_url, path)
                if result:
                    results["docs"].append(result)

            # Check common API paths
            for path in COMMON_API_PATHS:
                result = self._check_api_endpoint(base_url, path)
                if result:
                    results["endpoints"].append(result)

            # If we found results on HTTPS, don't bother with HTTP
            if any(results.values()):
                break

        return results if any(results.values()) else None

    def _check_swagger(self, base_url: str, path: str) -> Optional[Dict]:
        """Check for Swagger specification"""
        url = urljoin(base_url, path)
        try:
            response = requests.get(
                url,
                timeout=self.config.timeout_http,
                headers=self.headers,
                verify=False,
                allow_redirects=True,
            )

            if response.status_code == 200:
                content = response.text
                # Check if it looks like a Swagger spec
                if (
                    '"swagger"' in content
                    or "'swagger'" in content
                    or "swagger:" in content
                ):
                    spec_data = self._parse_spec(content)
                    return {
                        "url": url,
                        "type": "swagger",
                        "version": spec_data.get("version", "unknown"),
                        "title": spec_data.get("title", ""),
                        "endpoints_count": spec_data.get("endpoints_count", 0),
                        "endpoints": spec_data.get("endpoints", [])[
                            :20
                        ],  # Limit stored endpoints
                    }
        except Exception:
            pass
        return None

    def _check_openapi(self, base_url: str, path: str) -> Optional[Dict]:
        """Check for OpenAPI specification"""
        url = urljoin(base_url, path)
        try:
            response = requests.get(
                url,
                timeout=self.config.timeout_http,
                headers=self.headers,
                verify=False,
                allow_redirects=True,
            )

            if response.status_code == 200:
                content = response.text
                # Check if it looks like an OpenAPI spec
                if (
                    '"openapi"' in content
                    or "'openapi'" in content
                    or "openapi:" in content
                ):
                    spec_data = self._parse_spec(content)
                    return {
                        "url": url,
                        "type": "openapi",
                        "version": spec_data.get("version", "unknown"),
                        "title": spec_data.get("title", ""),
                        "endpoints_count": spec_data.get("endpoints_count", 0),
                        "endpoints": spec_data.get("endpoints", [])[:20],
                    }
        except Exception:
            pass
        return None

    def _parse_spec(self, content: str) -> Dict:
        """Parse OpenAPI/Swagger spec and extract info"""
        try:
            if content.strip().startswith("{"):
                spec = json.loads(content)
            else:
                # Try YAML
                import yaml

                spec = yaml.safe_load(content)

            if not isinstance(spec, dict):
                return {}

            endpoints = []
            paths = spec.get("paths", {})
            for path, methods in paths.items():
                if isinstance(methods, dict):
                    for method in methods.keys():
                        if method.lower() in [
                            "get",
                            "post",
                            "put",
                            "delete",
                            "patch",
                            "options",
                            "head",
                        ]:
                            endpoints.append(
                                {
                                    "path": path,
                                    "method": method.upper(),
                                    "summary": methods[method].get("summary", "")
                                    if isinstance(methods[method], dict)
                                    else "",
                                }
                            )

            info = spec.get("info", {})
            return {
                "version": spec.get("openapi", spec.get("swagger", "unknown")),
                "title": info.get("title", ""),
                "description": info.get("description", "")[:200]
                if info.get("description")
                else "",
                "endpoints_count": len(endpoints),
                "endpoints": endpoints,
            }
        except Exception:
            return {}

    def _check_graphql(self, base_url: str, path: str) -> Optional[Dict]:
        """Check for GraphQL endpoint"""
        url = urljoin(base_url, path)

        # First try GET with query parameter
        try:
            response = requests.get(
                url,
                params={"query": "{ __typename }"},
                timeout=self.config.timeout_http,
                headers={**self.headers, "Accept": "application/json"},
                verify=False,
                allow_redirects=True,
            )

            if self._is_graphql_response(response):
                introspection = self._try_graphql_introspection(url)
                return {
                    "url": url,
                    "type": "graphql",
                    "introspection_enabled": introspection.get("enabled", False),
                    "types_count": introspection.get("types_count", 0),
                    "queries": introspection.get("queries", []),
                    "mutations": introspection.get("mutations", []),
                }
        except Exception:
            pass

        # Try POST
        try:
            response = requests.post(
                url,
                json={"query": "{ __typename }"},
                timeout=self.config.timeout_http,
                headers={**self.headers, "Content-Type": "application/json"},
                verify=False,
                allow_redirects=True,
            )

            if self._is_graphql_response(response):
                introspection = self._try_graphql_introspection(url)
                return {
                    "url": url,
                    "type": "graphql",
                    "introspection_enabled": introspection.get("enabled", False),
                    "types_count": introspection.get("types_count", 0),
                    "queries": introspection.get("queries", []),
                    "mutations": introspection.get("mutations", []),
                }
        except Exception:
            pass

        return None

    def _is_graphql_response(self, response: requests.Response) -> bool:
        """Check if response looks like GraphQL"""
        if response.status_code not in [200, 400]:
            return False

        try:
            data = response.json()
            # GraphQL responses have 'data' or 'errors' keys
            return "data" in data or "errors" in data
        except Exception:
            return False

    def _try_graphql_introspection(self, url: str) -> Dict:
        """Attempt GraphQL introspection"""
        result = {
            "enabled": False,
            "types_count": 0,
            "queries": [],
            "mutations": [],
        }

        try:
            response = requests.post(
                url,
                json={"query": GRAPHQL_INTROSPECTION_QUERY},
                timeout=self.config.timeout_http,
                headers={**self.headers, "Content-Type": "application/json"},
                verify=False,
            )

            if response.status_code == 200:
                data = response.json()
                if "data" in data and data["data"] and "__schema" in data["data"]:
                    schema = data["data"]["__schema"]
                    result["enabled"] = True

                    types = schema.get("types", [])
                    result["types_count"] = len(types)

                    # Extract query fields
                    query_type_name = schema.get("queryType", {}).get("name")
                    mutation_type_name = schema.get("mutationType", {}).get("name")

                    for t in types:
                        if t.get("name") == query_type_name and t.get("fields"):
                            result["queries"] = [f["name"] for f in t["fields"][:20]]
                        elif t.get("name") == mutation_type_name and t.get("fields"):
                            result["mutations"] = [f["name"] for f in t["fields"][:20]]

        except Exception:
            pass

        return result

    def _check_api_docs(self, base_url: str, path: str) -> Optional[Dict]:
        """Check for API documentation pages"""
        url = urljoin(base_url, path)
        try:
            response = requests.get(
                url,
                timeout=self.config.timeout_http,
                headers=self.headers,
                verify=False,
                allow_redirects=True,
            )

            if response.status_code == 200:
                content = response.text.lower()
                # Check if it looks like API documentation
                doc_indicators = [
                    "api documentation",
                    "api reference",
                    "swagger",
                    "openapi",
                    "graphql",
                    "endpoint",
                    "rest api",
                    "api-docs",
                    "redoc",
                    "rapidoc",
                ]
                if any(indicator in content for indicator in doc_indicators):
                    return {
                        "url": url,
                        "type": "documentation",
                        "title": self._extract_title(response.text),
                    }
        except Exception:
            pass
        return None

    def _check_api_endpoint(self, base_url: str, path: str) -> Optional[Dict]:
        """Check for common API endpoints"""
        url = urljoin(base_url, path)
        try:
            response = requests.get(
                url,
                timeout=self.config.timeout_http,
                headers={**self.headers, "Accept": "application/json"},
                verify=False,
                allow_redirects=True,
            )

            if response.status_code == 200:
                content_type = response.headers.get("Content-Type", "")

                # Check if JSON response
                if "application/json" in content_type:
                    try:
                        data = response.json()
                        return {
                            "url": url,
                            "type": "api_endpoint",
                            "content_type": "json",
                            "keys": list(data.keys())[:10]
                            if isinstance(data, dict)
                            else None,
                        }
                    except Exception:
                        pass

                # Check for XML
                elif "xml" in content_type:
                    return {
                        "url": url,
                        "type": "api_endpoint",
                        "content_type": "xml",
                    }

        except Exception:
            pass
        return None

    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def check_single_target(self, target: str) -> Dict:
        """Check a single target with detailed output"""
        return self._check_target(target) or {
            "swagger": [],
            "openapi": [],
            "graphql": [],
            "docs": [],
            "endpoints": [],
        }
