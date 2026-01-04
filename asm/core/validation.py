"""
Input validation utilities for security.

This module provides validation functions to prevent injection attacks
by ensuring user inputs conform to expected patterns.
"""

import re
import shlex
from typing import List, Optional, Union
import ipaddress


class ValidationError(Exception):
    """Raised when input validation fails"""

    pass


def validate_domain(domain: str) -> str:
    """
    Validate a domain name against RFC 1035 standards.

    Args:
        domain: Domain name to validate

    Returns:
        The validated domain (unchanged if valid)

    Raises:
        ValidationError: If domain is invalid
    """
    if not domain:
        raise ValidationError("Domain cannot be empty")

    if len(domain) > 253:
        raise ValidationError("Domain too long (max 253 characters)")

    domain = domain.strip()

    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$|"
        r"^(?:\d{1,3}\.){3}\d{1,3}$|"
        r"^\[[0-9a-fA-F:]+\]$"
    )

    domain_patterns = [
        re.compile(
            r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,63}$"
        ),
        re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
        re.compile(r"^\[[0-9a-fA-F:]+\]$"),
    ]

    if not any(pattern.match(domain) for pattern in domain_patterns):
        raise ValidationError(f"Invalid domain format: {domain}")

    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", '"', "'"]
    if any(char in domain for char in dangerous_chars):
        raise ValidationError(f"Domain contains dangerous characters: {domain}")

    return domain


def validate_port(port: Union[int, str]) -> int:
    """
    Validate a port number.

    Args:
        port: Port number to validate

    Returns:
        The validated port as integer

    Raises:
        ValidationError: If port is invalid
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValidationError(f"Port must be numeric: {port}")

    if not (1 <= port_int <= 65535):
        raise ValidationError(f"Port must be between 1 and 65535: {port_int}")

    return port_int


def validate_port_list(ports: Union[List[int], List[str], str]) -> List[int]:
    """
    Validate a list of port numbers.

    Args:
        ports: List of ports or comma-separated string

    Returns:
        List of validated port numbers

    Raises:
        ValidationError: If any port is invalid
    """
    if isinstance(ports, str):
        port_list = ports.split(",")
    elif isinstance(ports, list):
        port_list = ports
    else:
        raise ValidationError("Ports must be a list or comma-separated string")

    validated_ports = []
    for port in port_list:
        validated_ports.append(validate_port(port))

    return sorted(list(set(validated_ports)))


def validate_url(url: str) -> str:
    """
    Validate a URL format.

    Args:
        url: URL to validate

    Returns:
        The validated URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url:
        raise ValidationError("URL cannot be empty")

    if len(url) > 2048:
        raise ValidationError("URL too long (max 2048 characters)")

    url_pattern = re.compile(
        r"^(https?://)?"
        r"(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}|"
        r"(?:\d{1,3}\.){3}\d{1,3})"
        r"(?::\d{1,5})?"
        r"(?:/[^\s]*)?$"
    )

    if not url_pattern.match(url.strip()):
        raise ValidationError(f"Invalid URL format: {url}")

    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">"]
    if any(char in url for char in dangerous_chars):
        raise ValidationError(f"URL contains dangerous characters: {url}")

    return url.strip()


def validate_subdomain(subdomain: str) -> str:
    """
    Validate a subdomain name.

    Args:
        subdomain: Subdomain to validate

    Returns:
        The validated subdomain

    Raises:
        ValidationError: If subdomain is invalid
    """
    if not subdomain:
        raise ValidationError("Subdomain cannot be empty")

    if len(subdomain) > 253:
        raise ValidationError("Subdomain too long (max 253 characters)")

    subdomain = subdomain.strip().lower()

    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    )

    if not pattern.match(subdomain):
        raise ValidationError(f"Invalid subdomain format: {subdomain}")

    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", '"', "'"]
    if any(char in subdomain for char in dangerous_chars):
        raise ValidationError(f"Subdomain contains dangerous characters: {subdomain}")

    return subdomain


def sanitize_shell_arg(arg: str) -> str:
    """
    Sanitize an argument for shell command execution.

    Args:
        arg: Argument to sanitize

    Returns:
        Properly quoted argument safe for shell execution
    """
    if not isinstance(arg, str):
        raise ValidationError("Shell argument must be a string")

    return shlex.quote(arg)


def validate_file_path(file_path: str, allowed_dirs: Optional[List[str]] = None) -> str:
    """
    Validate a file path to prevent path traversal attacks.

    Args:
        file_path: File path to validate
        allowed_dirs: List of allowed base directories (optional)

    Returns:
        The validated, normalized file path

    Raises:
        ValidationError: If path is invalid or contains traversal
    """
    if not file_path:
        raise ValidationError("File path cannot be empty")

    try:
        normalized_path = str(Path(file_path).resolve())
    except Exception as e:
        raise ValidationError(f"Invalid path format: {e}")

    if ".." in file_path:
        raise ValidationError(f"Path traversal detected: {file_path}")

    if allowed_dirs:
        allowed_resolved = [str(Path(d).resolve()) for d in allowed_dirs]
        if not any(normalized_path.startswith(allowed) for allowed in allowed_resolved):
            raise ValidationError(f"Path not in allowed directories: {normalized_path}")

    return normalized_path


from pathlib import Path


def is_safe_input(input_str: str) -> bool:
    """
    Quick check if input contains obviously dangerous characters.

    Args:
        input_str: Input string to check

    Returns:
        True if input appears safe, False otherwise
    """
    if not isinstance(input_str, str):
        return False

    dangerous_patterns = [
        r"[;&|`$()<>]",
        r"\.\./.*",
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, input_str):
            return False

    return True
