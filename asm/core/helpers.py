"""
Helper functions for ASM Tool
"""
from typing import List, Optional
from .database import Database
from .config import Config


def resolve_targets(
    db: Database, config: Config, domain: Optional[str] = None, all_known: bool = False
) -> List[str]:
    """
    Resolve list of target domains/subdomains based on input parameters.

    Logic:
    1. If all_known=True: Return all subdomains in DB
    2. If domain provided: Return subdomains for that domain (fallback to [domain] if empty)
    3. If neither: Return subdomains for all configured domains (fallback to configured domains if empty)

    Args:
        db: Database instance
        config: Config instance
        domain: Specific domain to target (optional)
        all_known: Whether to target all known subdomains (default: False)

    Returns:
        List of target domain strings
    """
    targets = []

    if all_known:
        targets = db.get_all_subdomains()
    elif domain:
        targets = db.get_subdomains(domain)
        if not targets:
            targets = [domain]
    else:
        # Use configured domains
        for d in config.domains:
            targets.extend(db.get_subdomains(d))
        
        # Fallback to just the configured domains if no subdomains found
        if not targets:
            targets = list(config.domains)

    # Ensure uniqueness
    return sorted(list(set(targets)))
