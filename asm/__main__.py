"""
ASM Tool - Main CLI Entry Point
"""

import click
import yaml
import atexit
from pathlib import Path
from typing import Dict
from rich.console import Console
from rich.table import Table

from .core.config import Config
from .core.database import Database
from .modules.subdomains import SubdomainEnumerator
from .modules.ports import PortScanner
from .modules.certificates import CertificateMonitor
from .modules.technologies import TechnologyFingerprinter
from .modules.dns_monitor import DNSMonitor
from .modules.nuclei_scanner import NucleiScanner
from .modules.urls import URLEnumerator
from .modules.takeover import TakeoverDetector
from .modules.api_discovery import APIDiscovery
from .modules.emails import EmailEnumerator
from .core.reporter import Reporter
from .core.notifier import Notifier
from .core.helpers import resolve_targets
from .core.scheduler import Scheduler

console = Console()


@click.group()
@click.option("--config", "-c", default="/app/config.yaml", help="Path to config file")
@click.option(
    "--data-dir", "-d", default="/app/data", help="Data directory for persistence"
)
@click.pass_context
def cli(ctx, config, data_dir):
    """Attack Surface Management Tool

    Monitor and track your external attack surface including subdomains,
    open ports, certificates, technologies, and vulnerabilities.
    """
    ctx.ensure_object(dict)  

    # Stylized coloring: crew (white/def), ai (red)
    # Since it's a single block, hard to regex colorize easily in one go without splitting strings.
    # Manual approximation for simplicity:
    
    console.print(r"""[bold white]   ______[/][bold red]                        ___    ____[/]
[bold white]  / ____/[/][bold white]________  _      __[/][bold red]  /   |  /  _/[/][bold red][/]
[bold white] / /   [/][bold white]/ ___/ _ \ | | /| / /[/][bold red] / /| |  / /  [/]
[bold white]/ /___[/][bold white]/ /  /  __/ | |/ |/ / [/][bold red]/ ___ |_/ /   [/]
[bold white]\____/[/][bold white]_/   \___/  |__/|__/ [/][bold red]/_/  |_/___/   [/]""", highlight=False)
    console.print("[dim]Powered by CrewAI[/]\n")

    config_path = Path(config)
    if config_path.exists():
        ctx.obj["config"] = Config.from_file(config_path)
    else:
        ctx.obj["config"] = Config()

    ctx.obj["data_dir"] = Path(data_dir)
    ctx.obj["data_dir"].mkdir(parents=True, exist_ok=True)
    ctx.obj["db"] = Database(ctx.obj["data_dir"] / "asm.db")

    # Ensure database is closed on exit to flush CachingMiddleware
    atexit.register(ctx.obj["db"].close)


@cli.command()
@click.argument("domains", nargs=-1, required=False)
@click.option("--passive-only", is_flag=True, help="Only use passive reconnaissance")
@click.pass_context
def discover(ctx, domains, passive_only):
    """Discover subdomains for the given domain(s)"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    # Use configured domains if none specified
    domains = domains if domains else config.domains
    if not domains:
        console.print(
            "[red]Error:[/] No domain specified and none configured in config.yaml"
        )
        return

    enumerator = SubdomainEnumerator(config)

    for domain in domains:
        console.print(f"\n[bold blue]Discovering subdomains for:[/] {domain}")

        results = enumerator.enumerate(domain, passive_only=passive_only)

        new_count = 0
        for subdomain in results:
            if db.add_subdomain(domain, subdomain):
                new_count += 1
                console.print(f"  [green]+ NEW:[/] {subdomain}")
            else:
                console.print(f"  [dim]  Known:[/] {subdomain}")

        console.print(
            f"\n[bold]Summary:[/] Found {len(results)} subdomains, {new_count} new"
        )


@cli.command()
@click.argument("domain", required=False)
@click.option(
    "--ports",
    "-p",
    default="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443",
    help="Ports to scan (comma-separated)",
)
@click.option("--all-known", is_flag=True, help="Scan all known subdomains")
@click.option("--workers", "-w", default=5, help="Parallel scan workers (default 5)")
@click.pass_context
def portscan(ctx, domain, ports, all_known, workers):
    """Scan ports on discovered assets"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    scanner = PortScanner(config)
    port_list = [int(p.strip()) for p in ports.split(",")]

    targets = resolve_targets(db, config, domain, all_known)

    if not targets:
        console.print(
            "[red]Error:[/] No targets found. Run 'discover' first or specify a domain."
        )
        return

    parallel_note = f" ({workers} workers)" if len(targets) > 1 else ""
    console.print(
        f"\n[bold blue]Scanning {len(targets)} targets on {len(port_list)} ports{parallel_note}[/]"
    )

    # Use parallel scanning for multiple targets
    all_results = scanner.scan_batch(targets, port_list, workers=workers)

    for results in all_results:
        target = results["target"]
        if results.get("error"):
            console.print(f"\n[red]{target}[/] - Error: {results['error']}")
            continue

        if results["open_ports"]:
            console.print(f"\n[yellow]{target}[/]")
            for port_info in results["open_ports"]:
                port = port_info["port"]
                service = port_info.get("service", "unknown")
                version = port_info.get("version", "")

                is_new = db.add_port(target, port, service, version)

                if is_new:
                    console.print(
                        f"  [green]+ NEW:[/] {port}/tcp - {service} {version}"
                    )
                else:
                    console.print(f"  [dim]  Open:[/] {port}/tcp - {service} {version}")


@cli.command()
@click.argument("domain", required=False)
@click.option("--all-known", is_flag=True, help="Check all known subdomains")
@click.option("--days-warning", default=30, help="Warn if cert expires within N days")
@click.option("--workers", "-w", default=10, help="Parallel check workers (default 10)")
@click.pass_context
def certificates(ctx, domain, all_known, days_warning, workers):
    """Monitor SSL/TLS certificates"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    monitor = CertificateMonitor(config)

    targets = resolve_targets(db, config, domain, all_known)

    if not targets:
        console.print(
            "[red]Error:[/] No targets found. Run 'discover' first or specify a domain."
        )
        return

    parallel_note = f" ({workers} workers)" if len(targets) > 1 else ""
    console.print(
        f"\n[bold blue]Checking certificates for {len(targets)} targets{parallel_note}[/]"
    )

    expiring_soon = []

    # Use parallel checking for multiple targets
    all_results = monitor.check_certificates_batch(targets, workers=workers)

    for cert_info in all_results:
        target = cert_info["host"]

        if cert_info.get("error"):
            console.print(f"  [dim]- {target}: {cert_info['error'][:50]}[/]")
            continue

        days_left = cert_info["days_until_expiry"]
        issuer = cert_info["issuer"]

        db.add_certificate(target, cert_info)

        if days_left < 0:
            console.print(
                f"  [red]✗ EXPIRED:[/] {target} "
                f"(expired {abs(days_left)} days ago)"
            )
        elif days_left <= days_warning:
            console.print(
                f"  [yellow]⚠ WARNING:[/] {target} expires in {days_left} days"
            )
            expiring_soon.append((target, days_left))
        else:
            console.print(
                f"  [green]✓[/] {target} - "
                f"valid for {days_left} days ({issuer})"
            )

    if expiring_soon:
        console.print(
            f"\n[bold yellow]⚠ {len(expiring_soon)} certificates "
            f"expiring within {days_warning} days[/]"
        )


@cli.command()
@click.argument("domain", required=False)
@click.option("--all-known", is_flag=True, help="Fingerprint all known subdomains")
@click.pass_context
def fingerprint(ctx, domain, all_known):
    """Identify technologies on discovered assets"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    fingerprinter = TechnologyFingerprinter(config)

    targets = resolve_targets(db, config, domain, all_known)

    if not targets:
        console.print(
            "[red]Error:[/] No targets found. Run 'discover' first or specify a domain."
        )
        return

    console.print(f"\n[bold blue]Fingerprinting {len(targets)} targets[/]")

    for target in targets:
        tech_info = fingerprinter.fingerprint(target)
        if tech_info:
            db.add_technologies(target, tech_info)

            techs = ", ".join(tech_info.get("technologies", []))[:80]
            status = tech_info.get("status_code", "?")
            title = tech_info.get("title", "")[:40]

            console.print(f"  [{status}] {target}")
            if title:
                console.print(f"      Title: {title}")
            if techs:
                console.print(f"      Tech: {techs}")


@cli.command()
@click.argument("domain")
@click.pass_context
def dns(ctx, domain):
    """Monitor DNS records for changes"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    monitor = DNSMonitor(config)

    console.print(f"\n[bold blue]Checking DNS records for:[/] {domain}")

    records = monitor.get_records(domain)
    changes = db.check_dns_changes(domain, records)

    table = Table(title=f"DNS Records for {domain}")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="white")
    table.add_column("Status", style="green")

    for record_type, values in records.items():
        for value in values:
            status = ""
            if changes.get("new", {}).get(record_type):
                if value in changes["new"][record_type]:
                    status = "[green]+ NEW[/]"
            if changes.get("removed", {}).get(record_type):
                if value in changes["removed"][record_type]:
                    status = "[red]- REMOVED[/]"
            table.add_row(record_type, str(value)[:60], status)

    console.print(table)
    db.save_dns_records(domain, records)


@cli.command()
@click.argument("domain", required=False)
@click.option("--all-known", is_flag=True, help="Scan all known subdomains")
@click.option(
    "--severity", "-s", default="medium,high,critical", help="Minimum severity"
)
@click.option("--templates", "-t", default="", help="Specific template tags to use")
@click.pass_context
def vulnscan(ctx, domain, all_known, severity, templates):
    """Run vulnerability scan using Nuclei"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    scanner = NucleiScanner(config)

    targets = resolve_targets(db, config, domain, all_known)

    if not targets:
        console.print(
            "[red]Error:[/] No targets found. Run 'discover' first or specify a domain."
        )
        return

    console.print(
        f"\n[bold blue]Running vulnerability scan on {len(targets)} targets[/]"
    )
    console.print(f"[dim]Severity filter: {severity}[/]")

    findings = scanner.scan(targets, severity=severity, tags=templates)

    for finding in findings:
        sev = finding["severity"].upper()
        color = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }.get(sev, "white")

        db.add_finding(finding)

        console.print(f"\n[{color}][{sev}][/] {finding['name']}")
        console.print(f"  Host: {finding['host']}")
        console.print(f"  Template: {finding['template_id']}")
        if finding.get("matched_at"):
            console.print(f"  Matched: {finding['matched_at']}")

    console.print(f"\n[bold]Total findings:[/] {len(findings)}")


@cli.command()
@click.argument("domain", required=False)
@click.option("--include-subs/--no-subs", default=True, help="Include subdomains")
@click.option("--interesting-only", is_flag=True, help="Only show interesting URLs")
@click.option("--js-only", is_flag=True, help="Only show JavaScript files")
@click.option("--show-params", is_flag=True, help="Show discovered parameters")
@click.pass_context
def urls(ctx, domain, include_subs, interesting_only, js_only, show_params):
    """Enumerate historical URLs using GAU (Wayback, CommonCrawl, etc.)"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    # Use configured domains if none specified
    domains = [domain] if domain else config.domains
    if not domains:
        console.print(
            "[red]Error:[/] No domain specified and none configured in config.yaml"
        )
        return

    enumerator = URLEnumerator(config)

    for domain in domains:
        console.print(f"\n[bold blue]Enumerating URLs for:[/] {domain}")
        console.print("[dim]Sources: Wayback Machine, Common Crawl, OTX, URLScan[/]")

        results = enumerator.enumerate(domain, include_subdomains=include_subs)

        # Store in database
        counts = db.add_urls_bulk(domain, results)

        # Display summary
        console.print("\n[bold]Summary:[/]")
        console.print(f"  Total URLs: {results['total']}")
        console.print(f"  Unique paths: {len(results['unique_paths'])}")
        console.print(f"  Unique endpoints: {len(results['endpoints'])}")
        console.print(f"  Interesting URLs: {len(results['interesting'])}")
        console.print(f"  New URLs stored: {counts['new']}")

        # Show by extension breakdown
        if results["by_extension"]:
            console.print("\n[bold]By file type:[/]")
            for ext_type, urls_list in sorted(results["by_extension"].items()):
                console.print(f"  {ext_type}: {len(urls_list)}")

        # Show interesting URLs
        if results["interesting"] and not js_only:
            console.print(
                f"\n[bold yellow]Interesting URLs ({len(results['interesting'])}):[/]"
            )
            for url in results["interesting"][:20]:  # Limit display
                console.print(
                    f"  [yellow]→[/] {url[:100]}{'...' if len(url) > 100 else ''}"
                )
            if len(results["interesting"]) > 20:
                console.print(
                    f"  [dim]... and {len(results['interesting']) - 20} more[/]"
                )

        # Show JS files if requested
        if js_only and results["by_extension"].get("js"):
            console.print(
                f"\n[bold cyan]JavaScript files "
                f"({len(results['by_extension']['js'])}):[/]"
            )
            for url in results["by_extension"]["js"][:30]:
                console.print(
                    f"  [cyan]→[/] {url[:100]}{'...' if len(url) > 100 else ''}"
                )
            if len(results["by_extension"]["js"]) > 30:
                console.print(
                    f"  [dim]... and {len(results['by_extension']['js']) - 30} more[/]"
                )

        # Show parameters if requested
        if show_params and results["parameters"]:
            console.print(
                f"\n[bold magenta]Discovered parameters "
                f"({len(results['parameters'])}):[/]"
            )
            for param in sorted(results["parameters"].keys())[:30]:
                console.print(f"  [magenta]?{param}=[/]")
            if len(results["parameters"]) > 30:
                console.print(
                    f"  [dim]... and {len(results['parameters']) - 30} more[/]"
                )


@cli.command()
@click.argument("domain", required=False)
@click.option("--all-known", is_flag=True, help="Check all known subdomains")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed progress")
@click.option("--workers", "-w", default=10, help="Parallel check workers (default 10)")
@click.pass_context
def takeover(ctx, domain, all_known, verbose, workers):
    """Detect subdomain takeover vulnerabilities"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    detector = TakeoverDetector(config)

    targets = resolve_targets(db, config, domain, all_known)

    if not targets:
        console.print(
            "[red]Error:[/] No targets found. Run 'discover' first or specify a domain."
        )
        return

    parallel_note = f" ({workers} workers)" if len(targets) > 1 else ""
    console.print(
        f"\n[bold blue]Checking {len(targets)} subdomains "
        f"for takeover vulnerabilities{parallel_note}[/]"
    )
    console.print(
        f"[dim]Checking against {len(detector.get_all_fingerprints())} "
        "known vulnerable services[/]"
    )

    if verbose:
        vulnerabilities = []
        from .constants.takeover_fingerprints import FINGERPRINTS

        for target in targets:
            console.print(f"  [dim]Checking {target}...[/]", end=" ")
            cname = detector._get_cname(target)
            if cname:
                # Find matching service
                matched_service = None
                for fp in FINGERPRINTS:
                    if any(p.lower() in cname.lower() for p in fp.cnames):
                        matched_service = fp.service
                        break

                if matched_service:
                    console.print(
                        f"[yellow]CNAME → {cname}[/] [cyan]({matched_service})[/]",
                        end=" ",
                    )
                    result = detector.check_domain(target)
                    if result:
                        console.print("[red]VULNERABLE![/]")
                        vulnerabilities.append(result)
                    else:
                        console.print("[green]✓ claimed[/]")
                else:
                    console.print(
                        f"[yellow]CNAME → {cname}[/] "
                        "[dim](not a known takeover target)[/]"
                    )
            else:
                console.print("[dim]no CNAME[/]")
    else:
        vulnerabilities = detector.check_subdomains(targets, workers=workers)

    if vulnerabilities:
        console.print(
            f"\n[bold red]⚠ Found {len(vulnerabilities)} potential takeover(s)![/]\n"
        )

        for vuln in vulnerabilities:
            is_new = db.add_takeover(vuln)
            status = "[green]NEW[/]" if is_new else "[dim]Known[/]"

            console.print(f"[red]{'━' * 60}[/]")
            console.print(f"  {status} [bold red]{vuln['subdomain']}[/]")
            console.print(f"  [yellow]Service:[/] {vuln['service']}")
            console.print(f"  [yellow]CNAME:[/] {vuln.get('cname', 'N/A')}")
            console.print(f"  [yellow]Type:[/] {vuln['type']}")
            console.print(f"  [yellow]Confidence:[/] {vuln['confidence']}")
            console.print(f"  [yellow]Evidence:[/] {vuln['evidence'][:100]}")
            if vuln.get("documentation"):
                console.print(f"  [blue]Docs:[/] {vuln['documentation']}")

        console.print(
            "\n[bold red]⚠ CRITICAL: These subdomains may be vulnerable to takeover![/]"
        )
        console.print(
            "[dim]An attacker could claim these services "
            "and serve malicious content.[/]"
        )
    else:
        console.print("\n[bold green]✓ No takeover vulnerabilities detected[/]")

    # Show summary
    stats = db.get_statistics()
    if stats.get("takeovers", 0) > 0:
        console.print(
            f"\n[dim]Total open takeover findings in database: {stats['takeovers']}[/]"
        )


@cli.command()
@click.argument("domain", required=False)
@click.option("--all-known", is_flag=True, help="Check all known subdomains")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed progress")
@click.option("--workers", "-w", default=20, help="Parallel discovery workers (default 20)")
@click.pass_context
def apis(ctx, domain, all_known, verbose, workers):
    """Discover API endpoints (Swagger, OpenAPI, GraphQL)"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    discovery = APIDiscovery(config)

    targets = resolve_targets(db, config, domain, all_known)

    if not targets:
        console.print(
            "[red]Error:[/] No targets found. Run 'discover' first or specify a domain."
        )
        return

    parallel_note = f" ({workers} workers)" if len(targets) > 1 else ""
    console.print(f"\n[bold blue]Discovering APIs on {len(targets)} targets{parallel_note}[/]")
    console.print(
        "[dim]Checking for Swagger, OpenAPI specs, and GraphQL endpoints...[/]"
    )

    # Run in parallel with configurable workers
    results = discovery.discover(targets, workers=workers)

    # Show verbose output after completion
    if verbose:
        for spec in results["swagger_specs"]:
            console.print(f"  [green]✓ Swagger:[/] {spec['url']}")
            if spec.get("title"):
                console.print(
                    f"    Title: {spec['title']}, "
                    f"Endpoints: {spec.get('endpoints_count', 0)}"
                )

        for spec in results["openapi_specs"]:
            console.print(f"  [green]✓ OpenAPI:[/] {spec['url']}")
            if spec.get("title"):
                console.print(
                    f"    Title: {spec['title']}, "
                    f"Endpoints: {spec.get('endpoints_count', 0)}"
                )

        for g in results["graphql_endpoints"]:
            introspection = (
                "[red]INTROSPECTION ENABLED[/]"
                if g.get("introspection_enabled")
                else "[dim]disabled[/]"
            )
            console.print(f"  [cyan]✓ GraphQL:[/] {g['url']} ({introspection})")

        for d in results["api_docs"]:
            console.print(f"  [yellow]✓ Docs:[/] {d['url']}")

    # Store results in database
    new_count = 0
    for spec in results["swagger_specs"]:
        if db.add_api(spec):
            new_count += 1
    for spec in results["openapi_specs"]:
        if db.add_api(spec):
            new_count += 1
    for endpoint in results["graphql_endpoints"]:
        if db.add_api(endpoint):
            new_count += 1
    for doc in results["api_docs"]:
        if db.add_api(doc):
            new_count += 1

    # Summary
    console.print(f"\n[bold]{'━' * 50}[/]")
    console.print("[bold]API Discovery Summary[/]")
    console.print(f"[bold]{'━' * 50}[/]")

    if results["swagger_specs"]:
        console.print(
            f"\n[green]Swagger/OpenAPI Specs: "
            f"{len(results['swagger_specs']) + len(results['openapi_specs'])}[/]"
        )
        for spec in results["swagger_specs"] + results["openapi_specs"]:
            console.print(f"  → {spec['url']}")
            if spec.get("endpoints_count"):
                console.print(
                    f"    [dim]{spec['endpoints_count']} endpoints defined[/]"
                )

    if results["graphql_endpoints"]:
        console.print(
            f"\n[cyan]GraphQL Endpoints: {len(results['graphql_endpoints'])}[/]"
        )
        for gql in results["graphql_endpoints"]:
            introspection = (
                "[red]⚠ INTROSPECTION ENABLED[/]"
                if gql.get("introspection_enabled")
                else ""
            )
            console.print(f"  → {gql['url']} {introspection}")
            if gql.get("introspection_enabled"):
                console.print(
                    f"    [dim]Types: {gql.get('types_count', 0)}, "
                    f"Queries: {len(gql.get('queries', []))}, "
                    f"Mutations: {len(gql.get('mutations', []))}[/]"
                )

    if results["api_docs"]:
        console.print(f"\n[yellow]API Documentation: {len(results['api_docs'])}[/]")
        for doc in results["api_docs"]:
            console.print(f"  → {doc['url']}")

    total = (
        len(results["swagger_specs"])
        + len(results["openapi_specs"])
        + len(results["graphql_endpoints"])
        + len(results["api_docs"])
    )
    if total == 0:
        console.print("\n[dim]No API specifications found[/]")
    else:
        console.print(
            f"\n[bold]Total: {total} API endpoints/specs found ({new_count} new)[/]"
        )


@cli.command()
@click.argument("domain", required=False)
@click.pass_context
def emails(ctx, domain):
    """Enumerate email addresses for a domain"""
    db = ctx.obj["db"]
    config = ctx.obj["config"]

    # Use configured domains if none specified
    domains = [domain] if domain else config.domains
    if not domains:
        console.print(
            "[red]Error:[/] No domain specified and none configured in config.yaml"
        )
        return

    enumerator = EmailEnumerator(config)

    for target_domain in domains:
        console.print(f"\n[bold blue]Enumerating emails for:[/] {target_domain}")

        # Show which sources will be used
        sources = ["phonebook.cz", "skymem.info", "ct_logs"]
        if config.hunter_api_key:
            sources.insert(0, "hunter.io")
        else:
            console.print(
                "[dim]Tip: Add hunter.api_key to config for better results[/]"
            )

        console.print(f"[dim]Sources: {', '.join(sources)}[/]")

        results = enumerator.enumerate(target_domain)

        # Store in database
        counts = db.add_emails_bulk(target_domain, results)

        # Display results
        if results["emails"]:
            console.print(f"\n[green]Found {len(results['emails'])} email(s):[/]")

            # Group by source
            for source, source_emails in results["by_source"].items():
                console.print(f"\n  [cyan]{source}[/] ({len(source_emails)}):")
                for email in sorted(source_emails)[:15]:
                    console.print(f"    {email}")
                if len(source_emails) > 15:
                    console.print(f"    [dim]... and {len(source_emails) - 15} more[/]")

            # Show detected pattern
            if results["patterns"]:
                console.print(
                    f"\n[yellow]Email pattern detected:[/] {results['patterns'][0]}"
                )

            # Show role accounts
            role_accounts = [
                e
                for e in results["emails"]
                if any(
                    e.split("@")[0].startswith(p)
                    for p in [
                        "admin",
                        "info",
                        "support",
                        "sales",
                        "contact",
                        "help",
                        "hr",
                        "jobs",
                        "security",
                    ]
                )
            ]
            if role_accounts:
                console.print(
                    f"\n[dim]Role accounts: {', '.join(role_accounts[:5])}[/]"
                )

            console.print(
                f"\n[bold]Summary:[/] {len(results['emails'])} "
                f"emails found, {counts['new']} new"
            )
        else:
            console.print(f"\n[dim]No emails found for {target_domain}[/]")


@cli.command()
@click.argument("domain")
@click.option(
    "--notify/--no-notify", default=False, help="Send notifications for changes"
)
@click.option(
    "--parallel/--sequential",
    default=True,
    help="Run independent modules in parallel (default: parallel)"
)
@click.option(
    "--workers", "-w", default=5, help="Max parallel workers per group (default 5)"
)
@click.pass_context
def scan(ctx, domain, notify, parallel, workers):
    """Run a full scan (discover + portscan + certs + fingerprint +
    urls + takeover + apis + emails + vulnscan)

    Execution groups (with --parallel):
      1. discover (sequential - must find targets first)
      2. portscan, certificates, fingerprint, takeover, dns (parallel)
      3. urls, emails, apis (parallel)
      4. vulnscan (sequential - runs last)
    """
    from .core.parallel_runner import ParallelRunner
    import time

    mode = "parallel" if parallel else "sequential"
    console.print(f"\n[bold magenta]═══ Full Attack Surface Scan: {domain} ═══[/]")
    console.print(f"[dim]Mode: {mode}" + (f" ({workers} workers)" if parallel else "") + "[/]\n")

    start_time = time.time()

    if parallel:
        # Use parallel runner for improved performance
        runner = ParallelRunner(ctx, console, max_workers=workers)

        # Register module functions that wrap ctx.invoke
        def make_invoker(cmd, **kwargs):
            def invoker(domain):
                ctx.invoke(cmd, domain=domain, **kwargs)
            return invoker

        # Register all modules
        runner.register_module("discover", lambda d: ctx.invoke(discover, domains=(d,)))
        runner.register_module("portscan", make_invoker(portscan))
        runner.register_module("certificates", make_invoker(certificates))
        runner.register_module("fingerprint", make_invoker(fingerprint))
        runner.register_module("takeover", make_invoker(takeover))
        runner.register_module("dns", make_invoker(dns))
        runner.register_module("urls", make_invoker(urls))
        runner.register_module("emails", make_invoker(emails))
        runner.register_module("apis", make_invoker(apis))
        runner.register_module("vulnscan", make_invoker(vulnscan))

        # Run with parallel execution
        runner.run(domain, parallel=True)

        # Show summary
        summary = runner.get_summary()
        elapsed = time.time() - start_time
        console.print(f"\n[dim]Completed {summary['successful']}/{summary['total_modules']} "
                      f"modules in {elapsed:.1f}s[/]")
    else:
        # Sequential execution (original behavior)
        ctx.invoke(discover, domains=(domain,))
        ctx.invoke(portscan, domain=domain)
        ctx.invoke(certificates, domain=domain)
        ctx.invoke(fingerprint, domain=domain)
        ctx.invoke(dns, domain=domain)
        ctx.invoke(urls, domain=domain)
        ctx.invoke(takeover, domain=domain)
        ctx.invoke(apis, domain=domain)
        ctx.invoke(emails, domain=domain)
        ctx.invoke(vulnscan, domain=domain)

        elapsed = time.time() - start_time
        console.print(f"\n[dim]Completed in {elapsed:.1f}s[/]")

    if notify:
        notifier = Notifier(ctx.obj["config"])
        report = ctx.obj["db"].get_scan_summary(domain)
        notifier.send_summary(domain, report)

    console.print("\n[bold magenta]═══ Scan Complete ═══[/]")


@cli.command()
@click.argument("domain", required=False)
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json", "markdown", "html"]),
    default="table",
)
@click.option("--output", "-o", help="Output file path")
@click.pass_context
def report(ctx, domain, fmt, output):
    """Generate a report of discovered assets"""
    db = ctx.obj["db"]
    reporter = Reporter(db)

    if domain:
        data = db.get_domain_summary(domain)
    else:
        data = db.get_full_summary()

    report_content = reporter.generate(data, format=fmt)

    if output:
        Path(output).write_text(report_content)
        console.print(f"[green]Report saved to:[/] {output}")
    else:
        console.print(report_content)


@cli.command()
@click.pass_context
def status(ctx):
    """Show current database status and statistics"""
    db = ctx.obj["db"]

    stats = db.get_statistics()

    table = Table(title="ASM Database Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Domains tracked", str(stats["domains"]))
    table.add_row("Subdomains discovered", str(stats["subdomains"]))
    table.add_row("Open ports found", str(stats["ports"]))
    table.add_row("Certificates tracked", str(stats["certificates"]))
    table.add_row("URLs discovered", str(stats.get("urls", 0)))
    table.add_row("Interesting URLs", str(stats.get("interesting_urls", 0)))
    table.add_row("API endpoints/specs", str(stats.get("apis", 0)))
    table.add_row("Emails discovered", str(stats.get("emails", 0)))
    table.add_row("Takeover vulnerabilities", str(stats.get("takeovers", 0)))
    table.add_row("Vulnerability findings", str(stats["findings"]))
    table.add_row("Last scan", stats.get("last_scan", "Never"))

    console.print(table)


@cli.command()
@click.option(
    "--cron", "-c", default="0 6 * * *", help="Cron expression for scheduling"
)
@click.argument("domains", nargs=-1, required=True)
@click.pass_context
def schedule(ctx, cron, domains):
    """Schedule recurring scans"""
    scheduler = Scheduler(ctx.obj["config"], ctx.obj["data_dir"])
    scheduler.add_job(domains, cron)
    console.print(f"[green]Scheduled scan for {', '.join(domains)} at: {cron}[/]")


@cli.command()
@click.argument("domain")
@click.option("--days", "-d", default=30, help="Number of days to analyze trends for")
@click.option(
    "--type",
    "-t",
    "asset_type",
    type=click.Choice(
        ["subdomains", "ports", "certificates", "vulnerabilities", "all"]
    ),
    default="all",
    help="Asset type to analyze",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    type=click.Choice(["table", "json", "ascii"]),
    default="table",
    help="Output format",
)
@click.option(
    "--alert-threshold",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Minimum severity level for alerts",
)
@click.pass_context
def trends(ctx, domain, days, asset_type, fmt, alert_threshold):
    """Show historical trend analysis and change tracking for a domain"""
    db = ctx.obj["db"]

    console.print(
        f"\n[bold blue]Analyzing trends for:[/] {domain} (last {days} days)\n"
    )

    # Get trend summary from database
    trend_data = db.get_trend_summary(domain, days)

    if not trend_data.get("has_history", False):
        # No historical data - show helpful message
        console.print(f"[yellow]No historical scan data available for {domain}.[/]\n")
        console.print("[bold]Trends will be available after multiple scans.[/]\n")
        console.print(
            "[dim]Run the following to start collecting data:[/]\n"
            f"  [cyan]python -m asm scan {domain}[/]"
        )
        return

    if fmt == "json":
        console.print_json(data=trend_data)
        return

    # Filter by asset type if specified
    if asset_type != "all":
        trend_data = {asset_type: trend_data.get(asset_type, {})}

    # Display trends in table format
    _display_trends_table(trend_data, alert_threshold)


def _display_trends_table(trend_data: Dict, alert_threshold: str = "") -> None:
    """Display trend data in formatted tables"""
    from rich.panel import Panel

    asset_types = ["subdomains", "ports", "certificates", "vulnerabilities"]

    for asset_type in asset_types:
        if asset_type not in trend_data:
            continue

        data = trend_data[asset_type]

        if asset_type == "vulnerabilities":
            vuln_data = data.get("delta", {})
            table = Table(title="Vulnerability Trends")
            table.add_column("Severity", style="white")
            table.add_column("Current", style="green")
            table.add_column("Previous", style="dim")
            table.add_column("Change", style="yellow")

            for severity in ["critical", "high", "medium", "low"]:
                delta = vuln_data.get(severity, 0)
                if severity == "total":
                    continue
                if alert_threshold and severity != alert_threshold:
                    continue

                current = data.get("current", {}).get(severity, 0)
                previous = data.get("previous", {}).get(severity, 0)

                change_color = "red" if delta > 0 else "green"
                change_str = f"+{delta}" if delta >= 0 else str(delta)

                table.add_row(
                    severity.upper(),
                    str(current),
                    str(previous),
                    f"[{change_color}]{change_str}[/]",
                )

            console.print(table)

        else:
            table = Table(title=f"{asset_type.capitalize()} Trends")
            table.add_column("Metric", style="white")
            table.add_column("Change", style="green")

            table.add_row("Current", str(data.get("current", 0)))
            table.add_row("Previous", str(data.get("previous", 0)))

            delta = data.get("delta", 0)
            delta_color = "red" if delta > 0 else "green"
            delta_str = f"+{delta}" if delta >= 0 else str(delta)
            table.add_row("Change", f"[{delta_color}]{delta_str}[/]")

            console.print(table)

            if data.get("new"):
                new_items = data["new"][:10]
                new_str = "\n  ".join(f"[green]+ {item}[/]" for item in new_items)
                if len(data["new"]) > 10:
                    new_str += f"\n  [dim]... and {len(data['new']) - 10} more[/]"
                console.print(Panel(new_str, title="[green]New Items[/]"))

            if data.get("removed"):
                removed_items = data["removed"][:10]
                removed_str = "\n  ".join(f"[red]- {item}[/]" for item in removed_items)
                if len(data["removed"]) > 10:
                    removed_str += (
                        f"\n  [dim]... and {len(data['removed']) - 10} more[/]"
                    )
                console.print(Panel(removed_str, title="[red]Removed Items[/]"))

    if "risk_score" in trend_data:
        risk = trend_data["risk_score"]
        table = Table(title="Risk Score Trend")
        table.add_column("Current", style="white")
        table.add_column("Previous", style="dim")
        table.add_column("Delta", style="yellow")
        table.add_column("Trend", style="white")

        trend_color = {
            "increasing": "red",
            "decreasing": "green",
            "stable": "white",
        }.get(risk.get("trend", "stable"), "white")

        table.add_row(
            str(risk.get("current", 0)),
            str(risk.get("previous", 0)),
            str(risk.get("delta", 0)),
            f"[{trend_color}]{risk.get('trend', 'stable').upper()}[/]",
        )
        console.print(table)

    if "recent_changes" in trend_data and trend_data["recent_changes"]:
        console.print("\n[bold]Recent Changes:[/]")
        for change in trend_data["recent_changes"][:5]:
            sev = change.get("severity", "info").lower()
            sev_color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
            }.get(sev, "white")

            if alert_threshold:
                severity_order = ["critical", "high", "medium", "low"]
                if severity_order.index(sev) > severity_order.index(alert_threshold):
                    continue

            console.print(
                f"[{sev_color}][{sev.upper()}][/] {change.get('description', '')}"
            )


@cli.command()
@click.pass_context
def init(ctx):
    """Initialize configuration file with defaults"""
    config_path = Path("/app/config.yaml")

    if config_path.exists():
        if not click.confirm("Config file exists. Overwrite?"):
            return

    default_config = {
        "domains": ["example.com"],
        "notifications": {
            "slack": {"enabled": False, "webhook_url": ""},
            "email": {
                "enabled": False,
                "smtp_host": "",
                "smtp_port": 587,
                "from_addr": "",
                "to_addr": "",
            },
        },
        "scanning": {
            "ports": "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443",
            "nuclei_severity": "medium,high,critical",
            "passive_only": False,
        },
        "shodan": {"enabled": False, "api_key": ""},
        "schedule": {"full_scan": "0 6 * * *", "cert_check": "0 */6 * * *"},
    }

    config_path.write_text(yaml.dump(default_config, default_flow_style=False))
    console.print(f"[green]Created config file:[/] {config_path}")
    console.print("[dim]Edit this file to configure your domains and notifications[/]")


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
