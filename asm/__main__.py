"""
ASM Tool - Main CLI Entry Point
"""

import click
import yaml
import sys
import atexit
from pathlib import Path
from datetime import datetime
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
from .core.scheduler import Scheduler

console = Console()


@click.group()
@click.option('--config', '-c', default='/app/config.yaml', help='Path to config file')
@click.option('--data-dir', '-d', default='/app/data', help='Data directory for persistence')
@click.pass_context
def cli(ctx, config, data_dir):
    """Attack Surface Management Tool
    
    Monitor and track your external attack surface including subdomains,
    open ports, certificates, technologies, and vulnerabilities.
    """
    ctx.ensure_object(dict)
    
    config_path = Path(config)
    if config_path.exists():
        ctx.obj['config'] = Config.from_file(config_path)
    else:
        ctx.obj['config'] = Config()
    
    ctx.obj['data_dir'] = Path(data_dir)
    ctx.obj['data_dir'].mkdir(parents=True, exist_ok=True)
    ctx.obj['db'] = Database(ctx.obj['data_dir'] / 'asm.db')

    # Ensure database is closed on exit to flush CachingMiddleware
    atexit.register(ctx.obj['db'].close)


@cli.command()
@click.argument('domains', nargs=-1, required=False)
@click.option('--passive-only', is_flag=True, help='Only use passive reconnaissance')
@click.pass_context
def discover(ctx, domains, passive_only):
    """Discover subdomains for the given domain(s)"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    # Use configured domains if none specified
    domains = domains if domains else config.domains
    if not domains:
        console.print("[red]Error:[/] No domain specified and none configured in config.yaml")
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
        
        console.print(f"\n[bold]Summary:[/] Found {len(results)} subdomains, {new_count} new")


@cli.command()
@click.argument('domain', required=False)
@click.option('--ports', '-p', default='21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443',
              help='Ports to scan (comma-separated)')
@click.option('--all-known', is_flag=True, help='Scan all known subdomains')
@click.pass_context
def portscan(ctx, domain, ports, all_known):
    """Scan ports on discovered assets"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    scanner = PortScanner(config)
    port_list = [int(p.strip()) for p in ports.split(',')]

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
        if not targets:
            targets = config.domains

    if not targets:
        console.print("[red]Error:[/] No targets found. Run 'discover' first or specify a domain.")
        return
    
    console.print(f"\n[bold blue]Scanning {len(targets)} targets on {len(port_list)} ports[/]")
    
    for target in targets:
        results = scanner.scan(target, port_list)
        
        if results['open_ports']:
            console.print(f"\n[yellow]{target}[/]")
            for port_info in results['open_ports']:
                port = port_info['port']
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                
                existing = db.get_port(target, port)
                is_new = db.add_port(target, port, service, version)
                
                if is_new:
                    console.print(f"  [green]+ NEW:[/] {port}/tcp - {service} {version}")
                else:
                    console.print(f"  [dim]  Open:[/] {port}/tcp - {service} {version}")


@cli.command()
@click.argument('domain', required=False)
@click.option('--all-known', is_flag=True, help='Check all known subdomains')
@click.option('--days-warning', default=30, help='Warn if cert expires within N days')
@click.pass_context
def certificates(ctx, domain, all_known, days_warning):
    """Monitor SSL/TLS certificates"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    monitor = CertificateMonitor(config)

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
        if not targets:
            targets = config.domains

    if not targets:
        console.print("[red]Error:[/] No targets found. Run 'discover' first or specify a domain.")
        return
    
    console.print(f"\n[bold blue]Checking certificates for {len(targets)} targets[/]")
    
    expiring_soon = []
    
    for target in targets:
        try:
            cert_info = monitor.check_certificate(target)
            if cert_info:
                days_left = cert_info['days_until_expiry']
                issuer = cert_info['issuer']
                
                db.add_certificate(target, cert_info)
                
                if days_left < 0:
                    console.print(f"  [red]✗ EXPIRED:[/] {target} (expired {abs(days_left)} days ago)")
                elif days_left <= days_warning:
                    console.print(f"  [yellow]⚠ WARNING:[/] {target} expires in {days_left} days")
                    expiring_soon.append((target, days_left))
                else:
                    console.print(f"  [green]✓[/] {target} - valid for {days_left} days ({issuer})")
        except Exception as e:
            console.print(f"  [dim]- {target}: No cert or error ({str(e)[:50]})[/]")
    
    if expiring_soon:
        console.print(f"\n[bold yellow]⚠ {len(expiring_soon)} certificates expiring within {days_warning} days[/]")


@cli.command()
@click.argument('domain', required=False)
@click.option('--all-known', is_flag=True, help='Fingerprint all known subdomains')
@click.pass_context
def fingerprint(ctx, domain, all_known):
    """Identify technologies on discovered assets"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    fingerprinter = TechnologyFingerprinter(config)

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
        if not targets:
            targets = config.domains

    if not targets:
        console.print("[red]Error:[/] No targets found. Run 'discover' first or specify a domain.")
        return
    
    console.print(f"\n[bold blue]Fingerprinting {len(targets)} targets[/]")
    
    for target in targets:
        tech_info = fingerprinter.fingerprint(target)
        if tech_info:
            db.add_technologies(target, tech_info)
            
            techs = ', '.join(tech_info.get('technologies', []))[:80]
            status = tech_info.get('status_code', '?')
            title = tech_info.get('title', '')[:40]
            
            console.print(f"  [{status}] {target}")
            if title:
                console.print(f"      Title: {title}")
            if techs:
                console.print(f"      Tech: {techs}")


@cli.command()
@click.argument('domain')
@click.pass_context
def dns(ctx, domain):
    """Monitor DNS records for changes"""
    db = ctx.obj['db']
    config = ctx.obj['config']
    
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
            if changes.get('new', {}).get(record_type):
                if value in changes['new'][record_type]:
                    status = "[green]+ NEW[/]"
            if changes.get('removed', {}).get(record_type):
                if value in changes['removed'][record_type]:
                    status = "[red]- REMOVED[/]"
            table.add_row(record_type, str(value)[:60], status)
    
    console.print(table)
    db.save_dns_records(domain, records)


@cli.command()
@click.argument('domain', required=False)
@click.option('--all-known', is_flag=True, help='Scan all known subdomains')
@click.option('--severity', '-s', default='medium,high,critical', help='Minimum severity')
@click.option('--templates', '-t', default='', help='Specific template tags to use')
@click.pass_context
def vulnscan(ctx, domain, all_known, severity, templates):
    """Run vulnerability scan using Nuclei"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    scanner = NucleiScanner(config)

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
        if not targets:
            targets = config.domains

    if not targets:
        console.print("[red]Error:[/] No targets found. Run 'discover' first or specify a domain.")
        return
    
    console.print(f"\n[bold blue]Running vulnerability scan on {len(targets)} targets[/]")
    console.print(f"[dim]Severity filter: {severity}[/]")
    
    findings = scanner.scan(targets, severity=severity, tags=templates)
    
    for finding in findings:
        sev = finding['severity'].upper()
        color = {'CRITICAL': 'red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue'}.get(sev, 'white')
        
        db.add_finding(finding)
        
        console.print(f"\n[{color}][{sev}][/] {finding['name']}")
        console.print(f"  Host: {finding['host']}")
        console.print(f"  Template: {finding['template_id']}")
        if finding.get('matched_at'):
            console.print(f"  Matched: {finding['matched_at']}")
    
    console.print(f"\n[bold]Total findings:[/] {len(findings)}")


@cli.command()
@click.argument('domain', required=False)
@click.option('--include-subs/--no-subs', default=True, help='Include subdomains')
@click.option('--interesting-only', is_flag=True, help='Only show interesting URLs')
@click.option('--js-only', is_flag=True, help='Only show JavaScript files')
@click.option('--show-params', is_flag=True, help='Show discovered parameters')
@click.pass_context
def urls(ctx, domain, include_subs, interesting_only, js_only, show_params):
    """Enumerate historical URLs using GAU (Wayback, CommonCrawl, etc.)"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    # Use configured domains if none specified
    domains = [domain] if domain else config.domains
    if not domains:
        console.print("[red]Error:[/] No domain specified and none configured in config.yaml")
        return

    enumerator = URLEnumerator(config)

    for domain in domains:
        console.print(f"\n[bold blue]Enumerating URLs for:[/] {domain}")
        console.print("[dim]Sources: Wayback Machine, Common Crawl, OTX, URLScan[/]")

        results = enumerator.enumerate(domain, include_subdomains=include_subs)

        # Store in database
        counts = db.add_urls_bulk(domain, results)

        # Display summary
        console.print(f"\n[bold]Summary:[/]")
        console.print(f"  Total URLs: {results['total']}")
        console.print(f"  Unique paths: {len(results['unique_paths'])}")
        console.print(f"  Unique endpoints: {len(results['endpoints'])}")
        console.print(f"  Interesting URLs: {len(results['interesting'])}")
        console.print(f"  New URLs stored: {counts['new']}")

        # Show by extension breakdown
        if results['by_extension']:
            console.print(f"\n[bold]By file type:[/]")
            for ext_type, urls_list in sorted(results['by_extension'].items()):
                console.print(f"  {ext_type}: {len(urls_list)}")

        # Show interesting URLs
        if results['interesting'] and not js_only:
            console.print(f"\n[bold yellow]Interesting URLs ({len(results['interesting'])}):[/]")
            for url in results['interesting'][:20]:  # Limit display
                console.print(f"  [yellow]→[/] {url[:100]}{'...' if len(url) > 100 else ''}")
            if len(results['interesting']) > 20:
                console.print(f"  [dim]... and {len(results['interesting']) - 20} more[/]")

        # Show JS files if requested
        if js_only and results['by_extension'].get('js'):
            console.print(f"\n[bold cyan]JavaScript files ({len(results['by_extension']['js'])}):[/]")
            for url in results['by_extension']['js'][:30]:
                console.print(f"  [cyan]→[/] {url[:100]}{'...' if len(url) > 100 else ''}")
            if len(results['by_extension']['js']) > 30:
                console.print(f"  [dim]... and {len(results['by_extension']['js']) - 30} more[/]")

        # Show parameters if requested
        if show_params and results['parameters']:
            console.print(f"\n[bold magenta]Discovered parameters ({len(results['parameters'])}):[/]")
            for param in sorted(results['parameters'].keys())[:30]:
                console.print(f"  [magenta]?{param}=[/]")
            if len(results['parameters']) > 30:
                console.print(f"  [dim]... and {len(results['parameters']) - 30} more[/]")


@cli.command()
@click.argument('domain', required=False)
@click.option('--all-known', is_flag=True, help='Check all known subdomains')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed progress')
@click.pass_context
def takeover(ctx, domain, all_known, verbose):
    """Detect subdomain takeover vulnerabilities"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    detector = TakeoverDetector(config)

    # Determine targets
    targets = []
    if all_known:
        targets = db.get_all_subdomains()
    elif domain:
        targets = db.get_subdomains(domain)
        if not targets:
            targets = [domain]
    else:
        # Use configured domains' subdomains
        for d in config.domains:
            targets.extend(db.get_subdomains(d))
        if not targets:
            targets = config.domains

    if not targets:
        console.print("[red]Error:[/] No targets found. Run 'discover' first or specify a domain.")
        return

    console.print(f"\n[bold blue]Checking {len(targets)} subdomains for takeover vulnerabilities[/]")
    console.print(f"[dim]Checking against {len(detector.get_all_fingerprints())} known vulnerable services[/]")

    if verbose:
        vulnerabilities = []
        from .modules.takeover import FINGERPRINTS
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
                    console.print(f"[yellow]CNAME → {cname}[/] [cyan]({matched_service})[/]", end=" ")
                    result = detector.check_domain(target)
                    if result:
                        console.print(f"[red]VULNERABLE![/]")
                        vulnerabilities.append(result)
                    else:
                        console.print(f"[green]✓ claimed[/]")
                else:
                    console.print(f"[yellow]CNAME → {cname}[/] [dim](not a known takeover target)[/]")
            else:
                console.print(f"[dim]no CNAME[/]")
    else:
        vulnerabilities = detector.check_subdomains(targets)

    if vulnerabilities:
        console.print(f"\n[bold red]⚠ Found {len(vulnerabilities)} potential takeover(s)![/]\n")

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
            if vuln.get('documentation'):
                console.print(f"  [blue]Docs:[/] {vuln['documentation']}")

        console.print(f"\n[bold red]⚠ CRITICAL: These subdomains may be vulnerable to takeover![/]")
        console.print("[dim]An attacker could claim these services and serve malicious content.[/]")
    else:
        console.print(f"\n[bold green]✓ No takeover vulnerabilities detected[/]")

    # Show summary
    stats = db.get_statistics()
    if stats.get('takeovers', 0) > 0:
        console.print(f"\n[dim]Total open takeover findings in database: {stats['takeovers']}[/]")


@cli.command()
@click.argument('domain', required=False)
@click.option('--all-known', is_flag=True, help='Check all known subdomains')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed progress')
@click.pass_context
def apis(ctx, domain, all_known, verbose):
    """Discover API endpoints (Swagger, OpenAPI, GraphQL)"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    discovery = APIDiscovery(config)

    # Determine targets
    targets = []
    if all_known:
        targets = db.get_all_subdomains()
    elif domain:
        targets = db.get_subdomains(domain)
        if not targets:
            targets = [domain]
    else:
        # Use configured domains' subdomains
        for d in config.domains:
            targets.extend(db.get_subdomains(d))
        if not targets:
            targets = config.domains

    if not targets:
        console.print("[red]Error:[/] No targets found. Run 'discover' first or specify a domain.")
        return

    console.print(f"\n[bold blue]Discovering APIs on {len(targets)} targets[/]")
    console.print("[dim]Checking for Swagger, OpenAPI specs, and GraphQL endpoints...[/]")

    # Always run in parallel
    results = discovery.discover(targets, workers=20)

    # Show verbose output after completion
    if verbose:
        for spec in results['swagger_specs']:
            console.print(f"  [green]✓ Swagger:[/] {spec['url']}")
            if spec.get('title'):
                console.print(f"    Title: {spec['title']}, Endpoints: {spec.get('endpoints_count', 0)}")

        for spec in results['openapi_specs']:
            console.print(f"  [green]✓ OpenAPI:[/] {spec['url']}")
            if spec.get('title'):
                console.print(f"    Title: {spec['title']}, Endpoints: {spec.get('endpoints_count', 0)}")

        for g in results['graphql_endpoints']:
            introspection = "[red]INTROSPECTION ENABLED[/]" if g.get('introspection_enabled') else "[dim]disabled[/]"
            console.print(f"  [cyan]✓ GraphQL:[/] {g['url']} ({introspection})")

        for d in results['api_docs']:
            console.print(f"  [yellow]✓ Docs:[/] {d['url']}")

    # Store results in database
    new_count = 0
    for spec in results['swagger_specs']:
        if db.add_api(spec):
            new_count += 1
    for spec in results['openapi_specs']:
        if db.add_api(spec):
            new_count += 1
    for endpoint in results['graphql_endpoints']:
        if db.add_api(endpoint):
            new_count += 1
    for doc in results['api_docs']:
        if db.add_api(doc):
            new_count += 1

    # Summary
    console.print(f"\n[bold]{'━' * 50}[/]")
    console.print(f"[bold]API Discovery Summary[/]")
    console.print(f"[bold]{'━' * 50}[/]")

    if results['swagger_specs']:
        console.print(f"\n[green]Swagger/OpenAPI Specs: {len(results['swagger_specs']) + len(results['openapi_specs'])}[/]")
        for spec in results['swagger_specs'] + results['openapi_specs']:
            console.print(f"  → {spec['url']}")
            if spec.get('endpoints_count'):
                console.print(f"    [dim]{spec['endpoints_count']} endpoints defined[/]")

    if results['graphql_endpoints']:
        console.print(f"\n[cyan]GraphQL Endpoints: {len(results['graphql_endpoints'])}[/]")
        for gql in results['graphql_endpoints']:
            introspection = "[red]⚠ INTROSPECTION ENABLED[/]" if gql.get('introspection_enabled') else ""
            console.print(f"  → {gql['url']} {introspection}")
            if gql.get('introspection_enabled'):
                console.print(f"    [dim]Types: {gql.get('types_count', 0)}, Queries: {len(gql.get('queries', []))}, Mutations: {len(gql.get('mutations', []))}[/]")

    if results['api_docs']:
        console.print(f"\n[yellow]API Documentation: {len(results['api_docs'])}[/]")
        for doc in results['api_docs']:
            console.print(f"  → {doc['url']}")

    total = len(results['swagger_specs']) + len(results['openapi_specs']) + len(results['graphql_endpoints']) + len(results['api_docs'])
    if total == 0:
        console.print(f"\n[dim]No API specifications found[/]")
    else:
        console.print(f"\n[bold]Total: {total} API endpoints/specs found ({new_count} new)[/]")


@cli.command()
@click.argument('domain', required=False)
@click.pass_context
def emails(ctx, domain):
    """Enumerate email addresses for a domain"""
    db = ctx.obj['db']
    config = ctx.obj['config']

    # Use configured domains if none specified
    domains = [domain] if domain else config.domains
    if not domains:
        console.print("[red]Error:[/] No domain specified and none configured in config.yaml")
        return

    enumerator = EmailEnumerator(config)

    for target_domain in domains:
        console.print(f"\n[bold blue]Enumerating emails for:[/] {target_domain}")

        # Show which sources will be used
        sources = ['phonebook.cz', 'skymem.info', 'ct_logs']
        if config.hunter_api_key:
            sources.insert(0, 'hunter.io')
        else:
            console.print("[dim]Tip: Add hunter.api_key to config for better results[/]")

        console.print(f"[dim]Sources: {', '.join(sources)}[/]")

        results = enumerator.enumerate(target_domain)

        # Store in database
        counts = db.add_emails_bulk(target_domain, results)

        # Display results
        if results['emails']:
            console.print(f"\n[green]Found {len(results['emails'])} email(s):[/]")

            # Group by source
            for source, source_emails in results['by_source'].items():
                console.print(f"\n  [cyan]{source}[/] ({len(source_emails)}):")
                for email in sorted(source_emails)[:15]:
                    console.print(f"    {email}")
                if len(source_emails) > 15:
                    console.print(f"    [dim]... and {len(source_emails) - 15} more[/]")

            # Show detected pattern
            if results['patterns']:
                console.print(f"\n[yellow]Email pattern detected:[/] {results['patterns'][0]}")

            # Show role accounts
            role_accounts = [e for e in results['emails'] if any(
                e.split('@')[0].startswith(p) for p in
                ['admin', 'info', 'support', 'sales', 'contact', 'help', 'hr', 'jobs', 'security']
            )]
            if role_accounts:
                console.print(f"\n[dim]Role accounts: {', '.join(role_accounts[:5])}[/]")

            console.print(f"\n[bold]Summary:[/] {len(results['emails'])} emails found, {counts['new']} new")
        else:
            console.print(f"\n[dim]No emails found for {target_domain}[/]")


@cli.command()
@click.argument('domain')
@click.option('--notify/--no-notify', default=False, help='Send notifications for changes')
@click.pass_context
def scan(ctx, domain, notify):
    """Run a full scan (discover + portscan + certs + fingerprint + urls + takeover + apis + emails + vulnscan)"""
    console.print(f"\n[bold magenta]═══ Full Attack Surface Scan: {domain} ═══[/]\n")

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

    if notify:
        notifier = Notifier(ctx.obj['config'])
        report = ctx.obj['db'].get_scan_summary(domain)
        notifier.send_summary(domain, report)

    console.print(f"\n[bold magenta]═══ Scan Complete ═══[/]")


@cli.command()
@click.argument('domain', required=False)
@click.option('--format', '-f', 'fmt', type=click.Choice(['table', 'json', 'markdown', 'html']), default='table')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def report(ctx, domain, fmt, output):
    """Generate a report of discovered assets"""
    db = ctx.obj['db']
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
    db = ctx.obj['db']

    stats = db.get_statistics()

    table = Table(title="ASM Database Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Domains tracked", str(stats['domains']))
    table.add_row("Subdomains discovered", str(stats['subdomains']))
    table.add_row("Open ports found", str(stats['ports']))
    table.add_row("Certificates tracked", str(stats['certificates']))
    table.add_row("URLs discovered", str(stats.get('urls', 0)))
    table.add_row("Interesting URLs", str(stats.get('interesting_urls', 0)))
    table.add_row("API endpoints/specs", str(stats.get('apis', 0)))
    table.add_row("Emails discovered", str(stats.get('emails', 0)))
    table.add_row("Takeover vulnerabilities", str(stats.get('takeovers', 0)))
    table.add_row("Vulnerability findings", str(stats['findings']))
    table.add_row("Last scan", stats.get('last_scan', 'Never'))

    console.print(table)


@cli.command()
@click.option('--cron', '-c', default='0 6 * * *', help='Cron expression for scheduling')
@click.argument('domains', nargs=-1, required=True)
@click.pass_context
def schedule(ctx, cron, domains):
    """Schedule recurring scans"""
    scheduler = Scheduler(ctx.obj['config'], ctx.obj['data_dir'])
    scheduler.add_job(domains, cron)
    console.print(f"[green]Scheduled scan for {', '.join(domains)} at: {cron}[/]")


@cli.command()
@click.pass_context
def init(ctx):
    """Initialize configuration file with defaults"""
    config_path = Path('/app/config.yaml')
    
    if config_path.exists():
        if not click.confirm('Config file exists. Overwrite?'):
            return
    
    default_config = {
        'domains': ['example.com'],
        'notifications': {
            'slack': {
                'enabled': False,
                'webhook_url': ''
            },
            'email': {
                'enabled': False,
                'smtp_host': '',
                'smtp_port': 587,
                'from_addr': '',
                'to_addr': ''
            }
        },
        'scanning': {
            'ports': '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443',
            'nuclei_severity': 'medium,high,critical',
            'passive_only': False
        },
        'shodan': {
            'enabled': False,
            'api_key': ''
        },
        'schedule': {
            'full_scan': '0 6 * * *',
            'cert_check': '0 */6 * * *'
        }
    }
    
    config_path.write_text(yaml.dump(default_config, default_flow_style=False))
    console.print(f"[green]Created config file:[/] {config_path}")
    console.print("[dim]Edit this file to configure your domains and notifications[/]")


def main():
    cli(obj={})


if __name__ == '__main__':
    main()
