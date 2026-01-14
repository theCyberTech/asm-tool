# Product Requirements Document: ASM Interactive Dashboard

## Overview
A web-based interactive dashboard for viewing and exploring attack surface management scan results. The dashboard provides a local-only interface for security practitioners to browse historical scan data, filter across domains, and drill down into detailed findings with a security-focused dark aesthetic.

## Problem Statement
Currently, ASM scan results are accessed via CLI commands and generated reports. Users need a more intuitive way to:
- Browse scan history across multiple domains
- Quickly filter and search findings
- Drill down into specific results without re-running commands
- Get an at-a-glance overview of their attack surface

## Goals
1. Provide a clickable, mouse-driven interface for exploring scan data
2. Enable filtering and searching across all historical scan results
3. Display aggregate statistics alongside domain-specific details
4. Start simple with tables, but design for future chart/visualization additions

## Non-Goals
- Multi-user authentication (local-only, single user)
- Remote access configuration
- Triggering scans from the dashboard
- Exporting data (handled via existing CLI)

## Technical Approach

### Stack
- **Backend**: Go HTTP server (net/http or chi router)
- **Frontend**: htmx + HTML templates
- **Styling**: Tailwind CSS or custom CSS with dark security aesthetic
- **Data**: Read from existing SQLite database

### Architecture
```
asm-go/
├── internal/
│   └── dashboard/
│       ├── server.go          # HTTP server setup
│       ├── handlers.go        # Route handlers
│       ├── templates/         # HTML templates
│       │   ├── layout.html
│       │   ├── index.html     # Landing page
│       │   ├── domain.html    # Domain detail view
│       │   ├── partials/      # htmx partial templates
│       │   └── components/    # Reusable UI components
│       └── static/            # CSS, JS assets
├── cmd/asm/main.go            # Add 'dashboard' command
```

### CLI Integration
```bash
# Start dashboard server
./asm.sh dashboard

# With custom port
./asm.sh dashboard --port 8080
```

## User Interface

### Landing Page
- **Header**: ASM Tool branding with dark theme
- **Stats Bar**: Aggregate counts (total domains, subdomains, open ports, vulnerabilities)
- **Domain List**: Table/cards showing:
  - Domain name
  - Last scan date
  - Scan count
  - Quick stats (subdomain count, open ports, critical vulns)
  - Click to view details

### Search & Filter Bar
- Text search across domains
- Date range picker
- Scan type filter (full scan, subdomain only, etc.)
- Severity filter for vulnerabilities

### Domain Detail View
- **Breadcrumb**: Home → domain.com
- **Scan Selector**: Dropdown of scan dates for this domain
- **Card Layout** (one card per module):
  - Subdomains (count, click to expand)
  - Open Ports (count by service type)
  - Certificates (expiring soon highlighted)
  - DNS Records
  - Technologies Detected
  - Vulnerabilities (grouped by severity)
  - URLs Discovered
  - API Endpoints
  - Email Addresses
  - Cloud Storage Buckets
  - Subdomain Takeover Risks

### Drill-Down Modals
- Clicking a card opens a modal with full results
- Sortable/filterable tables within modals
- Severity color coding (critical=red, high=orange, medium=yellow, low=blue)

## Visual Design

### Color Palette (Security Dark Theme)
- **Background**: #0d1117 (near black)
- **Surface**: #161b22 (card backgrounds)
- **Border**: #30363d
- **Text Primary**: #e6edf3
- **Text Secondary**: #8b949e
- **Accent Colors**:
  - Critical: #f85149 (red)
  - High: #db6d28 (orange)
  - Medium: #d29922 (yellow)
  - Low: #58a6ff (blue)
  - Info: #8b949e (gray)

### Typography
- Sans-serif for UI (Inter, system-ui)
- Monospace for technical data (IPs, ports, hashes)

## Data Model (Read-Only)

The dashboard reads from existing SQLite tables:
- `domains` - tracked domains
- `subdomains` - enumerated subdomains
- `ports` - open port findings
- `certificates` - TLS cert data
- `dns_records` - DNS findings
- `technologies` - detected tech stack
- `vulnerabilities` - nuclei findings
- `urls` - discovered URLs
- `api_endpoints` - API findings
- `emails` - enumerated emails
- `cloud_storage` - bucket findings
- `takeover_risks` - subdomain takeover candidates
- `scans` - scan metadata (if exists, else derive from timestamps)

## User Stories

### US-001: View All Domains
**As a** security practitioner  
**I want to** see all monitored domains on a single page  
**So that** I can quickly assess my attack surface scope

**Acceptance Criteria**:
- Landing page shows all domains from database
- Each domain displays last scan date and quick stats
- Domains are clickable to view details

### US-002: Search and Filter
**As a** security practitioner  
**I want to** search and filter across all scan data  
**So that** I can quickly find specific findings

**Acceptance Criteria**:
- Search bar filters domains by name
- Date range filter limits results to time period
- Filters apply immediately (htmx partial updates)

### US-003: View Domain Details
**As a** security practitioner  
**I want to** click into a domain and see all findings  
**So that** I can understand the full attack surface for that domain

**Acceptance Criteria**:
- Domain page shows cards for each scan module
- Cards display count and summary
- Historical scan selector allows viewing past results

### US-004: Drill Into Findings
**As a** security practitioner  
**I want to** click a card to see detailed findings  
**So that** I can investigate specific issues

**Acceptance Criteria**:
- Clicking card opens modal with full data table
- Tables are sortable and filterable
- Severity levels are color-coded

### US-005: View Aggregate Statistics
**As a** security practitioner  
**I want to** see aggregate stats across all domains  
**So that** I can understand overall security posture

**Acceptance Criteria**:
- Stats bar shows total counts
- Vulnerability breakdown by severity
- Stats update when filters applied

## Implementation Phases

### Phase 1: Core Infrastructure
- Dashboard HTTP server setup
- Base HTML templates with dark theme
- Landing page with domain list
- Basic routing structure

### Phase 2: Domain Details
- Domain detail page with cards
- Scan history selector
- Card click opens modal stub

### Phase 3: Data Display
- Populate all card types with real data
- Modal tables for each finding type
- Severity color coding

### Phase 4: Search & Filter
- Search bar implementation
- Date range filtering
- Filter persistence in URL params

### Phase 5: Polish
- Loading states
- Empty states
- Error handling
- Responsive layout adjustments

## Success Metrics
- Dashboard loads in <500ms for typical dataset
- All scan data accessible within 3 clicks
- Zero runtime dependencies beyond Go binary

## Open Questions
1. Should scan history be stored explicitly or derived from finding timestamps?
2. Pagination strategy for large result sets (infinite scroll vs. pages)?
3. Should the dashboard auto-refresh or require manual reload?

## Dependencies
- Existing SQLite database schema
- Go 1.21+ for embed directive (static assets)