# ASM Tool

A local-first **web** attack surface management app. It monitors **crewai.com** (and its subdomains) for subdomains, open ports, certificates, technologies, DNS records, URLs, APIs, emails, cloud buckets, and takeover risks.

The product is a TypeScript frontend and TypeScript backend. Open the UI, start a scan from Operations, and browse results in the dashboard.

![Node 22+](https://img.shields.io/badge/node-22+-339933.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## Features

- **Subdomain Enumeration** — Certificate Transparency and public passive sources
- **Port Scanning** — Native TCP connect scans with service names
- **Certificate Monitoring** — Track TLS certificates and expiry
- **URL & API Discovery** — Wayback URLs plus common API/docs paths
- **Technology Fingerprinting** — Headers, titles, and common stacks
- **DNS Monitoring** — A, AAAA, MX, NS, TXT, SOA, CAA
- **Subdomain Takeover Detection** — CNAME fingerprint checks
- **Email & Cloud Enumeration** — Emails from HTTP bodies and S3 name probes
- **Header findings** — Missing HSTS/CSP and similar misconfigurations
- **Dashboard** — TypeScript React UI served by the TypeScript backend

## Scan scope

Scans are hardcoded to **crewai.com** and its subdomains (`app.crewai.com`, and so on). Other domains are rejected by the API and job runner.

## Quick Start

```bash
git clone https://github.com/theCyberTech/asm-tool.git
cd asm-tool
npm install
npm start
```

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080), go to **Operations**, and start a full scan of `crewai.com`.

### Development

```bash
npm install
npm test
npm run dev
```

- API: [http://127.0.0.1:8080](http://127.0.0.1:8080)
- Vite UI (proxies `/api` to the backend): [http://127.0.0.1:5173](http://127.0.0.1:5173)

### Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `ASM_HOST` | `127.0.0.1` | Bind address |
| `ASM_PORT` | `8080` | Backend port |
| `ASM_DATABASE_PATH` | `data/asm.db` | SQLite file |
| `ASM_DASHBOARD_TOKEN` | empty | If set, required as `X-ASM-Token` to start scans |
| `ASM_PORTS` | common TCP ports | Port scan list |

## Architecture

```
web/      TypeScript + React dashboard (Vite)
server/   TypeScript HTTP API, SQLite, and scanners (Hono)
data/     SQLite database
```

The backend owns scanning. The UI talks to `/api/overview`, `/api/domains`, `/api/assets/*`, and `/api/runs/start`. There is no CLI in the primary workflow.

## Legacy Go CLI

`asm-go/` is the previous Go CLI and is no longer the supported way to run this tool.
