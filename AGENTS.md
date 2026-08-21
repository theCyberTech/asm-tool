# AGENTS.md

## Project Overview

ASM Tool is a TypeScript web app for attack surface management. It monitors
crewai.com (and its subdomains) for subdomains, open ports, certificates,
technologies, DNS records, URLs, APIs, cloud buckets, and takeover
risks. The React UI talks to a Node/Hono backend that runs scans in-process
and stores results in SQLite.

## Repository Layout

- `web/` - TypeScript + React dashboard (Vite)
- `server/` - TypeScript HTTP API, SQLite store, scanners, and job runner
- `data/` - SQLite database (`data/asm.db`)
- `asm-go/` - Legacy Go CLI (not the primary product)

## Development Commands

```bash
npm install
npm test
npm run dev     # API on :8080, Vite on :5173
npm start       # production: build UI and serve it from the API
```

Run workspace tests directly with `npm test -w asm-server` or `npm test -w asm-dashboard`.

## Coding Guidelines

- Keep scanner modules in `server/src/scanners` and persist through `Store`.
- Scan entry points must use `normalizeScanTarget` so only `crewai.com` and
  its subdomains can be scanned. Do not put that allowlist in `normalizeTarget`.
- The JSON API under `/api` must stay compatible with `web/src/api`.
- Add or update tests for behavior changes.
- Do not commit generated databases, `web/dist`, or secrets.

## External Dependencies

Nuclei is optional and not required for the web app. Header-based findings are
collected during fingerprinting.
