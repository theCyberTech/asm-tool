# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ASM Tool is a TypeScript web app for attack surface management. It monitors crewai.com and its subdomains, stores results in SQLite, and serves a React dashboard from a Hono backend.

## Common Commands

```bash
npm install
npm test
npm run dev
npm start
```

## Architecture

```
web/       TypeScript + React dashboard (Vite)
server/
  src/index.ts           HTTP entry
  src/app.ts             Hono routes (`/api/*`, SPA fallback)
  src/db/store.ts        SQLite persistence
  src/scanners/          Discovery modules
  src/jobs/runner.ts     In-process scan jobs
  src/target.ts          Domain normalization and crewai.com allowlist
data/      SQLite database
asm-go/    Legacy Go CLI
```

## Key Patterns

- **Web API**: `server/src/app.ts` serves the same JSON shapes the React client in `web/src/api` expects.
- **Store**: `server/src/db/store.ts` is the persistence boundary for scan results.
- **Scanners**: Each module in `server/src/scanners` is invoked by `runModule` / the job runner.
- **Scan scope**: `normalizeScanTarget` allows only `crewai.com` and subdomains.

## External Dependencies

Nuclei is optional. The web app records header-based findings without it.
