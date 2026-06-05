# AI Coding Security Guard

A security layer for AI coding workflows. Detects secrets, dangerous shell commands,
and code vulnerabilities (SQL injection, XSS, SSRF, weak crypto, …) **before** they reach
your repo, your runtime, or production.

The project ships three components that work together or independently:

| Component | What it is | Status |
|---|---|---|
| [`claude-safe/`](claude-safe/) | Go CLI: scanner, git-diff checker, hook handler, command gate | ✅ Complete |
| [`vscode-claude-safe/`](vscode-claude-safe/) | VSCode extension — diagnostics + sidebar tree | ✅ Complete |
| [`enterprise/`](enterprise/) | SaaS dashboard (Go API + Postgres + Next.js 14) | ✅ Complete |

---

## Architecture

```
                   ┌─────────────────────────────────────┐
                   │         Developer Machine           │
                   │                                     │
   AI assistant ──►│  ┌──────────────┐   ┌────────────┐  │
   (Claude Code)   │  │ Claude Code  │──►│ claude-safe│  │
                   │  │   hooks      │   │  (Go CLI)  │  │
                   │  └──────────────┘   └─────┬──────┘  │
                   │                           │         │
                   │  ┌──────────────┐         │         │
                   │  │  VSCode ext. │◄────────┤         │
                   │  │ (diagnostics)│         │         │
                   │  └──────────────┘         │         │
                   └───────────────────────────┼─────────┘
                                               │ HTTPS + API key
                                               ▼
                   ┌─────────────────────────────────────┐
                   │       Enterprise Dashboard          │
                   │                                     │
                   │  Next.js 14 ──► Go REST API ──► Postgres
                   │  (frontend)     (backend)           │
                   │                                     │
                   │  Auth · Stats · Incidents · Audit   │
                   │  Policies · Developers · API keys   │
                   │  Webhooks                           │
                   └─────────────────────────────────────┘
```

**Data flow:** the CLI runs locally (offline-capable). When `CLAUDE_SAFE_ENTERPRISE_URL`
and `CLAUDE_SAFE_API_KEY` are set, each scan result is reported asynchronously to the
dashboard — blocked events show up in real time on the Incidents page.

---

## Prerequisites

| Use case | What you need |
|---|---|
| Run the CLI only | Go 1.23+ |
| Run the VSCode extension | Node 20+, the `claude-safe` binary on `PATH` |
| Run the enterprise stack | Docker + Docker Compose (the easiest path) |
| Develop the enterprise stack natively | Go 1.23+, Node 20+, PostgreSQL 16 |

---

## Quick start

### 1. CLI only

```bash
cd claude-safe
go build -o claude-safe .

# Initialize hooks + policy in the current repo
./claude-safe init

# Scan staged changes before a commit
./claude-safe scan --staged

# Scan a directory or file
./claude-safe scan ./src
./claude-safe analyze internal/handler.go

# Gate a shell command (exits non-zero if blocked by policy)
./claude-safe run -- "rm -rf node_modules"
```

`claude-safe init` drops a `.claude-safe/policy.yaml` (see [policy.example.yaml](claude-safe/policy.example.yaml))
and wires the `hook` subcommand into your Claude Code hooks so every tool call gets vetted.

### 2. VSCode extension

```bash
cd vscode-claude-safe
npm install
npm run compile
# Open the folder in VSCode and press F5 to launch an Extension Development Host
```

By default the extension calls `claude-safe` from your `PATH`. Override via
`Settings → Claude Safe → Binary Path`.

### 3. Enterprise dashboard (Docker)

```bash
cd enterprise
docker-compose up
```

That brings up Postgres, the Go API on `:8080`, and the Next.js dashboard on
[http://localhost:3000](http://localhost:3000).

Seeded login credentials (from [001_init.sql](enterprise/backend/migrations/001_init.sql)):

| Email | Role | Password |
|---|---|---|
| `admin@example.com` | admin | `password123` |
| `analyst@example.com` | analyst | `password123` |
| `dev1@example.com` | developer | `password123` |

> Change `JWT_SECRET` and the seeded passwords before any non-local deployment.

### 4. Connect the CLI to the dashboard

Create an API key under **Settings → API Keys** in the dashboard, then:

```bash
export CLAUDE_SAFE_ENTERPRISE_URL=http://localhost:8080
export CLAUDE_SAFE_API_KEY=cs_<key-from-dashboard>

# Any scan now also streams events to the dashboard
claude-safe scan --staged
```

---

## CLI usage

```
claude-safe — AI Coding Security Guard

Commands:
  init        Initialize claude-safe in the current project (policy + hooks)
  scan        Scan code, files, or git diff for security issues
              flags: --file <path>, --staged, --git-diff, --text <str>, --json
  analyze     Analyze a source file for vulnerabilities (SQLi, XSS, SSRF, crypto, …)
              flags: --file <path>, --dir <path>, --lang <name>, --text <str>, --json
  hook        Process a Claude Code hook event from stdin
  run         Validate and execute a shell command after a security check
  uninstall   Remove claude-safe hooks and config from the current project

Global flags:
  -p, --policy <file>   Path to policy file (default: .claude-safe/policy.yaml)
```

The policy file controls what gets blocked vs. warned. Key fields:

```yaml
block_dangerous_commands: true
block_private_keys: true
block_secrets: true
max_risk_level: medium   # safe | low | medium | high | critical
allow_sudo: false
audit_log: true
audit_log_path: .claude-safe/audit.log

allow_list: []   # exact substrings exempted from blocking
deny_list:  []   # additional always-blocked patterns
```

See [`policy.example.yaml`](claude-safe/policy.example.yaml) for the full schema.

---

## Environment variables

### CLI ([`claude-safe/`](claude-safe/))

| Variable | Purpose |
|---|---|
| `CLAUDE_SAFE_ENTERPRISE_URL` | Dashboard base URL. Enables remote reporting when set. |
| `CLAUDE_SAFE_API_KEY` | API key created in the dashboard (`cs_…`). Required with the URL above. |

### Backend ([`enterprise/backend/`](enterprise/backend/))

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgres://claude_safe:secret@localhost:5432/claude_safe?sslmode=disable` | Postgres DSN |
| `JWT_SECRET` | `dev-secret-change-in-production!!` | HS256 signing key — **change in prod** |
| `PORT` | `8080` | HTTP listener |
| `CORS_ORIGIN` | `http://localhost:3000` | Allowed dashboard origin |

### Frontend ([`enterprise/frontend/`](enterprise/frontend/))

| Variable | Default | Purpose |
|---|---|---|
| `BACKEND_URL` | `http://backend:8080` | Internal URL the Next.js server uses to call the API |

---

## Docker Compose layout

[`enterprise/docker-compose.yml`](enterprise/docker-compose.yml) starts three services:

- `postgres` — Postgres 16, auto-runs SQL files from `backend/migrations/` on first boot
- `backend` — Go API (built from `backend/Dockerfile`), waits for Postgres healthcheck
- `frontend` — Next.js 14 server, talks to `backend` over the compose network

```bash
# Run in foreground (logs visible)
docker-compose up

# Run in background
docker-compose up -d

# Reset the database (wipes volume)
docker-compose down -v
```

---

## Dashboard pages

Once logged in at [localhost:3000](http://localhost:3000):

| Page | What it shows |
|---|---|
| **Dashboard** | Aggregate stats — blocked events, risk trends, top developers |
| **Incidents** | Every blocked/warned scan event, filterable by severity and developer |
| **Audit Logs** | Append-only audit trail of admin actions |
| **Policies** | Server-side policies pushed to CLIs |
| **Developers** | Per-developer activity and risk score |
| **Settings → API Keys** | Issue/revoke `cs_…` keys for CLI reporting |
| **Settings → Webhooks** | Outbound webhooks for blocked events (Slack-compatible payloads) |

---

## Screenshots

> Drop PNG/GIF captures into `docs/screenshots/` and reference them here.
> Example layout to fill in:
>
> - `docs/screenshots/dashboard.png` — Overview page
> - `docs/screenshots/incidents.png` — Incidents list with severity filter
> - `docs/screenshots/vscode-diagnostics.png` — In-editor findings
> - `docs/screenshots/cli-scan.png` — `claude-safe scan --staged` output

---

## Project layout

```
ai-coding-security/
├── claude-safe/          # Go CLI
│   ├── cmd/              # Cobra commands: hook, scan, analyze, run, init
│   ├── internal/
│   │   ├── analyzer/     # Code vulnerability scanner (SQLi, XSS, SSRF…)
│   │   ├── secrets/      # Secret detection engine
│   │   ├── command/      # Dangerous command validator
│   │   ├── risk/         # Risk scoring engine
│   │   ├── policy/       # YAML policy engine
│   │   ├── audit/        # Local audit logger
│   │   ├── git/          # Git diff scanner
│   │   └── reporter/     # Enterprise dashboard reporter
│   └── policy.example.yaml
│
├── vscode-claude-safe/   # VSCode extension
│   └── src/
│       ├── extension.ts  # Activation, debounce, command registration
│       ├── analyzer.ts   # CLI bridge
│       ├── diagnostics.ts
│       ├── sidebar.ts    # TreeDataProvider
│       └── statusBar.ts
│
└── enterprise/
    ├── backend/          # Go REST API
    │   ├── internal/
    │   │   ├── handlers/   # auth · stats · incidents · audit · policies
    │   │   │               # developers · apikeys · webhooks
    │   │   ├── middleware/ # JWT + API-key auth, RBAC
    │   │   ├── ratelimit/  # In-memory token bucket
    │   │   └── models/
    │   └── migrations/
    │       ├── 001_init.sql   # core schema + seed data
    │       └── 002_saas.sql   # api_keys + webhooks
    ├── frontend/         # Next.js 14 App Router
    │   └── app/(dashboard)/
    │       ├── dashboard/  incidents/  audit-logs/  policies/
    │       ├── developers/ settings/   api-keys/    webhooks/
    │       └── layout.tsx                 # auth guard
    └── docker-compose.yml
```

---

## Roadmap

See [`NEXT_STEPS.md`](NEXT_STEPS.md) for the prioritized backlog (Slack integration,
multi-tenancy, SSE live updates, GitHub App, MFA, Helm chart, billing, …) and the
list of known technical debt.

Risk-scoring rules and the workflow this project implements are documented in
[`RISK_CRITERIA.md`](RISK_CRITERIA.md) and [`WORKFLOW.md`](WORKFLOW.md).

---

## License

MIT — see individual sub-package manifests for details.
