# AI Coding Security Guard — Next Steps

Trạng thái hiện tại: Phase 1–5 đã implement xong phần core.
Dưới đây là danh sách việc cần làm tiếp, sắp xếp theo độ ưu tiên.

---

## 🟢 Ưu tiên cao (nên làm trước)

### 1. README.md tổng thể
- Viết hướng dẫn setup toàn bộ project (CLI + VSCode + Enterprise)
- Bao gồm: prerequisites, quick start, docker-compose, CLI usage, env vars
- Thêm architecture diagram
- Thêm demo screenshots

### 2. Slack Integration (Webhook → Slack)
- Khi có blocked event, gửi notification vào Slack channel
- Implement trong backend: handler `/api/integrations/slack`
- Dùng Slack Incoming Webhooks API
- Thêm UI config trong Settings page
- Độ phức tạp: thấp, giá trị cao

### 3. Pre-commit hook CI/CD
- Thêm GitHub Actions workflow để auto-run `claude-safe scan --staged` trong CI
- File: `.github/workflows/security.yml`
- Tích hợp với `claude-safe scan --git-diff` cho PR checks

---

## 🟡 Ưu tiên trung bình

### 4. Multi-Tenancy (Organizations)
Cần thiết để trở thành SaaS thực sự.

**Backend:**
- Thêm bảng `organizations` vào migration
- Thêm `org_id` vào `users`, `scan_events`, `policies`, `api_keys`, `webhooks`
- Tất cả query phải filter theo `org_id`
- Thêm endpoint `/api/organizations` (create, invite member)
- JWT claims thêm `org_id`

**Frontend:**
- Thêm trang Organization Settings
- Thêm flow invite member qua email
- Thêm org switcher trong Sidebar

### 5. Real-time Dashboard (SSE)
- Thay polling bằng Server-Sent Events cho dashboard
- Backend: thêm `/api/events/stream` endpoint
- Frontend: dùng `EventSource` API để nhận live updates
- Hiển thị blocked events realtime không cần refresh

### 6. Compliance Export
- Export audit logs ra CSV/PDF
- Thêm nút "Export" trên trang Audit Logs
- Lọc theo date range, developer, risk level
- Format phù hợp SOC2/ISO27001 reporting

### 7. GitHub/GitLab Integration
- Kết nối với GitHub App hoặc GitLab OAuth
- Auto-scan pull requests khi mở
- Post security report comment lên PR
- Block merge nếu có CRITICAL findings

---

## 🔴 Ưu tiên thấp / Long-term

### 8. Billing & Subscriptions
- Tích hợp Stripe
- Plans: Free (1 developer) / Team (10 devs) / Enterprise (unlimited)
- Usage-based billing theo số scan events
- Bảng `subscriptions`, `usage_records` trong DB

### 9. Kubernetes Deployment
- Viết Helm chart cho toàn bộ stack
- Horizontal Pod Autoscaler cho backend
- PostgreSQL với persistent volumes
- Ingress controller với TLS
- File: `k8s/` hoặc `helm/`

### 10. Redis Caching
- Thay in-memory rate limiter bằng Redis (để scale multi-instance)
- Cache `/api/stats` response (TTL 30s)
- Session store cho JWT blacklist (logout support)
- Thêm `redis` service vào docker-compose

### 11. MFA (Multi-Factor Authentication)
- TOTP (Google Authenticator compatible)
- Thêm bảng `mfa_secrets` trong DB
- Endpoint: `POST /api/auth/mfa/setup`, `POST /api/auth/mfa/verify`
- Frontend: QR code setup flow

### 12. VSCode Extension — Marketplace Publish
- Thêm icon, screenshots, changelog
- Setup `vsce` publish pipeline
- Publish lên Visual Studio Marketplace
- Thêm telemetry opt-in

### 13. Jira Integration
- Tự động tạo Jira ticket khi phát hiện CRITICAL finding
- Config URL, project key, API token trong Settings
- Webhook → Jira REST API

### 14. SIEM Integration
- Forward audit events ra Splunk / Elastic / Datadog
- Format: CEF (Common Event Format) hoặc JSON
- Endpoint `/api/integrations/siem`

---

## 📋 Technical Debt cần fix

| Issue | File | Mô tả |
|---|---|---|
| No integration tests | `enterprise/backend/` | Chỉ có unit tests trong CLI, backend không có tests |
| Audit log pagination frontend | `audit-logs/page.tsx` | Chưa hiển thị empty state khi không có events |
| VSCode extension not published | `vscode-claude-safe/` | Chỉ chạy local, chưa có `.vsix` release |
| CORS origin hardcoded | `docker-compose.yml` | `http://localhost:3000` — cần dynamic cho production |
| No request timeout | `enterprise/backend/` | HTTP server thiếu `ReadTimeout`, `WriteTimeout` |
| Password reset flow | `enterprise/backend/` | Chưa có "Forgot password" |

---

## 🏗️ Architecture hiện tại

```
ai-coding-security/
├── claude-safe/          # Phase 1+2: Go CLI (complete)
│   ├── cmd/              # Cobra commands: hook, scan, analyze, run, init
│   ├── internal/
│   │   ├── analyzer/     # Code vulnerability scanner (SQL, XSS, SSRF...)
│   │   ├── secrets/      # Secret detection engine
│   │   ├── command/      # Dangerous command validator
│   │   ├── risk/         # Risk scoring engine
│   │   ├── policy/       # YAML policy engine
│   │   ├── audit/        # Local audit logger
│   │   ├── git/          # Git diff scanner
│   │   └── reporter/     # Enterprise dashboard reporter (Phase 5)
│   └── policy.example.yaml
│
├── vscode-claude-safe/   # Phase 3: VSCode Extension (complete)
│   └── src/
│       ├── extension.ts  # Activation, debounce, command registration
│       ├── analyzer.ts   # CLI bridge
│       ├── diagnostics.ts
│       ├── sidebar.ts    # TreeDataProvider
│       └── statusBar.ts
│
└── enterprise/           # Phase 4+5: Enterprise Platform (complete)
    ├── backend/          # Go REST API
    │   ├── internal/
    │   │   ├── handlers/ # auth, stats, incidents, audit, policies,
    │   │   │             # developers, apikeys, webhooks
    │   │   ├── middleware/ # JWT + API key auth, RBAC
    │   │   ├── ratelimit/  # In-memory token bucket
    │   │   └── models/
    │   └── migrations/
    │       ├── 001_init.sql   # core schema + seed data
    │       └── 002_saas.sql   # api_keys + webhooks (Phase 5)
    ├── frontend/         # Next.js 14 App Router
    │   └── app/(dashboard)/
    │       ├── dashboard/    incidents/ audit-logs/ policies/
    │       ├── developers/   settings/ api-keys/ webhooks/
    │       └── layout.tsx    # auth guard
    └── docker-compose.yml    # postgres → backend → frontend
```

---

## 🚀 Quick Start (hiện tại)

```bash
# Enterprise platform
cd enterprise
docker-compose up

# CLI (local)
cd claude-safe
go build -o claude-safe .
./claude-safe init          # setup hooks + policy
./claude-safe scan --staged # scan trước khi commit

# VSCode Extension
cd vscode-claude-safe
npm install && npm run compile
# F5 trong VSCode để chạy Extension Development Host

# CLI → Dashboard integration
export CLAUDE_SAFE_ENTERPRISE_URL=http://localhost:8080
export CLAUDE_SAFE_API_KEY=cs_<key-từ-dashboard>
```

---

*Last updated: 2026-05-18*
