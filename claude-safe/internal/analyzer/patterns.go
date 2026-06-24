package analyzer

import (
	"regexp"
	"strings"
)

// VulnType categorises the class of vulnerability found.
type VulnType string

const (
	VulnSQLInjection        VulnType = "SQL_INJECTION"
	VulnXSS                 VulnType = "XSS"
	VulnCommandInjection    VulnType = "COMMAND_INJECTION"
	VulnSSRF                VulnType = "SSRF"
	VulnPathTraversal       VulnType = "PATH_TRAVERSAL"
	VulnInsecureCrypto      VulnType = "INSECURE_CRYPTO"
	VulnInsecureJWT         VulnType = "INSECURE_JWT"
	VulnUnsafeDeserialize   VulnType = "UNSAFE_DESERIALIZATION"
	VulnEvalInjection       VulnType = "EVAL_INJECTION"
	VulnDebugEnabled        VulnType = "DEBUG_ENABLED"
	VulnInsecureRandom      VulnType = "INSECURE_RANDOM"
	VulnXXE                 VulnType = "XXE"
	VulnOpenRedirect        VulnType = "OPEN_REDIRECT"
)

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
)

// CodeFinding represents one vulnerability found in source code.
type CodeFinding struct {
	VulnType    VulnType
	Severity    Severity
	Line        int
	Code        string // snippet of matching line
	Description string
	Remediation string
	Source      string // "regex" or "semgrep"
	RuleID      string
}

type vulnRule struct {
	id          string
	vulnType    VulnType
	severity    Severity
	pattern     *regexp.Regexp
	languages   []Language // nil = all languages
	description string
	remediation string
}

// allRules contains all regex-based vulnerability detection rules.
// Rules are ordered by severity descending.
var allRules = []vulnRule{

	// ── SQL INJECTION ──────────────────────────────────────────────────────────

	{
		id: "sql-inject-go-fmt",
		vulnType: VulnSQLInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)(db\.|tx\.|rows\.|row\.)?(Query|Exec|QueryRow|QueryContext|ExecContext)\s*\(\s*(fmt\.Sprintf|fmt\.Errorf|\+)`),
		languages: []Language{LangGo},
		description: "SQL query built with fmt.Sprintf or string concatenation — SQL injection risk",
		remediation: "Use parameterised queries: db.Query(\"SELECT ... WHERE id = ?\", id)",
	},
	{
		// Catches: cursor.execute("...%s..." % var) and cursor.execute(f"SELECT...")
		// Does NOT catch: cursor.execute("...%s...", (var,)) [safe parameterised]
		id: "sql-inject-py-format",
		vulnType: VulnSQLInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)cursor\.(execute|executemany)\s*\([^)]*['"]\s*%\s+\w|cursor\.(execute|executemany)\s*\([^)]*\.format\s*\(|cursor\.(execute|executemany)\s*\(\s*f['"](SELECT|INSERT|UPDATE|DELETE)`),
		languages: []Language{LangPython},
		description: "SQL query uses string formatting — SQL injection risk",
		remediation: "Use parameterised queries: cursor.execute('SELECT ... WHERE id = %s', (id,))",
	},
	{
		id: "sql-inject-js-template",
		vulnType: VulnSQLInjection, severity: SevCritical,
		pattern:   regexp.MustCompile("(?i)(query|execute|run)\\s*\\(\\s*`(SELECT|INSERT|UPDATE|DELETE|DROP)[^`]*\\$\\{"),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "SQL query uses template literal interpolation — SQL injection risk",
		remediation: "Use parameterised queries with placeholders ($1, ?, :param)",
	},
	{
		id: "sql-inject-java-concat",
		vulnType: VulnSQLInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)(executeQuery|executeUpdate|execute)\s*\(\s*"(SELECT|INSERT|UPDATE|DELETE).{0,80}"\s*\+`),
		languages: []Language{LangJava},
		description: "SQL query built with string concatenation — SQL injection risk",
		remediation: "Use PreparedStatement with parameterised queries",
	},
	{
		id: "sql-inject-php-concat",
		vulnType: VulnSQLInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)(mysql_query|mysqli_query|pg_query)\s*\(\s*["'](SELECT|INSERT|UPDATE|DELETE).{0,80}\$`),
		languages: []Language{LangPHP},
		description: "SQL query uses variable interpolation — SQL injection risk",
		remediation: "Use PDO with prepared statements",
	},

	// ── XSS ───────────────────────────────────────────────────────────────────

	{
		id: "xss-innerhtml",
		vulnType: VulnXSS, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)\.innerHTML\s*=|\.outerHTML\s*=`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "Assigning to innerHTML can execute attacker-controlled scripts",
		remediation: "Use textContent or sanitise with DOMPurify before setting innerHTML",
	},
	{
		id: "xss-document-write",
		vulnType: VulnXSS, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)document\.write\s*\(`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "document.write() can inject arbitrary HTML/JS",
		remediation: "Use safe DOM APIs: createElement, textContent, appendChild",
	},
	{
		id: "xss-react-dangerous",
		vulnType: VulnXSS, severity: SevHigh,
		pattern:   regexp.MustCompile(`dangerouslySetInnerHTML\s*=\s*\{\s*\{`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "dangerouslySetInnerHTML bypasses React's XSS protection",
		remediation: "Sanitise HTML with DOMPurify before using dangerouslySetInnerHTML",
	},
	{
		id: "xss-php-echo",
		vulnType: VulnXSS, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)echo\s+\$_(GET|POST|REQUEST|COOKIE)`),
		languages: []Language{LangPHP},
		description: "Directly echoing user input — XSS risk",
		remediation: "Use htmlspecialchars($_GET['x'], ENT_QUOTES, 'UTF-8')",
	},
	{
		id: "xss-py-render-string",
		vulnType: VulnXSS, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)render(_template)?_string\s*\(.*request\.(args|form|data|json)`),
		languages: []Language{LangPython},
		description: "Server-side template injection from user input",
		remediation: "Never render user input as templates; use safe escaping",
	},

	// ── COMMAND INJECTION ─────────────────────────────────────────────────────

	{
		id: "cmd-inject-go-exec",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`exec\.Command\s*\(\s*(fmt\.Sprintf|os\.Args|r\.(Form|URL|Header)|c\.(Param|Query|PostForm))`),
		languages: []Language{LangGo},
		description: "exec.Command called with user-controlled input",
		remediation: "Never pass user input to exec.Command; use whitelists for allowed commands",
	},
	{
		id: "cmd-inject-py-os-system",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)(os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(.*(%s|f['""]|format\(|\+)`),
		languages: []Language{LangPython},
		description: "Shell command constructed from user input",
		remediation: "Use subprocess with a list of args (no shell=True) and avoid user input",
	},
	{
		id: "cmd-inject-py-shell-true",
		vulnType: VulnCommandInjection, severity: SevHigh,
		pattern:   regexp.MustCompile(`subprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True`),
		languages: []Language{LangPython},
		description: "subprocess called with shell=True — enables shell injection",
		remediation: "Use shell=False and pass arguments as a list",
	},
	{
		id: "cmd-inject-js-exec",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile("(?i)(child_process\\.exec|execSync)\\s*\\([^)]*\\$\\{|require\\(['\"]child_process['\"]\\)\\.exec"),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "child_process.exec with interpolated input — command injection",
		remediation: "Use execFile() with argument arrays instead of exec()",
	},
	{
		id: "cmd-inject-php-system",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)(system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`),
		languages: []Language{LangPHP},
		description: "Shell execution with user input — command injection",
		remediation: "Use escapeshellarg() and avoid passing user input to shell functions",
	},
	{
		id: "cmd-inject-java-runtime",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\s*\(\s*(request\.|getParameter|"[^"]*"\s*\+)`),
		languages: []Language{LangJava},
		description: "Runtime.exec called with user-controlled input",
		remediation: "Use ProcessBuilder with a fixed command array; validate all inputs",
	},

	// ── SSRF ──────────────────────────────────────────────────────────────────

	{
		id: "ssrf-go-http",
		vulnType: VulnSSRF, severity: SevHigh,
		pattern:   regexp.MustCompile(`http\.(Get|Post|Head|Do)\s*\(\s*(r\.(Form|URL|Query|Header)|fmt\.Sprintf|os\.Args)`),
		languages: []Language{LangGo},
		description: "HTTP request to user-controlled URL — SSRF risk",
		remediation: "Validate URL against an allowlist before making outbound requests",
	},
	{
		id: "ssrf-py-requests",
		vulnType: VulnSSRF, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)requests\.(get|post|put|delete|head|request)\s*\(\s*(request\.(args|form|data|json)|url|target)`),
		languages: []Language{LangPython},
		description: "requests called with user-supplied URL — SSRF risk",
		remediation: "Validate and allowlist URLs before making outbound HTTP requests",
	},
	{
		id: "ssrf-js-fetch",
		vulnType: VulnSSRF, severity: SevHigh,
		pattern:   regexp.MustCompile("(?i)(fetch|axios\\.(get|post|put|delete))\\s*\\([^)]*\\$\\{(req\\.|request\\.|params\\.|query\\.)"),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "fetch/axios called with user-controlled URL — SSRF risk",
		remediation: "Validate URL origin against an allowlist before fetching",
	},

	// ── PATH TRAVERSAL ────────────────────────────────────────────────────────

	{
		id: "path-traversal-go",
		vulnType: VulnPathTraversal, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(os\.Open|os\.ReadFile|ioutil\.ReadFile|os\.Create|os\.WriteFile)\s*\(\s*(r\.(Form|URL|Query)|fmt\.Sprintf.*req|filepath\.Join\s*\([^)]*r\.)`),
		languages: []Language{LangGo},
		description: "File operation with user-controlled path — path traversal risk",
		remediation: "Use filepath.Clean and validate path is within expected directory",
	},
	{
		id: "path-traversal-py",
		vulnType: VulnPathTraversal, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)open\s*\(\s*(request\.(args|form|files)|os\.path\.join\s*\([^)]*request\.|f['""][^'""]*(request\.|user_))`),
		languages: []Language{LangPython},
		description: "File opened with user-controlled path — path traversal risk",
		remediation: "Use os.path.abspath and verify path starts with allowed base directory",
	},
	{
		id: "path-traversal-php",
		vulnType: VulnPathTraversal, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(include|require|file_get_contents|fopen|readfile)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`),
		languages: []Language{LangPHP},
		description: "File inclusion with user input — path traversal or LFI risk",
		remediation: "Use basename() and restrict to allowed directories with realpath()",
	},

	// ── INSECURE CRYPTO ───────────────────────────────────────────────────────

	{
		id: "crypto-md5-password",
		vulnType: VulnInsecureCrypto, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(md5|sha1)\s*\(.*pass(word)?|hashlib\.(md5|sha1)\s*\(.*pass(word)?|MD5\s*\(.*pass(word)?`),
		languages: nil, // all languages
		description: "MD5/SHA1 used for password hashing — too weak for passwords",
		remediation: "Use bcrypt, Argon2, or scrypt for password hashing",
	},
	{
		id: "crypto-md5-go",
		vulnType: VulnInsecureCrypto, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)crypto/md5|md5\.New\(\)|md5\.Sum\(`),
		languages: []Language{LangGo},
		description: "MD5 is cryptographically broken — do not use for security purposes",
		remediation: "Use SHA-256 (crypto/sha256) or better; use bcrypt for passwords",
	},
	{
		id: "crypto-md5-py",
		vulnType: VulnInsecureCrypto, severity: SevMedium,
		pattern:   regexp.MustCompile(`hashlib\.(md5|sha1)\s*\(`),
		languages: []Language{LangPython},
		description: "MD5/SHA1 is cryptographically weak",
		remediation: "Use hashlib.sha256() or hashlib.sha3_256(); use bcrypt for passwords",
	},
	{
		id: "crypto-weak-js",
		vulnType: VulnInsecureCrypto, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)createHash\s*\(\s*['"]md5['"]|createHash\s*\(\s*['"]sha1['"]`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "MD5/SHA1 hash algorithm is cryptographically weak",
		remediation: "Use SHA-256: crypto.createHash('sha256')",
	},
	{
		id: "crypto-ecb-mode",
		vulnType: VulnInsecureCrypto, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(AES/ECB|Cipher\.getInstance\s*\(\s*"AES"|createCipheriv\s*\(\s*['"]aes-\d+-ecb)`),
		languages: nil,
		description: "AES in ECB mode is insecure — does not hide data patterns",
		remediation: "Use AES-GCM or AES-CBC with a random IV",
	},

	// ── INSECURE JWT ──────────────────────────────────────────────────────────

	{
		id: "jwt-no-verify-py",
		vulnType: VulnInsecureJWT, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature\s*:\s*False|jwt\.decode\s*\([^)]*algorithms\s*=\s*\[\s*["']none["']`),
		languages: []Language{LangPython},
		description: "JWT decoded without signature verification",
		remediation: "Always verify JWT signatures: jwt.decode(token, key, algorithms=['HS256'])",
	},
	{
		id: "jwt-none-alg",
		vulnType: VulnInsecureJWT, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)(alg|algorithm)\s*[=:]\s*["']none["']`),
		languages: nil,
		description: "JWT 'none' algorithm disables signature verification",
		remediation: "Always specify a strong algorithm (HS256, RS256) and verify the signature",
	},
	{
		id: "jwt-hardcoded-secret",
		vulnType: VulnInsecureJWT, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(jwt\.sign|jwt\.verify|jwt_encode|jwt_decode)\s*\([^)]*["'][a-zA-Z0-9]{8,}["']`),
		languages: nil,
		description: "JWT signed/verified with a hardcoded secret",
		remediation: "Load JWT secret from environment variables, not source code",
	},

	// ── UNSAFE DESERIALIZATION ────────────────────────────────────────────────

	{
		id: "deserialize-py-pickle",
		vulnType: VulnUnsafeDeserialize, severity: SevCritical,
		pattern:   regexp.MustCompile(`pickle\.loads\s*\(|pickle\.load\s*\(|cPickle\.loads?\s*\(`),
		languages: []Language{LangPython},
		description: "pickle.loads on untrusted data allows arbitrary code execution",
		remediation: "Use json.loads() or marshal for data; never unpickle untrusted input",
	},
	{
		// Matches yaml.load(x) but NOT yaml.safe_load or yaml.load(x, Loader=...)
		id: "deserialize-py-yaml",
		vulnType: VulnUnsafeDeserialize, severity: SevHigh,
		pattern:   regexp.MustCompile(`\byaml\.load\s*\([^,)]+\)\s*$`),
		languages: []Language{LangPython},
		description: "yaml.load() without Loader= is unsafe — allows arbitrary Python objects",
		remediation: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
	},
	{
		id: "deserialize-java-objectinput",
		vulnType: VulnUnsafeDeserialize, severity: SevCritical,
		pattern:   regexp.MustCompile(`ObjectInputStream\s*\(\s*(request\.|socket\.|getInputStream|new\s+ByteArrayInputStream)`),
		languages: []Language{LangJava},
		description: "Java deserialization from untrusted input — remote code execution risk",
		remediation: "Use a safe deserialization library (e.g. Jackson with type restrictions) or avoid Java serialization",
	},
	{
		id: "deserialize-php-unserialize",
		vulnType: VulnUnsafeDeserialize, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`),
		languages: []Language{LangPHP},
		description: "PHP unserialize on user input — object injection vulnerability",
		remediation: "Use json_decode() instead; never unserialize untrusted data",
	},

	// ── EVAL INJECTION ────────────────────────────────────────────────────────

	{
		id: "eval-py",
		vulnType: VulnEvalInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)\beval\s*\(\s*(request\.(args|form|data|json)|input\(|os\.environ|sys\.argv)`),
		languages: []Language{LangPython},
		description: "eval() on user-controlled data — arbitrary code execution",
		remediation: "Never pass user input to eval(); use ast.literal_eval() for safe evaluation",
	},
	{
		id: "eval-js",
		vulnType: VulnEvalInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)\beval\s*\(\s*(req\.|request\.|params\.|query\.|body\.|\$_(GET|POST))`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "eval() on user-controlled data — arbitrary code execution",
		remediation: "Never use eval() with untrusted input; use JSON.parse() for data",
	},
	{
		id: "eval-php",
		vulnType: VulnEvalInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`),
		languages: []Language{LangPHP},
		description: "eval() on user input — arbitrary code execution",
		remediation: "Remove eval(); never execute user-supplied code",
	},

	// ── DEBUG ENABLED ─────────────────────────────────────────────────────────

	{
		id: "debug-django",
		vulnType: VulnDebugEnabled, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)DEBUG\s*=\s*True`),
		languages: []Language{LangPython},
		description: "Django DEBUG=True exposes stack traces and internal info in production",
		remediation: "Set DEBUG=False in production; use environment variables",
	},
	{
		id: "debug-node",
		vulnType: VulnDebugEnabled, severity: SevLow,
		pattern:   regexp.MustCompile(`(?i)NODE_ENV\s*=\s*['"]development['"]|console\.(log|debug|trace)\s*\(.*password`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "Development mode or sensitive data logged to console",
		remediation: "Use NODE_ENV=production in production; never log passwords",
	},

	// ── INSECURE RANDOM ───────────────────────────────────────────────────────

	{
		id: "random-py-not-crypto",
		vulnType: VulnInsecureRandom, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)(random\.random|random\.randint|random\.choice)\s*\(.*(token|session|secret|key|password)`),
		languages: []Language{LangPython},
		description: "random module is not cryptographically secure — predictable output",
		remediation: "Use secrets.token_hex() or secrets.token_urlsafe() for security tokens",
	},
	{
		id: "random-js-math",
		vulnType: VulnInsecureRandom, severity: SevMedium,
		pattern:   regexp.MustCompile(`Math\.random\s*\(\s*\)`),
		languages: []Language{LangJavaScript, LangTypeScript},
		description: "Math.random() is not cryptographically secure",
		remediation: "Use crypto.randomBytes() or crypto.getRandomValues() for security tokens",
	},

	// ── XXE ───────────────────────────────────────────────────────────────────

	{
		id: "xxe-java-documentbuilder",
		vulnType: VulnXXE, severity: SevHigh,
		pattern:   regexp.MustCompile(`DocumentBuilderFactory\.newInstance\(\)`),
		languages: []Language{LangJava},
		description: "DocumentBuilderFactory without XXE protection — XML External Entity attack",
		remediation: "Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)",
	},
	{
		id: "xxe-py-lxml",
		vulnType: VulnXXE, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)etree\.(parse|fromstring)\s*\([^)]*\)|lxml\.etree`),
		languages: []Language{LangPython},
		description: "lxml/ElementTree may be vulnerable to XXE if parsing untrusted XML",
		remediation: "Use defusedxml library: import defusedxml.ElementTree as ET",
	},

	// ── RUBY ──────────────────────────────────────────────────────────────────

	{
		id: "sql-inject-ruby-string",
		vulnType: VulnSQLInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)\.(where|find_by_sql|execute|select|joins)\s*\(\s*["'].*#\{|\.where\s*\(\s*"[^?]*\+|\.where\s*\(\s*"[^?]*%`),
		languages: []Language{LangRuby},
		description: "ActiveRecord query uses string interpolation or concatenation — SQL injection risk",
		remediation: "Use parameterised queries: where('id = ?', id) or where(id: id)",
	},
	{
		id: "cmd-inject-ruby-backtick",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile("(?i)(`[^`]*#\\{|system\\s*\\([^)]*#\\{|exec\\s*\\([^)]*#\\{|%x\\([^)]*#\\{)"),
		languages: []Language{LangRuby},
		description: "Shell command interpolates user-controlled variable — command injection risk",
		remediation: "Use system() with an argument array; never interpolate user input into shell strings",
	},
	{
		id: "cmd-inject-ruby-open",
		vulnType: VulnCommandInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)open\s*\(\s*["'][|]|IO\.popen\s*\([^)]*#\{|Open3\.(popen|capture)\w*\s*\([^)]*#\{`),
		languages: []Language{LangRuby},
		description: "Kernel#open or IO.popen with interpolated input — command injection",
		remediation: "Use IO.popen(['cmd', arg]) with an array; avoid string interpolation in shell calls",
	},
	{
		id: "eval-ruby",
		vulnType: VulnEvalInjection, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)\beval\s*\(\s*(params|request\.|session\[|cookies\[|gets\b)`),
		languages: []Language{LangRuby},
		description: "eval() on user-controlled input — arbitrary code execution",
		remediation: "Never pass user input to eval(); redesign to avoid dynamic evaluation",
	},
	{
		id: "deserialize-ruby-marshal",
		vulnType: VulnUnsafeDeserialize, severity: SevCritical,
		pattern:   regexp.MustCompile(`(?i)Marshal\.load\s*\(|Marshal\.restore\s*\(`),
		languages: []Language{LangRuby},
		description: "Marshal.load on untrusted data allows arbitrary code execution",
		remediation: "Use JSON.parse or MessagePack instead; never unmarshal untrusted data",
	},
	{
		id: "deserialize-ruby-yaml",
		vulnType: VulnUnsafeDeserialize, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)YAML\.(load|unsafe_load)\s*\(\s*(params|request\.|File\.read\s*\(\s*(params|request\.))`),
		languages: []Language{LangRuby},
		description: "YAML.load on untrusted data allows arbitrary object instantiation",
		remediation: "Use YAML.safe_load() for untrusted input",
	},
	{
		id: "xss-ruby-html-safe",
		vulnType: VulnXSS, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(params|request\.|cookies\[|session\[)[^.]*\.html_safe|raw\s*\(\s*(params|request\.|cookies\[)`),
		languages: []Language{LangRuby},
		description: "User input marked html_safe or passed to raw() bypasses Rails XSS protection",
		remediation: "Never call html_safe or raw() on user input; use h() or let Rails auto-escape",
	},
	{
		id: "path-traversal-ruby",
		vulnType: VulnPathTraversal, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(File\.(read|open|write|delete)|Dir\.glob|Pathname\.new)\s*\([^)]*#\{(params|request\.)`),
		languages: []Language{LangRuby},
		description: "File operation uses request param in path — path traversal risk",
		remediation: "Use File.expand_path and verify result is within an allowed base directory",
	},
	{
		id: "ssrf-ruby-net-http",
		vulnType: VulnSSRF, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)(Net::HTTP\.(get|post|start)|URI\.open|open-uri)\s*\([^)]*#\{(params|request\.)`),
		languages: []Language{LangRuby},
		description: "HTTP request to user-controlled URL — SSRF risk",
		remediation: "Validate and allowlist URLs before making outbound HTTP requests",
	},
	{
		id: "crypto-ruby-md5",
		vulnType: VulnInsecureCrypto, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)Digest::(MD5|SHA1)\.(hexdigest|digest)\s*\(`),
		languages: []Language{LangRuby},
		description: "MD5/SHA1 is cryptographically weak",
		remediation: "Use Digest::SHA256 for hashing; use bcrypt gem for password hashing",
	},
	{
		id: "crypto-ruby-password-md5",
		vulnType: VulnInsecureCrypto, severity: SevHigh,
		pattern:   regexp.MustCompile(`(?i)Digest::(MD5|SHA1)\.hexdigest\s*\([^)]*pass(word)?`),
		languages: []Language{LangRuby},
		description: "MD5/SHA1 used for password hashing — too weak",
		remediation: "Use bcrypt: BCrypt::Password.create(password)",
	},
	{
		id: "random-ruby-rand",
		vulnType: VulnInsecureRandom, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)\brand\s*\(|Random\.rand\s*\(`),
		languages: []Language{LangRuby},
		description: "rand/Random.rand is not cryptographically secure",
		remediation: "Use SecureRandom.hex, SecureRandom.uuid, or SecureRandom.urlsafe_base64",
	},
	{
		id: "debug-ruby-puts-password",
		vulnType: VulnDebugEnabled, severity: SevMedium,
		pattern:   regexp.MustCompile(`(?i)\b(?:puts|pp|p|logger\.(?:debug|info))[\s(][^#\n]*\b(?:password|secret|token|api_key)\b`),
		languages: []Language{LangRuby},
		description: "Sensitive data (password/secret/token) logged or printed",
		remediation: "Remove logging of sensitive values; use [REDACTED] in logs",
	},
}

// Scanner holds the compiled rules for a given language.
type Scanner struct {
	rules []vulnRule
}

// NewScanner creates a Scanner with rules applicable to the given language.
func NewScanner(lang Language) *Scanner {
	var applicable []vulnRule
	for _, r := range allRules {
		if len(r.languages) == 0 {
			applicable = append(applicable, r)
			continue
		}
		for _, l := range r.languages {
			if l == lang {
				applicable = append(applicable, r)
				break
			}
		}
	}
	return &Scanner{rules: applicable}
}

// ScanContent scans source code content line by line and returns findings.
func (s *Scanner) ScanContent(content string) []CodeFinding {
	var findings []CodeFinding
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Skip obvious comments (single-line)
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "/*") {
			continue
		}

		for _, r := range s.rules {
			if r.pattern.MatchString(line) {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 120 {
					snippet = snippet[:120] + "..."
				}
				findings = append(findings, CodeFinding{
					VulnType:    r.vulnType,
					Severity:    r.severity,
					Line:        lineNum + 1,
					Code:        snippet,
					Description: r.description,
					Remediation: r.remediation,
					Source:      "regex",
					RuleID:      r.id,
				})
				break // one rule match per line is enough
			}
		}
	}
	return findings
}
