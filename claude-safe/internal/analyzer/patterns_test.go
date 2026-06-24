package analyzer

import "testing"

type patternTestCase struct {
	name      string
	lang      Language
	code      string
	wantVuln  VulnType
	wantFound bool
}

func TestScanner_SQLInjection(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "Go fmt.Sprintf in Query",
			lang:      LangGo,
			code:      `rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))`,
			wantVuln:  VulnSQLInjection,
			wantFound: true,
		},
		{
			name:      "Go safe parameterised",
			lang:      LangGo,
			code:      `rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)`,
			wantVuln:  VulnSQLInjection,
			wantFound: false,
		},
		{
			name:      "Python cursor format string",
			lang:      LangPython,
			code:      `cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)`,
			wantVuln:  VulnSQLInjection,
			wantFound: true,
		},
		{
			name:      "Python safe parameterised",
			lang:      LangPython,
			code:      `cursor.execute("SELECT * FROM users WHERE name = %s", (name,))`,
			wantVuln:  VulnSQLInjection,
			wantFound: false,
		},
		{
			name:      "JS template literal in query",
			lang:      LangJavaScript,
			code:      "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
			wantVuln:  VulnSQLInjection,
			wantFound: true,
		},
		{
			name:      "Java string concat in executeQuery",
			lang:      LangJava,
			code:      `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)`,
			wantVuln:  VulnSQLInjection,
			wantFound: true,
		},
		{
			name:      "PHP mysql_query with variable",
			lang:      LangPHP,
			code:      `mysql_query("SELECT * FROM users WHERE id = " . $_GET['id'])`,
			wantVuln:  VulnSQLInjection,
			wantFound: true,
		},
	}
	runCases(t, cases)
}

func TestScanner_XSS(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "innerHTML assignment",
			lang:      LangJavaScript,
			code:      `element.innerHTML = userInput`,
			wantVuln:  VulnXSS,
			wantFound: true,
		},
		{
			name:      "document.write",
			lang:      LangJavaScript,
			code:      `document.write(data)`,
			wantVuln:  VulnXSS,
			wantFound: true,
		},
		{
			name:      "React dangerouslySetInnerHTML",
			lang:      LangTypeScript,
			code:      `<div dangerouslySetInnerHTML={{ __html: content }} />`,
			wantVuln:  VulnXSS,
			wantFound: true,
		},
		{
			name:      "PHP echo GET param",
			lang:      LangPHP,
			code:      `echo $_GET['name']`,
			wantVuln:  VulnXSS,
			wantFound: true,
		},
		{
			name:      "Safe textContent",
			lang:      LangJavaScript,
			code:      `element.textContent = userInput`,
			wantVuln:  VulnXSS,
			wantFound: false,
		},
	}
	runCases(t, cases)
}

func TestScanner_CommandInjection(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "Python os.system with format",
			lang:      LangPython,
			code:      `os.system("ping %s" % host)`,
			wantVuln:  VulnCommandInjection,
			wantFound: true,
		},
		{
			name:      "Python subprocess shell=True",
			lang:      LangPython,
			code:      `subprocess.run(cmd, shell=True)`,
			wantVuln:  VulnCommandInjection,
			wantFound: true,
		},
		{
			name:      "PHP system with GET param",
			lang:      LangPHP,
			code:      `system($_GET['cmd'])`,
			wantVuln:  VulnCommandInjection,
			wantFound: true,
		},
		{
			name:      "Python safe subprocess",
			lang:      LangPython,
			code:      `subprocess.run(["ping", host], shell=False)`,
			wantVuln:  VulnCommandInjection,
			wantFound: false,
		},
	}
	runCases(t, cases)
}

func TestScanner_InsecureCrypto(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "Python MD5 for password",
			lang:      LangPython,
			code:      `hashed = hashlib.md5(password.encode()).hexdigest()`,
			wantVuln:  VulnInsecureCrypto,
			wantFound: true,
		},
		{
			name:      "Go crypto/md5 import",
			lang:      LangGo,
			code:      `import "crypto/md5"`,
			wantVuln:  VulnInsecureCrypto,
			wantFound: true,
		},
		{
			name:      "JS createHash md5",
			lang:      LangJavaScript,
			code:      `const hash = crypto.createHash('md5').update(data).digest('hex')`,
			wantVuln:  VulnInsecureCrypto,
			wantFound: true,
		},
		{
			name:      "Safe bcrypt usage",
			lang:      LangPython,
			code:      `hashed = bcrypt.hashpw(password, bcrypt.gensalt())`,
			wantVuln:  VulnInsecureCrypto,
			wantFound: false,
		},
	}
	runCases(t, cases)
}

func TestScanner_UnsafeDeserialization(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "Python pickle.loads",
			lang:      LangPython,
			code:      `obj = pickle.loads(data)`,
			wantVuln:  VulnUnsafeDeserialize,
			wantFound: true,
		},
		{
			name:      "Python yaml.load without Loader",
			lang:      LangPython,
			code:      `config = yaml.load(stream)`,
			wantVuln:  VulnUnsafeDeserialize,
			wantFound: true,
		},
		{
			name:      "PHP unserialize on GET",
			lang:      LangPHP,
			code:      `$obj = unserialize($_GET['data'])`,
			wantVuln:  VulnUnsafeDeserialize,
			wantFound: true,
		},
		{
			name:      "Python yaml.safe_load is safe",
			lang:      LangPython,
			code:      `config = yaml.safe_load(stream)`,
			wantVuln:  VulnUnsafeDeserialize,
			wantFound: false,
		},
	}
	runCases(t, cases)
}

func TestScanner_EvalInjection(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "Python eval on request",
			lang:      LangPython,
			code:      `result = eval(request.args.get('expr'))`,
			wantVuln:  VulnEvalInjection,
			wantFound: true,
		},
		{
			name:      "PHP eval on POST",
			lang:      LangPHP,
			code:      `eval($_POST['code'])`,
			wantVuln:  VulnEvalInjection,
			wantFound: true,
		},
	}
	runCases(t, cases)
}

func TestScanner_InsecureJWT(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "JWT none algorithm",
			lang:      LangJavaScript,
			code:      `const token = jwt.sign(payload, '', { algorithm: 'none' })`,
			wantVuln:  VulnInsecureJWT,
			wantFound: true,
		},
	}
	runCases(t, cases)
}

func TestScanner_Ruby(t *testing.T) {
	cases := []patternTestCase{
		{
			name:      "SQL injection via string interpolation in where",
			lang:      LangRuby,
			code:      `User.where("name = '#{params[:name]}'")`,
			wantVuln:  VulnSQLInjection,
			wantFound: true,
		},
		{
			name:      "Safe ActiveRecord parameterised",
			lang:      LangRuby,
			code:      `User.where('name = ?', params[:name])`,
			wantVuln:  VulnSQLInjection,
			wantFound: false,
		},
		{
			name:      "Command injection via backtick interpolation",
			lang:      LangRuby,
			code:      "output = `ls #{params[:dir]}`",
			wantVuln:  VulnCommandInjection,
			wantFound: true,
		},
		{
			name:      "Command injection via system with interpolation",
			lang:      LangRuby,
			code:      `system("convert #{params[:file]} output.png")`,
			wantVuln:  VulnCommandInjection,
			wantFound: true,
		},
		{
			name:      "eval on user input",
			lang:      LangRuby,
			code:      `eval(params[:expr])`,
			wantVuln:  VulnEvalInjection,
			wantFound: true,
		},
		{
			name:      "Marshal.load on untrusted data",
			lang:      LangRuby,
			code:      `obj = Marshal.load(data)`,
			wantVuln:  VulnUnsafeDeserialize,
			wantFound: true,
		},
		{
			name:      "html_safe on user input",
			lang:      LangRuby,
			code:      `render html: params[:content].html_safe`,
			wantVuln:  VulnXSS,
			wantFound: true,
		},
		{
			name:      "MD5 for password",
			lang:      LangRuby,
			code:      `hashed = Digest::MD5.hexdigest(password)`,
			wantVuln:  VulnInsecureCrypto,
			wantFound: true,
		},
		{
			name:      "Insecure random",
			lang:      LangRuby,
			code:      `token = rand(100000).to_s`,
			wantVuln:  VulnInsecureRandom,
			wantFound: true,
		},
		{
			name:      "Safe SecureRandom",
			lang:      LangRuby,
			code:      `token = SecureRandom.hex(32)`,
			wantVuln:  VulnInsecureRandom,
			wantFound: false,
		},
		{
			name:      "Path traversal in File.read",
			lang:      LangRuby,
			code:      `content = File.read("uploads/#{params[:filename]}")`,
			wantVuln:  VulnPathTraversal,
			wantFound: true,
		},
		{
			name:      "puts logging a password",
			lang:      LangRuby,
			code:      `puts "user password is #{user.password}"`,
			wantVuln:  VulnDebugEnabled,
			wantFound: true,
		},
		{
			name:      "logger.debug with token",
			lang:      LangRuby,
			code:      `logger.debug("api token: #{api_key}")`,
			wantVuln:  VulnDebugEnabled,
			wantFound: true,
		},
		{
			name:      "migration column encrypted_password is not logging",
			lang:      LangRuby,
			code:      `t.string :encrypted_password, null: false, default: ""`,
			wantVuln:  VulnDebugEnabled,
			wantFound: false,
		},
		{
			name:      "migration index on reset_password_token is not logging",
			lang:      LangRuby,
			code:      `add_index :users, :reset_password_token, unique: true`,
			wantVuln:  VulnDebugEnabled,
			wantFound: false,
		},
	}
	runCases(t, cases)
}

func TestDetectFromPath(t *testing.T) {
	tests := []struct{ path string; want Language }{
		{"main.go", LangGo},
		{"app.py", LangPython},
		{"index.js", LangJavaScript},
		{"component.tsx", LangTypeScript},
		{"Main.java", LangJava},
		{"index.php", LangPHP},
		{"model.rb", LangRuby},
		{"unknown.txt", LangUnknown},
	}
	for _, tt := range tests {
		got := DetectFromPath(tt.path)
		if got != tt.want {
			t.Errorf("DetectFromPath(%q) = %s, want %s", tt.path, got, tt.want)
		}
	}
}

func TestEngine_AnalyzeContent(t *testing.T) {
	// A Python file with multiple vulnerabilities should score > 0
	code := `
import pickle, hashlib

def get_user(request):
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
    data = pickle.loads(request.data)
    hashed = hashlib.md5(password.encode()).hexdigest()
    return data
`
	report := AnalyzeContentWithLang(code, LangPython, "")
	if report.Stats.Total < 1 {
		t.Errorf("Expected >=1 findings for vulnerable Python code, got %d", report.Stats.Total)
	}
	if report.RiskScore == 0 {
		t.Error("Risk score should be > 0 for vulnerable code")
	}
	t.Logf("Found %d findings, score=%d, level=%s", report.Stats.Total, report.RiskScore, report.RiskLevel)
}

func TestEngine_CleanCode(t *testing.T) {
	code := `
package main

import (
    "fmt"
    "database/sql"
)

func getUser(db *sql.DB, id int) {
    row := db.QueryRow("SELECT name FROM users WHERE id = ?", id)
    var name string
    row.Scan(&name)
    fmt.Println(name)
}
`
	report := AnalyzeContentWithLang(code, LangGo, "")
	if report.Stats.Total > 0 {
		t.Errorf("Expected 0 findings for clean Go code, got %d:", report.Stats.Total)
		for _, f := range report.Findings {
			t.Logf("  %s line %d: %s", f.VulnType, f.Line, f.Code)
		}
	}
}

// runCases is a helper that runs a slice of patternTestCase against the scanner.
func runCases(t *testing.T, cases []patternTestCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewScanner(tc.lang)
			findings := s.ScanContent(tc.code)
			found := false
			for _, f := range findings {
				if f.VulnType == tc.wantVuln {
					found = true
					break
				}
			}
			if found != tc.wantFound {
				t.Errorf("ScanContent(%q): found=%v, want found=%v", tc.name, found, tc.wantFound)
				for _, f := range findings {
					t.Logf("  Got: %s (line %d)", f.VulnType, f.Line)
				}
			}
		})
	}
}
