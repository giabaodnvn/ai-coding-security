package command

import (
	"strings"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

type CommandRisk struct {
	Command     string
	RiskLevel   RiskLevel
	Reason      string
	ShouldBlock bool
}

type rule struct {
	pattern  string
	level    RiskLevel
	reason   string
	block    bool
	matchFn  func(cmd, pattern string) bool
}

var defaultRules = []rule{
	// CRITICAL — always block
	{"rm -rf /", RiskCritical, "Deletes entire root filesystem", true, func(cmd, _ string) bool {
		s := strings.TrimSpace(cmd)
		return s == "rm -rf /" || strings.Contains(s, "rm -rf / ") || strings.HasSuffix(s, "rm -rf /")
	}},
	{"rm -rf ~", RiskCritical, "Deletes entire home directory", true, contains},
	{"rm -rf *", RiskCritical, "Recursive force delete with wildcard", true, contains},
	{"mkfs", RiskCritical, "Formats filesystem — destroys all data", true, hasWord},
	{"dd if=", RiskCritical, "Low-level disk write — can destroy data", true, contains},
	{":(){ :|:& };:", RiskCritical, "Fork bomb — crashes the system", true, contains},
	{"curl|bash", RiskCritical, "Remote code execution via pipe (curl|bash)", true, hasPipe("curl", "bash")},
	{"curl|sh", RiskCritical, "Remote code execution via pipe (curl|sh)", true, hasPipe("curl", "sh")},
	{"wget|bash", RiskCritical, "Remote code execution via pipe (wget|bash)", true, hasPipe("wget", "bash")},
	{"wget|sh", RiskCritical, "Remote code execution via pipe (wget|sh)", true, hasPipe("wget", "sh")},
	{"python|pipe", RiskCritical, "Remote code execution via pipe (python)", true, hasPipe("curl", "python")},
	{"python -c", RiskCritical, "Inline Python execution — verify intent", true, contains},
	{"eval $(", RiskCritical, "Dynamic code evaluation — high injection risk", true, contains},
	{"sudo su", RiskCritical, "Full root shell escalation", true, contains},
	{"sudo -i", RiskCritical, "Root interactive shell", true, contains},
	{"chmod 777 / ", RiskCritical, "World-writable permissions on root", true, func(cmd, _ string) bool {
		return cmd == "chmod 777 /" || strings.HasSuffix(strings.TrimSpace(cmd), "chmod 777 /")
	}},
	{"iptables -F", RiskCritical, "Flushes all firewall rules", true, contains},
	{"shutdown", RiskCritical, "System shutdown", true, hasWord},
	{"reboot", RiskCritical, "System reboot", true, hasWord},
	{"halt", RiskCritical, "System halt", true, hasWord},

	// HIGH — block by default, allow via policy
	{"rm -rf", RiskHigh, "Recursive force delete", true, contains},
	{"chmod 777", RiskHigh, "World-writable permissions set", true, contains},
	{"kill -9", RiskHigh, "Force kill process — may cause data loss", true, contains},
	{"killall", RiskHigh, "Kills all matching processes", true, hasWord},
	{"pkill -9", RiskHigh, "Force kill by name", true, contains},
	{"truncate", RiskHigh, "Truncates file — destroys content", true, hasWord},
	{"shred", RiskHigh, "Securely deletes files — unrecoverable", true, hasWord},
	{"wipe", RiskHigh, "Wipes disk — destroys data", true, hasWord},
	{"docker system prune -a", RiskHigh, "Removes all Docker data", true, contains},
	{"git push --force", RiskHigh, "Force push — can overwrite remote history", true, contains},
	{"git push -f", RiskHigh, "Force push — can overwrite remote history", true, contains},
	{"git reset --hard", RiskHigh, "Hard reset — destroys uncommitted changes", true, contains},
	{"DROP TABLE", RiskHigh, "SQL table deletion", true, containsCI},
	{"DROP DATABASE", RiskHigh, "SQL database deletion", true, containsCI},
	{"DELETE FROM", RiskHigh, "SQL mass delete — verify WHERE clause", false, containsCI},

	// MEDIUM — warn, don't block by default
	{"sudo", RiskMedium, "Elevated privileges required", false, hasWord},
	{"chmod", RiskMedium, "Changing file permissions", false, hasWord},
	{"chown", RiskMedium, "Changing file ownership", false, hasWord},
	{"mv /", RiskMedium, "Moving root-level path", false, contains},
	{"docker run --privileged", RiskMedium, "Privileged Docker container", false, contains},
	{"docker run --rm -v /:/host", RiskMedium, "Host filesystem mounted in container", false, contains},
	{"nmap", RiskMedium, "Network scan tool", false, hasWord},
	{"ssh", RiskMedium, "Remote SSH connection", false, hasWord},
	{"scp", RiskMedium, "Remote file copy", false, hasWord},
	{"curl", RiskMedium, "External HTTP request", false, hasWord},
	{"wget", RiskMedium, "External file download", false, hasWord},
	{"pip install", RiskMedium, "Package installation", false, contains},
	{"npm install", RiskMedium, "Package installation", false, contains},
	{"apt install", RiskMedium, "System package installation", false, contains},
	{"apt-get install", RiskMedium, "System package installation", false, contains},
	{"systemctl", RiskMedium, "Service management", false, hasWord},
	{"crontab", RiskMedium, "Scheduled task modification", false, hasWord},
}

func contains(cmd, pattern string) bool {
	return strings.Contains(cmd, pattern)
}

func containsCI(cmd, pattern string) bool {
	return strings.Contains(strings.ToUpper(cmd), strings.ToUpper(pattern))
}

func hasWord(cmd, pattern string) bool {
	parts := strings.Fields(cmd)
	for _, p := range parts {
		if strings.EqualFold(p, pattern) {
			return true
		}
	}
	return strings.HasPrefix(strings.TrimSpace(cmd), pattern)
}

// hasPipe checks if cmd contains `tool` followed by `| executor` anywhere (handles URLs in between)
func hasPipe(tool, executor string) func(cmd, _ string) bool {
	return func(cmd, _ string) bool {
		lower := strings.ToLower(cmd)
		toolIdx := strings.Index(lower, tool)
		if toolIdx == -1 {
			return false
		}
		after := lower[toolIdx:]
		return strings.Contains(after, "| "+executor) || strings.Contains(after, "|"+executor)
	}
}

type Validator struct {
	rules     []rule
	allowList []string
}

func New() *Validator {
	return &Validator{rules: defaultRules}
}

func (v *Validator) WithAllowList(cmds []string) *Validator {
	v.allowList = cmds
	return v
}

func (v *Validator) Validate(cmd string) CommandRisk {
	trimmed := strings.TrimSpace(cmd)

	for _, allowed := range v.allowList {
		if strings.Contains(trimmed, allowed) {
			return CommandRisk{Command: trimmed, RiskLevel: RiskLow, Reason: "Command in allowlist", ShouldBlock: false}
		}
	}

	result := CommandRisk{Command: trimmed, RiskLevel: RiskLow, Reason: "No known risks detected", ShouldBlock: false}

	for _, r := range v.rules {
		if r.matchFn(trimmed, r.pattern) {
			// Take the highest risk level found
			if riskOrder(r.level) > riskOrder(result.RiskLevel) {
				result.RiskLevel = r.level
				result.Reason = r.reason
				result.ShouldBlock = r.block
			}
		}
	}

	return result
}

func riskOrder(r RiskLevel) int {
	switch r {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	}
	return 0
}
