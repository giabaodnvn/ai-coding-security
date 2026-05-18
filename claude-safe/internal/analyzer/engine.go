package analyzer

import (
	"os"
	"sort"
)

// Report is the complete analysis result for one file or snippet.
type Report struct {
	Language    Language
	Findings    []CodeFinding
	RiskScore   int
	RiskLevel   string
	SemgrepUsed bool
	Stats       Stats
}

// Stats summarises finding counts by severity.
type Stats struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Total    int
}

// AnalyzeFile reads a file from disk and runs a full security analysis.
func AnalyzeFile(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lang := DetectFromPath(path)
	if lang == LangUnknown {
		lang = DetectFromContent(string(data))
	}

	return analyzeContent(string(data), lang, path), nil
}

// AnalyzeContent runs a full security analysis on raw source code.
// filePath is used only for display/reporting (pass "" for inline text).
func AnalyzeContent(content, filePath string) *Report {
	lang := DetectFromPath(filePath)
	if lang == LangUnknown {
		lang = DetectFromContent(content)
	}
	return analyzeContent(content, lang, filePath)
}

// AnalyzeContentWithLang runs analysis with an explicit language override.
func AnalyzeContentWithLang(content string, lang Language, filePath string) *Report {
	return analyzeContent(content, lang, filePath)
}

func analyzeContent(content string, lang Language, filePath string) *Report {
	report := &Report{Language: lang}

	// 1. Regex-based scan (always runs, zero dependencies)
	scanner := NewScanner(lang)
	regexFindings := scanner.ScanContent(content)
	report.Findings = append(report.Findings, regexFindings...)

	// 2. Semgrep scan (runs only if semgrep is installed)
	if IsAvailable() && filePath != "" {
		sgFindings, err := RunSemgrep(filePath, lang)
		if err == nil {
			report.SemgrepUsed = true
			// Deduplicate: skip semgrep findings on lines already caught by regex
			regexLines := lineSet(regexFindings)
			for _, f := range sgFindings {
				if !regexLines[f.Line] {
					report.Findings = append(report.Findings, f)
				}
			}
		}
	} else if IsAvailable() && filePath == "" {
		sgFindings, err := RunSemgrepOnContent(content, lang)
		if err == nil {
			report.SemgrepUsed = true
			regexLines := lineSet(regexFindings)
			for _, f := range sgFindings {
				if !regexLines[f.Line] {
					report.Findings = append(report.Findings, f)
				}
			}
		}
	}

	// 3. Sort by line number for readable output
	sort.Slice(report.Findings, func(i, j int) bool {
		return report.Findings[i].Line < report.Findings[j].Line
	})

	// 4. Calculate risk score and stats
	report.Stats, report.RiskScore = calcScore(report.Findings)
	report.RiskLevel = scoreToLevel(report.RiskScore)

	return report
}

func lineSet(findings []CodeFinding) map[int]bool {
	m := make(map[int]bool, len(findings))
	for _, f := range findings {
		m[f.Line] = true
	}
	return m
}

func calcScore(findings []CodeFinding) (Stats, int) {
	var stats Stats
	score := 0

	for _, f := range findings {
		stats.Total++
		switch f.Severity {
		case SevCritical:
			stats.Critical++
			score += 35
		case SevHigh:
			stats.High++
			score += 20
		case SevMedium:
			stats.Medium++
			score += 10
		case SevLow:
			stats.Low++
			score += 3
		}
	}

	if score > 100 {
		score = 100
	}
	return stats, score
}

func scoreToLevel(score int) string {
	switch {
	case score == 0:
		return "SAFE"
	case score <= 15:
		return "LOW"
	case score <= 35:
		return "MEDIUM"
	case score <= 60:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
