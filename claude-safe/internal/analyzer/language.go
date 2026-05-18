package analyzer

import (
	"path/filepath"
	"strings"
)

type Language string

const (
	LangGo         Language = "go"
	LangPython      Language = "python"
	LangJavaScript  Language = "javascript"
	LangTypeScript  Language = "typescript"
	LangJava        Language = "java"
	LangPHP         Language = "php"
	LangRuby        Language = "ruby"
	LangSQL         Language = "sql"
	LangUnknown     Language = "unknown"
)

var extToLang = map[string]Language{
	".go":   LangGo,
	".py":   LangPython,
	".js":   LangJavaScript,
	".mjs":  LangJavaScript,
	".cjs":  LangJavaScript,
	".ts":   LangTypeScript,
	".tsx":  LangTypeScript,
	".jsx":  LangJavaScript,
	".java": LangJava,
	".php":  LangPHP,
	".rb":   LangRuby,
	".sql":  LangSQL,
}

// DetectFromPath returns the language based on file extension.
func DetectFromPath(path string) Language {
	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := extToLang[ext]; ok {
		return lang
	}
	return LangUnknown
}

// DetectFromContent guesses language from code content when path is unavailable.
func DetectFromContent(content string) Language {
	// Quick heuristic: look for distinctive keywords/patterns
	switch {
	case strings.Contains(content, "package main") || strings.Contains(content, "func main()"):
		return LangGo
	case strings.Contains(content, "def ") && strings.Contains(content, "import "):
		return LangPython
	case strings.Contains(content, "<?php"):
		return LangPHP
	case strings.Contains(content, "public class ") || strings.Contains(content, "public static void main"):
		return LangJava
	case strings.Contains(content, "interface ") && strings.Contains(content, ": string"):
		return LangTypeScript
	case strings.Contains(content, "const ") || strings.Contains(content, "require(") || strings.Contains(content, "exports."):
		return LangJavaScript
	case strings.Contains(content, "def ") && strings.Contains(content, "end"):
		return LangRuby
	case strings.Contains(content, "SELECT ") || strings.Contains(content, "INSERT INTO"):
		return LangSQL
	}
	return LangUnknown
}

// SemgrepID maps our language to Semgrep language identifier
func (l Language) SemgrepID() string {
	switch l {
	case LangGo:
		return "go"
	case LangPython:
		return "python"
	case LangJavaScript:
		return "javascript"
	case LangTypeScript:
		return "typescript"
	case LangJava:
		return "java"
	case LangPHP:
		return "php"
	case LangRuby:
		return "ruby"
	default:
		return ""
	}
}
