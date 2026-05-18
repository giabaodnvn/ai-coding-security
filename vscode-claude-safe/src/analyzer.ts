import { execFile } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as vscode from "vscode";

const execFileAsync = promisify(execFile);

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  VulnType: string;
  Severity: Severity;
  Line: number;
  Code: string;
  Description: string;
  Remediation: string;
  Source: string;
  RuleID: string;
}

export interface Stats {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  Total: number;
}

export interface AnalysisReport {
  source: string;
  language: string;
  risk_score: number;
  risk_level: string;
  semgrep_used: boolean;
  stats: Stats;
  findings: Finding[];
}

export interface ScanResult {
  report: AnalysisReport | null;
  error: string | null;
}

function getBinaryPath(): string {
  const cfg = vscode.workspace.getConfiguration("claudeSafe");
  return cfg.get<string>("binaryPath") || "claude-safe";
}

function getPolicyArgs(workspaceRoot: string | undefined): string[] {
  const cfg = vscode.workspace.getConfiguration("claudeSafe");
  const policyFile = cfg.get<string>("policyFile") || ".claude-safe/policy.yaml";
  if (workspaceRoot) {
    return ["--policy", path.join(workspaceRoot, policyFile)];
  }
  return [];
}

export async function analyzeFile(
  filePath: string,
  workspaceRoot: string | undefined
): Promise<ScanResult> {
  const binary = getBinaryPath();
  const policyArgs = getPolicyArgs(workspaceRoot);
  const args = ["analyze", "--file", filePath, "--json", ...policyArgs];

  try {
    const { stdout } = await execFileAsync(binary, args, { timeout: 15000 });
    const report = JSON.parse(stdout.trim()) as AnalysisReport;
    return { report, error: null };
  } catch (err: unknown) {
    // exit code 1 = vulnerabilities found — stdout still has JSON
    const execErr = err as { stdout?: string; stderr?: string; code?: number };
    if (execErr.stdout) {
      try {
        const report = JSON.parse(execErr.stdout.trim()) as AnalysisReport;
        return { report, error: null };
      } catch {
        // JSON parse failed
      }
    }
    const message = execErr.stderr || String(err);
    if (message.includes("not found") || message.includes("ENOENT")) {
      return {
        report: null,
        error: `claude-safe binary not found at "${binary}". Install it with: go install github.com/claude-safe/claude-safe@latest`,
      };
    }
    return { report: null, error: message };
  }
}

export function isSupportedLanguage(languageId: string): boolean {
  const supported = new Set([
    "go", "python", "javascript", "typescript",
    "javascriptreact", "typescriptreact", "java", "php", "ruby",
  ]);
  return supported.has(languageId);
}
