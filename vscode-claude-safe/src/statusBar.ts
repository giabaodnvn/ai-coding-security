import * as vscode from "vscode";
import { AnalysisReport } from "./analyzer";

export class SecurityStatusBar {
  private item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.item.command = "claudeSafe.scanFile";
    this.setIdle();
    this.item.show();
  }

  setIdle(): void {
    this.item.text = "$(shield) Claude Safe";
    this.item.tooltip = "Click to scan current file";
    this.item.backgroundColor = undefined;
  }

  setScanning(): void {
    this.item.text = "$(loading~spin) Scanning...";
    this.item.tooltip = "Claude Safe is scanning...";
    this.item.backgroundColor = undefined;
  }

  setResult(report: AnalysisReport): void {
    const { risk_level, stats } = report;

    if (stats.Total === 0) {
      this.item.text = "$(shield-check) Safe";
      this.item.tooltip = "No vulnerabilities found";
      this.item.backgroundColor = undefined;
      return;
    }

    const icon = riskIcon(risk_level);
    const label = `${icon} ${risk_level} (${stats.Total})`;
    this.item.text = label;
    this.item.tooltip = buildTooltip(report);

    if (risk_level === "CRITICAL" || risk_level === "HIGH") {
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground"
      );
    } else if (risk_level === "MEDIUM") {
      this.item.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground"
      );
    } else {
      this.item.backgroundColor = undefined;
    }
  }

  setError(message: string): void {
    this.item.text = "$(shield-x) Claude Safe Error";
    this.item.tooltip = message;
    this.item.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground"
    );
  }

  setUnsupported(): void {
    this.item.text = "$(shield) Claude Safe";
    this.item.tooltip = "Language not supported by Claude Safe";
    this.item.backgroundColor = undefined;
  }

  dispose(): void {
    this.item.dispose();
  }
}

function riskIcon(level: string): string {
  switch (level) {
    case "CRITICAL": return "$(error)";
    case "HIGH":     return "$(warning)";
    case "MEDIUM":   return "$(info)";
    case "LOW":      return "$(circle-outline)";
    case "SAFE":     return "$(shield-check)";
    default:         return "$(shield)";
  }
}

function buildTooltip(report: AnalysisReport): string {
  const { stats, risk_score, risk_level, language } = report;
  const lines = [
    `Claude Safe — ${language}`,
    `Risk: ${risk_level} (score ${risk_score}/100)`,
    `Findings: ${stats.Total} total`,
  ];
  if (stats.Critical > 0) lines.push(`  • ${stats.Critical} critical`);
  if (stats.High > 0)     lines.push(`  • ${stats.High} high`);
  if (stats.Medium > 0)   lines.push(`  • ${stats.Medium} medium`);
  if (stats.Low > 0)      lines.push(`  • ${stats.Low} low`);
  lines.push("Click to re-scan");
  return lines.join("\n");
}
