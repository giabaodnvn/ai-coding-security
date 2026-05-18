import * as vscode from "vscode";
import { Finding, Severity, AnalysisReport } from "./analyzer";

export const DIAGNOSTIC_SOURCE = "claude-safe";

export function createDiagnosticsCollection(): vscode.DiagnosticCollection {
  return vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
}

export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  document: vscode.TextDocument,
  report: AnalysisReport
): void {
  const diagnostics: vscode.Diagnostic[] = [];

  for (const finding of report.findings ?? []) {
    const diag = findingToDiagnostic(document, finding);
    if (diag) {
      diagnostics.push(diag);
    }
  }

  collection.set(document.uri, diagnostics);
}

export function clearDiagnostics(
  collection: vscode.DiagnosticCollection,
  uri?: vscode.Uri
): void {
  if (uri) {
    collection.delete(uri);
  } else {
    collection.clear();
  }
}

function findingToDiagnostic(
  document: vscode.TextDocument,
  finding: Finding
): vscode.Diagnostic | null {
  // Lines from CLI are 1-based; VSCode is 0-based
  const lineIndex = Math.max(0, finding.Line - 1);
  if (lineIndex >= document.lineCount) {
    return null;
  }

  const line = document.lineAt(lineIndex);
  // Try to narrow the range to where the vulnerable code snippet appears
  const snippetStart = finding.Code
    ? line.text.indexOf(finding.Code.trim().substring(0, 20))
    : -1;

  let range: vscode.Range;
  if (snippetStart >= 0) {
    range = new vscode.Range(
      lineIndex, snippetStart,
      lineIndex, Math.min(line.text.length, snippetStart + finding.Code.length)
    );
  } else {
    range = line.range;
  }

  const message = `[${finding.VulnType}] ${finding.Description}\nFix: ${finding.Remediation}`;
  const severity = severityToDiagnosticSeverity(finding.Severity);
  const diag = new vscode.Diagnostic(range, message, severity);

  diag.source = DIAGNOSTIC_SOURCE;
  diag.code = finding.RuleID;

  // Add a related info link with the remediation hint
  diag.relatedInformation = [
    new vscode.DiagnosticRelatedInformation(
      new vscode.Location(document.uri, range),
      `Remediation: ${finding.Remediation}`
    ),
  ];

  // Tag informational low findings so they render more subtly
  if (finding.Severity === "LOW") {
    diag.tags = [vscode.DiagnosticTag.Unnecessary];
  }

  return diag;
}

function severityToDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    case "LOW":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}
