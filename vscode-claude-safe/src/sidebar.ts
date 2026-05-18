import * as vscode from "vscode";
import * as path from "path";
import { AnalysisReport, Finding } from "./analyzer";

// ─── Tree nodes ───────────────────────────────────────────────────────────────

export type NodeKind = "file" | "finding" | "empty" | "summary";

export class SecurityNode extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly kind: NodeKind,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly finding?: Finding,
    public readonly filePath?: string,
  ) {
    super(label, collapsibleState);
  }
}

// ─── Findings tree ────────────────────────────────────────────────────────────

interface FileEntry {
  filePath: string;
  report: AnalysisReport;
}

export class FindingsProvider implements vscode.TreeDataProvider<SecurityNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<SecurityNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private entries: FileEntry[] = [];

  update(filePath: string, report: AnalysisReport): void {
    const idx = this.entries.findIndex((e) => e.filePath === filePath);
    if (idx >= 0) {
      this.entries[idx] = { filePath, report };
    } else {
      this.entries.push({ filePath, report });
    }
    this._onDidChangeTreeData.fire();
  }

  clearAll(): void {
    this.entries = [];
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: SecurityNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: SecurityNode): SecurityNode[] {
    if (!element) {
      return this.getRootNodes();
    }
    if (element.kind === "file" && element.filePath) {
      return this.getFindingNodes(element.filePath);
    }
    return [];
  }

  private getRootNodes(): SecurityNode[] {
    const filesWithFindings = this.entries.filter(
      (e) => (e.report.findings ?? []).length > 0
    );

    if (filesWithFindings.length === 0) {
      const node = new SecurityNode(
        "No vulnerabilities detected",
        "empty",
        vscode.TreeItemCollapsibleState.None
      );
      node.iconPath = new vscode.ThemeIcon("shield-check");
      node.description = "All scanned files are clean";
      return [node];
    }

    return filesWithFindings.map((entry) => {
      const findings = entry.report.findings ?? [];
      const label = path.basename(entry.filePath);
      const node = new SecurityNode(
        label,
        "file",
        vscode.TreeItemCollapsibleState.Expanded,
        undefined,
        entry.filePath,
      );
      node.description = `${findings.length} finding${findings.length !== 1 ? "s" : ""} — ${entry.report.risk_level}`;
      node.tooltip = entry.filePath;
      node.iconPath = fileIcon(entry.report.risk_level);
      node.resourceUri = vscode.Uri.file(entry.filePath);
      node.command = {
        command: "vscode.open",
        title: "Open File",
        arguments: [vscode.Uri.file(entry.filePath)],
      };
      return node;
    });
  }

  private getFindingNodes(filePath: string): SecurityNode[] {
    const entry = this.entries.find((e) => e.filePath === filePath);
    if (!entry) return [];

    return (entry.report.findings ?? []).map((finding) => {
      const node = new SecurityNode(
        `[${finding.Severity}] ${finding.VulnType}`,
        "finding",
        vscode.TreeItemCollapsibleState.None,
        finding,
        filePath
      );
      node.description = `Line ${finding.Line}`;
      node.tooltip = `${finding.Description}\n\nFix: ${finding.Remediation}`;
      node.iconPath = severityIcon(finding.Severity);
      node.command = {
        command: "vscode.open",
        title: "Go to finding",
        arguments: [
          vscode.Uri.file(filePath),
          { selection: new vscode.Range(finding.Line - 1, 0, finding.Line - 1, 999) },
        ],
      };
      return node;
    });
  }
}

// ─── Summary tree ─────────────────────────────────────────────────────────────

export class SummaryProvider implements vscode.TreeDataProvider<SecurityNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<SecurityNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private reports: AnalysisReport[] = [];

  update(reports: AnalysisReport[]): void {
    this.reports = reports;
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this.reports = [];
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: SecurityNode): vscode.TreeItem {
    return element;
  }

  getChildren(_element?: SecurityNode): SecurityNode[] {
    if (this.reports.length === 0) {
      const node = new SecurityNode(
        "No scans yet",
        "empty",
        vscode.TreeItemCollapsibleState.None
      );
      node.iconPath = new vscode.ThemeIcon("shield");
      node.description = "Open a supported file to trigger a scan";
      return [node];
    }

    const total = this.reports.reduce((s, r) => s + (r.stats?.Total ?? 0), 0);
    const critical = this.reports.reduce((s, r) => s + (r.stats?.Critical ?? 0), 0);
    const high = this.reports.reduce((s, r) => s + (r.stats?.High ?? 0), 0);
    const medium = this.reports.reduce((s, r) => s + (r.stats?.Medium ?? 0), 0);
    const low = this.reports.reduce((s, r) => s + (r.stats?.Low ?? 0), 0);
    const filesScanned = this.reports.length;
    const filesClean = this.reports.filter((r) => (r.stats?.Total ?? 0) === 0).length;

    const rows: Array<[string, string, vscode.ThemeIcon]> = [
      ["Files scanned", String(filesScanned), new vscode.ThemeIcon("files")],
      ["Files clean", String(filesClean), new vscode.ThemeIcon("shield-check")],
      ["Total findings", String(total), new vscode.ThemeIcon("warning")],
      ["Critical", String(critical), new vscode.ThemeIcon("error")],
      ["High", String(high), new vscode.ThemeIcon("warning")],
      ["Medium", String(medium), new vscode.ThemeIcon("info")],
      ["Low", String(low), new vscode.ThemeIcon("circle-outline")],
    ];

    return rows.map(([label, value, icon]) => {
      const node = new SecurityNode(
        label,
        "summary",
        vscode.TreeItemCollapsibleState.None
      );
      node.description = value;
      node.iconPath = icon;
      return node;
    });
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fileIcon(riskLevel: string): vscode.ThemeIcon {
  switch (riskLevel) {
    case "CRITICAL": return new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
    case "HIGH":     return new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground"));
    case "MEDIUM":   return new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground"));
    case "LOW":      return new vscode.ThemeIcon("circle-outline");
    default:         return new vscode.ThemeIcon("shield-check");
  }
}

function severityIcon(severity: string): vscode.ThemeIcon {
  switch (severity) {
    case "CRITICAL": return new vscode.ThemeIcon("error");
    case "HIGH":     return new vscode.ThemeIcon("warning");
    case "MEDIUM":   return new vscode.ThemeIcon("info");
    default:         return new vscode.ThemeIcon("circle-outline");
  }
}
