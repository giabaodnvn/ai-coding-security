import * as vscode from "vscode";
import {
  analyzeFile,
  isSupportedLanguage,
  AnalysisReport,
} from "./analyzer";
import { createDiagnosticsCollection, applyDiagnostics, clearDiagnostics } from "./diagnostics";
import { SecurityStatusBar } from "./statusBar";
import { FindingsProvider, SummaryProvider } from "./sidebar";

// ─── State ────────────────────────────────────────────────────────────────────

let diagnosticsCollection: vscode.DiagnosticCollection;
let statusBar: SecurityStatusBar;
let findingsProvider: FindingsProvider;
let summaryProvider: SummaryProvider;

// Track reports keyed by file path for summary updates
const reportCache = new Map<string, AnalysisReport>();

// Debounce timer per document
const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
const DEBOUNCE_MS = 800;

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  diagnosticsCollection = createDiagnosticsCollection();
  statusBar = new SecurityStatusBar();
  findingsProvider = new FindingsProvider();
  summaryProvider = new SummaryProvider();

  // Commands and disposables
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("claudeSafe.findings", findingsProvider),
    vscode.window.registerTreeDataProvider("claudeSafe.summary", summaryProvider),
    vscode.commands.registerCommand("claudeSafe.scanFile", cmdScanFile),
    vscode.commands.registerCommand("claudeSafe.scanWorkspace", cmdScanWorkspace),
    vscode.commands.registerCommand("claudeSafe.clearDiagnostics", cmdClearDiagnostics),

    // Document lifecycle events
    vscode.workspace.onDidSaveTextDocument(onDocumentSaved),
    vscode.workspace.onDidOpenTextDocument(onDocumentOpened),
    vscode.window.onDidChangeActiveTextEditor(onEditorChanged),

    diagnosticsCollection,
    statusBar,
  );

  // Scan the currently active file on startup
  if (vscode.window.activeTextEditor) {
    scheduleScan(vscode.window.activeTextEditor.document);
  }
}

export function deactivate(): void {
  debounceTimers.forEach((t) => clearTimeout(t));
  debounceTimers.clear();
}

// ─── Commands ─────────────────────────────────────────────────────────────────

async function cmdScanFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Claude Safe: No active editor to scan.");
    return;
  }
  await scanDocument(editor.document, true);
}

async function cmdScanWorkspace(): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage("Claude Safe: No workspace folder open.");
    return;
  }

  const supportedExts = ["go", "py", "js", "ts", "jsx", "tsx", "java", "php", "rb"];
  const pattern = `**/*.{${supportedExts.join(",")}}`;
  const excludePattern = "**/node_modules/**";

  const uris = await vscode.workspace.findFiles(pattern, excludePattern, 200);
  if (uris.length === 0) {
    vscode.window.showInformationMessage("Claude Safe: No supported source files found.");
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Claude Safe: Scanning workspace...",
      cancellable: true,
    },
    async (progress, token) => {
      const root = workspaceFolders[0].uri.fsPath;
      let done = 0;

      for (const uri of uris) {
        if (token.isCancellationRequested) break;

        const doc = await vscode.workspace.openTextDocument(uri);
        progress.report({
          message: `${++done}/${uris.length} — ${uri.fsPath.replace(root, "")}`,
          increment: (1 / uris.length) * 100,
        });

        if (!isSupportedLanguage(doc.languageId)) continue;

        const { report, error } = await analyzeFile(uri.fsPath, root);
        if (error) continue;
        if (report) {
          applyDiagnostics(diagnosticsCollection, doc, report);
          findingsProvider.update(uri.fsPath, report);
          reportCache.set(uri.fsPath, report);
        }
      }

      summaryProvider.update([...reportCache.values()]);
      const total = [...reportCache.values()].reduce(
        (s, r) => s + (r.stats?.Total ?? 0), 0
      );
      vscode.window.showInformationMessage(
        `Claude Safe: Scanned ${done} files — ${total} finding${total !== 1 ? "s" : ""} found.`
      );
    }
  );
}

function cmdClearDiagnostics(): void {
  clearDiagnostics(diagnosticsCollection);
  findingsProvider.clearAll();
  summaryProvider.clear();
  reportCache.clear();
  statusBar.setIdle();
}

// ─── Document event handlers ──────────────────────────────────────────────────

function onDocumentSaved(document: vscode.TextDocument): void {
  const cfg = vscode.workspace.getConfiguration("claudeSafe");
  if (cfg.get<boolean>("scanOnSave")) {
    scheduleScan(document);
  }
}

function onDocumentOpened(document: vscode.TextDocument): void {
  const cfg = vscode.workspace.getConfiguration("claudeSafe");
  if (cfg.get<boolean>("scanOnOpen")) {
    scheduleScan(document);
  }
}

function onEditorChanged(editor: vscode.TextEditor | undefined): void {
  if (!editor) {
    statusBar.setIdle();
    return;
  }
  // Update status bar to show cached result for the newly focused file
  const cached = reportCache.get(editor.document.uri.fsPath);
  if (cached) {
    statusBar.setResult(cached);
  } else if (isSupportedLanguage(editor.document.languageId)) {
    statusBar.setIdle();
  } else {
    statusBar.setUnsupported();
  }
}

// ─── Core scan logic ──────────────────────────────────────────────────────────

function scheduleScan(document: vscode.TextDocument): void {
  if (!isSupportedLanguage(document.languageId)) return;
  if (document.uri.scheme !== "file") return;

  const key = document.uri.fsPath;

  const existing = debounceTimers.get(key);
  if (existing) clearTimeout(existing);

  const timer = setTimeout(() => {
    debounceTimers.delete(key);
    scanDocument(document, false);
  }, DEBOUNCE_MS);

  debounceTimers.set(key, timer);
}

function countAboveThreshold(report: AnalysisReport, threshold: string): number {
  const s = report.stats;
  if (!s) return 0;
  switch (threshold) {
    case "CRITICAL": return s.Critical;
    case "HIGH":     return s.Critical + s.High;
    case "MEDIUM":   return s.Critical + s.High + s.Medium;
    case "ALL":      return s.Total;
    default:         return s.Critical + s.High;
  }
}

async function scanDocument(
  document: vscode.TextDocument,
  showNotification: boolean
): Promise<void> {
  if (!isSupportedLanguage(document.languageId)) return;
  if (document.uri.scheme !== "file") return;

  const filePath = document.uri.fsPath;
  const workspaceRoot = vscode.workspace.getWorkspaceFolder(document.uri)?.uri.fsPath;

  statusBar.setScanning();

  const { report, error } = await analyzeFile(filePath, workspaceRoot);

  if (error) {
    statusBar.setError(error);
    if (showNotification) {
      vscode.window.showErrorMessage(`Claude Safe error: ${error}`);
    }
    return;
  }

  if (!report) {
    statusBar.setIdle();
    return;
  }

  // Update all UI surfaces
  applyDiagnostics(diagnosticsCollection, document, report);
  findingsProvider.update(filePath, report);
  reportCache.set(filePath, report);
  summaryProvider.update([...reportCache.values()]);
  statusBar.setResult(report);

  if (showNotification) {
    const total = report.stats?.Total ?? 0;
    if (total === 0) {
      vscode.window.showInformationMessage(
        `Claude Safe: ${document.fileName} — No vulnerabilities found.`
      );
    } else {
      const msg = `Claude Safe: Found ${total} vulnerability${total !== 1 ? "ies" : ""} in ${document.fileName} (${report.risk_level})`;
      vscode.window.showWarningMessage(msg);
    }
  }

  // Auto-notification based on configured severity threshold
  if (!showNotification) {
    const cfg = vscode.workspace.getConfiguration("claudeSafe");
    const threshold = cfg.get<string>("maxNotificationSeverity") ?? "HIGH";
    const notifyCount = countAboveThreshold(report, threshold);
    if (notifyCount > 0) {
      vscode.window
        .showWarningMessage(
          `Claude Safe: ${notifyCount} ${threshold}+ vulnerability${notifyCount !== 1 ? "ies" : ""} in ${vscode.workspace.asRelativePath(document.uri)}`,
          "View Findings"
        )
        .then((action) => {
          if (action === "View Findings") {
            vscode.commands.executeCommand("claudeSafe.findings.focus");
          }
        });
    }
  }
}
