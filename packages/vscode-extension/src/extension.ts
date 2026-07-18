import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import * as parser from "@solidity-parser/parser";
import {
  scan,
  generateMarkdownReport,
  isSlitherAvailable,
  loadPlugins,
  clearCache,
  astCache,
} from "@chainproof/core";
import type { Finding, GasHint, ScanConfig, ASTCacheEntry } from "@chainproof/core";

// ─── Severity → VS Code DiagnosticSeverity ───────────────────────────────────

function toVSCodeSeverity(
  severity: Finding["severity"],
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
    case "gas":
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

// ─── Extension state ──────────────────────────────────────────────────────────

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;
let codeLensProvider: ChainProofCodeLensProvider;

// Caches findings per Solidity file to resolve against CodeLenses / CodeActions
const lastScanFindings = new Map<string, Finding[]>();

// ─── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  _extensionContext = context;
  outputChannel = vscode.window.createOutputChannel("ChainProof");
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("chainproof");
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  statusBarItem.command = "chainproof.scanCurrentFile";
  statusBarItem.text = "$(shield) ChainProof";
  statusBarItem.tooltip = "Click to scan current Solidity file";
  statusBarItem.show();

  // Register CodeLensProvider
  codeLensProvider = new ChainProofCodeLensProvider();
  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      { scheme: "file", language: "solidity" },
      codeLensProvider
    )
  );

  // Register CodeActionProvider
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file", language: "solidity" },
      new ChainProofCodeActionProvider(),
      {
        providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
      }
    )
  );

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("chainproof.scanCurrentFile", () =>
      scanCurrentFile(),
    ),
    vscode.commands.registerCommand("chainproof.scanWorkspace", () =>
      scanWorkspace(),
    ),
    vscode.commands.registerCommand("chainproof.generateReport", () =>
      generateReport(),
    ),
    vscode.commands.registerCommand("chainproof.clearDiagnostics", () => {
      diagnosticCollection.clear();
      lastScanFindings.clear();
      codeLensProvider.refresh();
      statusBarItem.text = "$(shield) ChainProof";
      statusBarItem.backgroundColor = undefined;
    }),
    vscode.commands.registerCommand(
      "chainproof.viewFunctionFindings",
      (uri: vscode.Uri, functionName: string, findings: Finding[]) => {
        const panel = vscode.window.createWebviewPanel(
          "chainproofFunctionFindings",
          `ChainProof Findings: ${functionName}`,
          vscode.ViewColumn.Beside,
          { enableScripts: true }
        );
        panel.webview.html = getFindingsWebviewHtml(functionName, findings);
      }
    ),
    vscode.commands.registerCommand(
      "chainproof.applyQuickFix",
      async (uri: vscode.Uri, finding: Finding) => {
        await applyQuickFix(uri, finding);
      }
    ),
    vscode.commands.registerCommand(
      "chainproof.suppressFinding",
      async (uri: vscode.Uri, finding: Finding) => {
        await suppressFinding(uri, finding);
      }
    ),
    vscode.commands.registerCommand(
      "chainproof.explainVulnerability",
      async (uri: vscode.Uri, finding: Finding) => {
        await explainVulnerability(uri, finding);
      }
    ),
    diagnosticCollection,
    statusBarItem,
    outputChannel,
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration("chainproof");
      if (config.get("enableOnSave") && doc.fileName.endsWith(".sol")) {
        scanDocument(doc);
      }
    }),
  );

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.fileName.endsWith(".sol")) {
        scanDocument(doc);
      }
    }),
  );

  // Scan any already-open .sol files
  vscode.workspace.textDocuments
    .filter((d) => d.fileName.endsWith(".sol"))
    .forEach((d) => scanDocument(d));

  // Restore AST cache from previous session.
  loadPersistedCache(context);

  // Register clearCache command so users can purge manually.
  context.subscriptions.push(
    vscode.commands.registerCommand("chainproof.clearASTCache", () => {
      clearCache();
      outputChannel.appendLine("[ChainProof] AST cache cleared.");
      vscode.window.showInformationMessage("ChainProof: AST cache cleared.");
    }),
  );

  outputChannel.appendLine(
    "[ChainProof] Extension activated. Ready to scan Solidity files.",
  );
}

const CACHE_FILENAME = "ast-cache.json";

function cacheStoragePath(context: vscode.ExtensionContext): string {
  return path.join(context.globalStorageUri.fsPath, CACHE_FILENAME);
}

function loadPersistedCache(context: vscode.ExtensionContext): void {
  const cachePath = cacheStoragePath(context);
  try {
    if (fs.existsSync(cachePath)) {
      const raw = fs.readFileSync(cachePath, "utf-8");
      const entries: ASTCacheEntry[] = JSON.parse(raw);
      astCache.hydrate(entries);
      outputChannel.appendLine(
        `[ChainProof] Restored ${entries.length} AST cache entries from previous session.`,
      );
    }
  } catch {
    // Corrupted cache — start fresh.
  }
}

function persistCache(context: vscode.ExtensionContext): void {
  const cachePath = cacheStoragePath(context);
  try {
    fs.mkdirSync(context.globalStorageUri.fsPath, { recursive: true });
    fs.writeFileSync(cachePath, JSON.stringify(astCache.serialize()), "utf-8");
  } catch {
    // Non-fatal — cache will be rebuilt on next session.
  }
}

// ─── Scan a single TextDocument ───────────────────────────────────────────────

async function scanDocument(document: vscode.TextDocument) {
  const config = vscode.workspace.getConfiguration("chainproof");
  const apiKey =
    config.get<string>("apiKey") || process.env.ANTHROPIC_API_KEY || undefined;

  // Load plugins from settings
  const pluginSpecs = config.get<string[]>("plugins") || [];
  const plugins = loadPlugins(pluginSpecs);

  const scanConfig: ScanConfig = {
    targets: [document.fileName],
    useSlither: config.get("useSlither") ?? true,
    useLLM: (config.get("useLLM") ?? false) && !!apiKey,
    useMetrics: config.get("useMetrics") ?? true,
    apiKey,
    minSeverity: config.get("minSeverity") ?? "low",
    plugins,
  };

  statusBarItem.text = "$(sync~spin) ChainProof scanning...";

  try {
    const result = await scan(scanConfig);
    const fileResult = result.files[0];
    if (!fileResult) return;

    // Filter out findings suppressed by an inline comment line: // chainproof-disable-next-line CP-X
    const filteredFindings = fileResult.findings.filter((finding) => {
      const prevLineIndex = finding.line - 2;
      if (prevLineIndex >= 0 && prevLineIndex < document.lineCount) {
        const prevLineText = document.lineAt(prevLineIndex).text;
        if (prevLineText.includes(`chainproof-disable-next-line ${finding.id}`)) {
          return false;
        }
      }
      return true;
    });

    // Update findings cache
    lastScanFindings.set(document.uri.toString(), filteredFindings);
    codeLensProvider.refresh();

    const diagnostics: vscode.Diagnostic[] = [];

    // ── Vulnerability findings → diagnostics ─────────────────────────────────
    for (const finding of filteredFindings) {
      const line = Math.max(0, finding.line - 1);
      const range = new vscode.Range(line, 0, line, 9999);
      const message = `[${finding.id}] ${finding.title}\n${finding.description}\n\nFix: ${finding.recommendation}`;

      const diag = new vscode.Diagnostic(
        range,
        message,
        toVSCodeSeverity(finding.severity),
      );
      diag.source = "ChainProof";
      diag.code = finding.swcId ?? finding.id;

      // Attach related info link for SWC entries
      if (finding.swcId) {
        diag.relatedInformation = [
          new vscode.DiagnosticRelatedInformation(
            new vscode.Location(document.uri, range),
            `SWC Registry: https://swcregistry.io/docs/${finding.swcId}`,
          ),
        ];
      }

      diagnostics.push(diag);
    }

    // ── Gas hints → informational diagnostics ─────────────────────────────────
    for (const hint of fileResult.gasHints) {
      const line = Math.max(0, hint.line - 1);
      const range = new vscode.Range(line, 0, line, 9999);
      const diag = new vscode.Diagnostic(
        range,
        `⛽ Gas: ${hint.description} (${hint.estimatedSaving})`,
        vscode.DiagnosticSeverity.Hint,
      );
      diag.source = "ChainProof";
      diag.code = "GAS";
      diagnostics.push(diag);
    }

    diagnosticCollection.set(document.uri, diagnostics);

    // Update status bar
    const { critical, high, total } = result.summary;
    if (critical > 0) {
      statusBarItem.text = `$(error) ChainProof: ${critical} critical`;
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground",
      );
    } else if (high > 0) {
      statusBarItem.text = `$(warning) ChainProof: ${high} high`;
      statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground",
      );
    } else if (total > 0) {
      statusBarItem.text = `$(info) ChainProof: ${total} hints`;
      statusBarItem.backgroundColor = undefined;
    } else {
      statusBarItem.text = "$(pass) ChainProof: clean";
      statusBarItem.backgroundColor = undefined;
    }

    outputChannel.appendLine(
      `[ChainProof] ${document.fileName}: ${total} findings (${critical} critical, ${high} high)`,
    );
  } catch (err) {
    statusBarItem.text = "$(error) ChainProof: error";
    outputChannel.appendLine(
      `[ChainProof] Error scanning ${document.fileName}: ${err}`,
    );
  }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("ChainProof: No active editor");
    return;
  }
  if (!editor.document.fileName.endsWith(".sol")) {
    vscode.window.showWarningMessage(
      "ChainProof: Active file is not a Solidity file",
    );
    return;
  }
  await scanDocument(editor.document);
  vscode.window.showInformationMessage(
    "ChainProof: Scan complete — check Problems panel",
  );
}

async function scanWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage("ChainProof: No workspace open");
    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ChainProof: Scanning workspace...",
      cancellable: false,
    },
    async () => {
      const docs = vscode.workspace.textDocuments.filter((d) =>
        d.fileName.endsWith(".sol"),
      );
      await Promise.all(docs.map((d) => scanDocument(d)));
    },
  );

  vscode.window.showInformationMessage("ChainProof: Workspace scan complete");
}

async function generateReport() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    vscode.window.showWarningMessage("ChainProof: No workspace open");
    return;
  }

  const workspacePath = folders[0].uri.fsPath;
  const config = vscode.workspace.getConfiguration("chainproof");
  const apiKey =
    config.get<string>("apiKey") || process.env.ANTHROPIC_API_KEY || undefined;

  // Load plugins from settings
  const pluginSpecs = config.get<string[]>("plugins") || [];
  const plugins = loadPlugins(pluginSpecs);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "ChainProof: Generating audit report...",
      cancellable: false,
    },
    async () => {
      const scanConfig: ScanConfig = {
        targets: [workspacePath],
        useSlither: config.get("useSlither") ?? true,
        useLLM: (config.get("useLLM") ?? false) && !!apiKey,
        useMetrics: config.get("useMetrics") ?? true,
        apiKey,
        minSeverity: "low",
        plugins,
      };

      const result = await scan(scanConfig);
      const report = generateMarkdownReport(result);
      const reportPath = path.join(workspacePath, "chainproof-audit-report.md");
      fs.writeFileSync(reportPath, report, "utf-8");

      const doc = await vscode.workspace.openTextDocument(reportPath);
      await vscode.window.showTextDocument(doc);
      vscode.window.showInformationMessage(
        `ChainProof: Report generated at chainproof-audit-report.md`,
      );
    },
  );
}

// ─── Quick Fix / suppression execution ────────────────────────────────────────

async function applyQuickFix(uri: vscode.Uri, finding: Finding) {
  const document = await vscode.workspace.openTextDocument(uri);
  const lineText = document.lineAt(finding.line - 1).text;
  const trimmed = lineText.trim();
  const indent = lineText.substring(0, lineText.indexOf(trimmed));

  let newText = lineText;
  if (finding.id === "CP-115") {
    newText = lineText.replace(/\btx\.origin\b/g, "msg.sender");
  } else if (finding.id === "CP-104") {
    if (trimmed.endsWith(";")) {
      const statement = trimmed.slice(0, -1).trim();
      newText = `${indent}(bool success, ) = ${statement}; require(success, "External call failed");`;
    } else {
      newText = `${indent}(bool success, ) = ${trimmed}; require(success, "External call failed");`;
    }
  }

  const edit = new vscode.WorkspaceEdit();
  const range = new vscode.Range(finding.line - 1, 0, finding.line - 1, lineText.length);
  edit.replace(uri, range, newText);

  const success = await vscode.workspace.applyEdit(edit);
  if (success) {
    await scanDocument(document);
  }
}

async function suppressFinding(uri: vscode.Uri, finding: Finding) {
  const document = await vscode.workspace.openTextDocument(uri);
  const lineText = document.lineAt(finding.line - 1).text;
  const trimmed = lineText.trim();
  const indent = lineText.substring(0, lineText.indexOf(trimmed));

  const edit = new vscode.WorkspaceEdit();
  const position = new vscode.Position(finding.line - 1, 0);
  edit.insert(uri, position, `${indent}// chainproof-disable-next-line ${finding.id}\n`);

  const success = await vscode.workspace.applyEdit(edit);
  if (success) {
    await scanDocument(document);
  }
}

async function explainVulnerability(uri: vscode.Uri, finding: Finding) {
  const document = await vscode.workspace.openTextDocument(uri);
  const sourceCode = document.getText();
  let targetFinding = finding;

  if (!finding.llmEnhanced) {
    const config = vscode.workspace.getConfiguration("chainproof");
    const apiKey =
      config.get<string>("apiKey") || process.env.ANTHROPIC_API_KEY || undefined;

    if (!apiKey) {
      vscode.window.showErrorMessage(
        "ChainProof: Anthropic API key is not configured. Please set chainproof.apiKey in your VS Code settings."
      );
      return;
    }

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "ChainProof: Explaining vulnerability with AI...",
        cancellable: false,
      },
      async () => {
        const scanConfig: ScanConfig = {
          targets: [document.fileName],
          useSlither: config.get("useSlither") ?? true,
          useLLM: true,
          apiKey,
          minSeverity: config.get("minSeverity") ?? "low",
        };

        const enhanced = await enhanceFindingsWithLLM([finding], sourceCode, scanConfig);
        if (enhanced && enhanced[0]) {
          targetFinding = enhanced[0];
          // Update the cache with enhanced finding
          const cached = lastScanFindings.get(uri.toString()) || [];
          const idx = cached.findIndex((f) => f.line === finding.line && f.id === finding.id);
          if (idx !== -1) {
            cached[idx] = targetFinding;
            lastScanFindings.set(uri.toString(), cached);
            codeLensProvider.refresh();
          }
        }
      }
    );
  }

  const panel = vscode.window.createWebviewPanel(
    "chainproofExplanation",
    `ChainProof AI Explanation: ${targetFinding.id}`,
    vscode.ViewColumn.Beside,
    { enableScripts: true }
  );

  panel.webview.html = getExplanationWebviewHtml(targetFinding);
}

// ─── CodeLens Provider ────────────────────────────────────────────────────────

interface FunctionRange {
  name: string;
  startLine: number;
  endLine: number;
}

function findFunctions(source: string): FunctionRange[] {
  const functions: FunctionRange[] = [];
  try {
    const ast = parser.parse(source, { loc: true });
    parser.visit(ast, {
      FunctionDefinition(node) {
        if (node.loc) {
          functions.push({
            name: node.name || "anonymous",
            startLine: node.loc.start.line,
            endLine: node.loc.end.line,
          });
        }
      },
    });
  } catch (e) {
    // If AST parsing fails (common during active coding/typing), fallback to regex
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const match = line.match(/\b(function|fallback|receive)\b\s*(\w+)?\s*\(/);
      if (match) {
        functions.push({
          name: match[2] || "anonymous",
          startLine: i + 1,
          endLine: i + 1,
        });
      }
    }
  }
  return functions;
}

class ChainProofCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  public readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  public refresh(): void {
    this._onDidChangeCodeLenses.fire();
  }

  public provideCodeLenses(
    document: vscode.TextDocument,
    token: vscode.CancellationToken
  ): vscode.CodeLens[] | Thenable<vscode.CodeLens[]> {
    const config = vscode.workspace.getConfiguration("chainproof");
    if (!config.get("enableCodeLens", true)) {
      return [];
    }

    const codeLenses: vscode.CodeLens[] = [];
    const uriStr = document.uri.toString();
    const findings = lastScanFindings.get(uriStr) || [];
    if (findings.length === 0) {
      return [];
    }

    const source = document.getText();
    const functions = findFunctions(source);

    // 1. Finding Summary Lens
    for (const fn of functions) {
      const fnFindings = findings.filter(
        (f) => f.line >= fn.startLine && f.line <= fn.endLine
      );

      if (fnFindings.length > 0) {
        const criticalCount = fnFindings.filter((f) => f.severity === "critical").length;
        const highCount = fnFindings.filter((f) => f.severity === "high").length;
        const mediumCount = fnFindings.filter((f) => f.severity === "medium").length;
        const lowCount = fnFindings.filter((f) => f.severity === "low").length;
        const infoCount = fnFindings.filter((f) => f.severity === "info").length;

        const totalFindings = fnFindings.length;
        const findingWord = totalFindings === 1 ? "finding" : "findings";
        const parts: string[] = [];
        if (criticalCount > 0) parts.push(`${criticalCount} critical`);
        if (highCount > 0) parts.push(`${highCount} high`);
        if (mediumCount > 0) parts.push(`${mediumCount} medium`);
        if (lowCount > 0) parts.push(`${lowCount} low`);
        if (infoCount > 0) parts.push(`${infoCount} info`);

        const summaryText = `[${totalFindings} ChainProof ${findingWord}: ${parts.join(", ")} — click to view]`;
        const range = new vscode.Range(fn.startLine - 1, 0, fn.startLine - 1, 0);

        codeLenses.push(
          new vscode.CodeLens(range, {
            title: summaryText,
            command: "chainproof.viewFunctionFindings",
            arguments: [document.uri, fn.name, fnFindings],
          })
        );
      }
    }

    // 2. Line-specific Lenses: Quick Fix, Suppress, and Explain Lenses
    for (const finding of findings) {
      const line = Math.max(0, finding.line - 1);
      const range = new vscode.Range(line, 0, line, 0);

      // Quick Fix Lens for CP-115 and CP-104
      if (finding.id === "CP-115") {
        codeLenses.push(
          new vscode.CodeLens(range, {
            title: `[ChainProof CP-115: Replace tx.origin with msg.sender — Apply Fix]`,
            command: "chainproof.applyQuickFix",
            arguments: [document.uri, finding],
          })
        );
      } else if (finding.id === "CP-104") {
        codeLenses.push(
          new vscode.CodeLens(range, {
            title: `[ChainProof CP-104: Check return value — Apply Fix]`,
            command: "chainproof.applyQuickFix",
            arguments: [document.uri, finding],
          })
        );
      }

      // Suppress Lens
      codeLenses.push(
        new vscode.CodeLens(range, {
          title: `[ChainProof ${finding.id}: Suppress this finding — Add inline comment]`,
          command: "chainproof.suppressFinding",
          arguments: [document.uri, finding],
        })
      );

      // Explain Lens
      codeLenses.push(
        new vscode.CodeLens(range, {
          title: `[ChainProof ${finding.id}: Explain this vulnerability with AI]`,
          command: "chainproof.explainVulnerability",
          arguments: [document.uri, finding],
        })
      );
    }

    return codeLenses;
  }
}

// ─── CodeAction Provider ──────────────────────────────────────────────────────

class ChainProofCodeActionProvider implements vscode.CodeActionProvider {
  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
    token: vscode.CancellationToken
  ): vscode.CodeAction[] {
    const codeActions: vscode.CodeAction[] = [];

    const chainProofDiagnostics = context.diagnostics.filter(
      (diag) => diag.source === "ChainProof"
    );

    for (const diagnostic of chainProofDiagnostics) {
      const findings = lastScanFindings.get(document.uri.toString()) || [];
      const finding = findings.find(
        (f) =>
          f.line - 1 === diagnostic.range.start.line &&
          (f.swcId === diagnostic.code || f.id === diagnostic.code)
      );

      if (!finding) continue;

      if (finding.id === "CP-115" || finding.id === "CP-104") {
        const action = new vscode.CodeAction(
          finding.id === "CP-115"
            ? "Replace tx.origin with msg.sender (ChainProof)"
            : "Check call return value (ChainProof)",
          vscode.CodeActionKind.QuickFix
        );
        action.command = {
          command: "chainproof.applyQuickFix",
          title: "Apply ChainProof Quick Fix",
          arguments: [document.uri, finding],
        };
        action.diagnostics = [diagnostic];
        codeActions.push(action);
      }

      // Suppression code action
      const suppressAction = new vscode.CodeAction(
        `Suppress finding ${finding.id} (ChainProof)`,
        vscode.CodeActionKind.QuickFix
      );
      suppressAction.command = {
        command: "chainproof.suppressFinding",
        title: "Suppress ChainProof Finding",
        arguments: [document.uri, finding],
      };
      suppressAction.diagnostics = [diagnostic];
      codeActions.push(suppressAction);
    }

    return codeActions;
  }
}

// ─── HTML Webviews ────────────────────────────────────────────────────────────

function getFindingsWebviewHtml(functionName: string, findings: Finding[]): string {
  const findingsHtml = findings
    .map(
      (f) => `
      <div class="finding card">
        <div class="header">
          <span class="severity badge ${f.severity}">${f.severity.toUpperCase()}</span>
          <span class="title">${f.title} (${f.id})</span>
        </div>
        <div class="details">
          <p><strong>Line:</strong> ${f.line}</p>
          <p><strong>Description:</strong> ${f.description}</p>
          <p><strong>Recommendation:</strong> ${f.recommendation}</p>
          ${
            f.llmEnhanced
              ? `<div class="ai-badge">✨ Enhanced with AI Explanation</div>`
              : ""
          }
        </div>
      </div>`
    )
    .join("");

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ChainProof Findings</title>
      <style>
        body {
          font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif);
          padding: 20px;
          color: var(--vscode-foreground);
          background-color: var(--vscode-editor-background);
        }
        h2 {
          border-bottom: 1px solid var(--vscode-settings-headerBorder);
          padding-bottom: 10px;
          margin-bottom: 20px;
        }
        .card {
          background-color: var(--vscode-editor-inactiveSelectionBackground, rgba(0,0,0,0.1));
          border-left: 4px solid var(--vscode-button-background);
          padding: 15px;
          margin-bottom: 20px;
          border-radius: 4px;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 10px;
        }
        .badge {
          padding: 3px 8px;
          border-radius: 3px;
          font-size: 0.8em;
          font-weight: bold;
        }
        .badge.critical { background-color: #ff3b30; color: white; }
        .badge.high { background-color: #ff9500; color: white; }
        .badge.medium { background-color: #ffcc00; color: black; }
        .badge.low { background-color: #34c759; color: white; }
        .badge.info { background-color: #007aff; color: white; }
        .badge.gas { background-color: #8e8e93; color: white; }
        .title {
          font-size: 1.1em;
          font-weight: bold;
        }
        .details p {
          margin: 8px 0;
        }
        .ai-badge {
          display: inline-block;
          margin-top: 10px;
          background-color: rgba(142, 94, 255, 0.15);
          color: #b39ddb;
          border: 1px solid #7e57c2;
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 0.85em;
        }
      </style>
    </head>
    <body>
      <h2>ChainProof Findings in function: <code>${functionName}</code></h2>
      ${findingsHtml}
    </body>
    </html>
  `;
}

function getExplanationWebviewHtml(finding: Finding): string {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>ChainProof AI Explanation</title>
      <style>
        body {
          font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif);
          padding: 20px;
          color: var(--vscode-foreground);
          background-color: var(--vscode-editor-background);
          line-height: 1.6;
        }
        h2 {
          border-bottom: 1px solid var(--vscode-settings-headerBorder);
          padding-bottom: 10px;
          margin-top: 0;
        }
        h3 {
          color: var(--vscode-textLink-foreground);
          margin-top: 25px;
          border-bottom: 1px solid rgba(255,255,255,0.1);
          padding-bottom: 5px;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 15px;
        }
        .badge {
          padding: 4px 10px;
          border-radius: 4px;
          font-size: 0.85em;
          font-weight: bold;
        }
        .badge.critical { background-color: #ff3b30; color: white; }
        .badge.high { background-color: #ff9500; color: white; }
        .badge.medium { background-color: #ffcc00; color: black; }
        .badge.low { background-color: #34c759; color: white; }
        .badge.info { background-color: #007aff; color: white; }
        .badge.gas { background-color: #8e8e93; color: white; }
        .title {
          font-size: 1.2em;
          font-weight: bold;
        }
        pre {
          background-color: var(--vscode-textCodeBlock-background, rgba(0,0,0,0.2));
          padding: 15px;
          border-radius: 4px;
          overflow-x: auto;
          font-family: var(--vscode-editor-font-family, "Courier New", Courier, monospace);
        }
        code {
          font-family: var(--vscode-editor-font-family, "Courier New", Courier, monospace);
        }
        .container {
          max-width: 800px;
          margin: 0 auto;
        }
        .ai-banner {
          background-color: rgba(142, 94, 255, 0.1);
          border: 1px solid rgba(142, 94, 255, 0.3);
          padding: 10px 15px;
          border-radius: 4px;
          margin-bottom: 20px;
          font-size: 0.9em;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <span class="badge ${finding.severity}">${finding.severity.toUpperCase()}</span>
          <span class="title">${finding.title} (${finding.id})</span>
        </div>
        <h2>Vulnerability Analysis</h2>
        
        <div class="ai-banner">
          ✨ <strong>AI-Powered Analysis</strong>: This analysis and recommendation were generated dynamically on-demand using LLM capability.
        </div>

        <h3>Vulnerability Explanation</h3>
        <p>${renderMarkdown(finding.description)}</p>

        <h3>Snippet</h3>
        <pre><code>${finding.snippet ? escapeHtml(finding.snippet) : "(no snippet)"}</code></pre>

        <h3>Recommendation & Corrective Action</h3>
        <p>${renderMarkdown(finding.recommendation)}</p>
      </div>
    </body>
    </html>
  `;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderMarkdown(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/\n/g, "<br>");
}

let _extensionContext: vscode.ExtensionContext | undefined;

export function deactivate() {
  if (_extensionContext) {
    persistCache(_extensionContext);
  }
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
  outputChannel?.dispose();
}
