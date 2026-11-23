// Trishul VS Code extension — local-first.
//
// This extension shells out to the user's own `trishul` binary and renders its
// findings inline as diagnostics. It makes NO network calls of its own: the
// only outbound action is opening the public install docs in the user's browser
// when the binary is missing, and that is user-initiated (a button click).

import { spawn } from "child_process";
import * as path from "path";
import * as vscode from "vscode";

/** Language IDs we offer to scan on save. Kept in sync with activationEvents. */
const SUPPORTED_LANGUAGES = new Set<string>([
  "javascript",
  "javascriptreact",
  "typescript",
  "typescriptreact",
  "python",
  "go",
  "rust",
  "java",
  "ruby",
  "php",
  "c",
  "cpp",
  "solidity",
]);

const INSTALL_DOCS_URL = "https://github.com/Armur-Ai/trishul#installation";

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("trishul");
  output = vscode.window.createOutputChannel("Trishul");
  context.subscriptions.push(diagnostics, output);

  context.subscriptions.push(
    vscode.commands.registerCommand("trishul.scanWorkspace", () =>
      scanWorkspace()
    ),
    vscode.commands.registerCommand("trishul.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage(
          "Trishul: open a file to scan it."
        );
        return;
      }
      void scanFile(editor.document.uri);
    })
  );

  // On save: scan the saved file when enabled and the language is supported.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("trishul");
      if (!cfg.get<boolean>("runOnSave", false)) {
        return;
      }
      if (!SUPPORTED_LANGUAGES.has(doc.languageId)) {
        return;
      }
      if (doc.uri.scheme !== "file") {
        return;
      }
      void scanFile(doc.uri);
    })
  );
}

export function deactivate(): void {
  if (diagnostics) {
    diagnostics.clear();
    diagnostics.dispose();
  }
}

/** Scan every workspace folder and replace all diagnostics. */
async function scanWorkspace(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showInformationMessage(
      "Trishul: open a folder or workspace to scan."
    );
    return;
  }
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Trishul: scanning workspace…",
      cancellable: false,
    },
    async () => {
      diagnostics.clear();
      for (const folder of folders) {
        const base = folder.uri.fsPath;
        const results = await runScan(base, base);
        if (results === undefined) {
          return; // binary missing / fatal — message already shown
        }
        applyDiagnostics(results, base, /* replaceAll */ false);
      }
    }
  );
}

/** Scan a single file and replace that file's diagnostics. */
async function scanFile(uri: vscode.Uri): Promise<void> {
  const filePath = uri.fsPath;
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  const base = folder ? folder.uri.fsPath : path.dirname(filePath);
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Window,
      title: `Trishul: scanning ${path.basename(filePath)}…`,
    },
    async () => {
      const results = await runScan(filePath, base);
      if (results === undefined) {
        return;
      }
      // Replace diagnostics for just this file.
      diagnostics.delete(uri);
      applyDiagnostics(results, base, /* replaceAll */ false, uri);
    }
  );
}

/** One parsed finding, normalized across SARIF and JSON. */
interface Finding {
  file: string; // path as reported (absolute or relative to scan base)
  line: number; // 1-based; 0/absent means unknown
  column: number; // 1-based; 0/absent means unknown
  endLine: number;
  endColumn: number;
  severity: vscode.DiagnosticSeverity;
  ruleId: string;
  message: string;
}

/**
 * Run `trishul scan <target> --format <fmt>` and return parsed findings.
 * Returns undefined on a fatal error (binary missing, non-zero/garbage output)
 * after showing the user a friendly message.
 */
async function runScan(
  target: string,
  base: string
): Promise<Finding[] | undefined> {
  const cfg = vscode.workspace.getConfiguration("trishul");
  const binary = cfg.get<string>("path", "trishul") || "trishul";
  const format = cfg.get<string>("format", "sarif") === "json" ? "json" : "sarif";
  const extraArgs = cfg.get<string[]>("extraArgs", []) ?? [];

  const args = ["scan", target, "--format", format, ...extraArgs];
  output.appendLine(`$ ${binary} ${args.join(" ")}`);

  let stdout: string;
  try {
    stdout = await exec(binary, args, base);
  } catch (err) {
    handleSpawnError(err, binary);
    return undefined;
  }

  try {
    return format === "sarif" ? parseSarif(stdout) : parseJson(stdout);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    output.appendLine(`Failed to parse ${format} output: ${msg}`);
    output.appendLine(stdout.slice(0, 2000));
    vscode.window.showErrorMessage(
      `Trishul: could not parse the scanner output (${format}). See the Trishul output channel for details.`
    );
    return undefined;
  }
}

/** Spawn the binary (no shell) and resolve with stdout. */
function exec(binary: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { cwd, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", (err) => reject(err));
    child.on("close", (code) => {
      if (stderr.trim()) {
        output.appendLine(stderr.trim());
      }
      // Trishul exits non-zero when findings exceed a threshold; that is not a
      // failure for us as long as it produced parseable output. Only reject
      // when there is no output at all to work with.
      if (code !== 0 && stdout.trim() === "") {
        reject(
          new Error(
            `trishul exited with code ${code}${
              stderr.trim() ? `: ${stderr.trim()}` : ""
            }`
          )
        );
        return;
      }
      resolve(stdout);
    });
  });
}

/** Friendly handling for the binary-missing (ENOENT) and related cases. */
function handleSpawnError(err: unknown, binary: string): void {
  const code = (err as NodeJS.ErrnoException)?.code;
  const message = err instanceof Error ? err.message : String(err);
  output.appendLine(`Error running trishul: ${message}`);

  if (code === "ENOENT") {
    const openDocs = "Install docs";
    const openSettings = "Set path";
    void vscode.window
      .showErrorMessage(
        `Trishul binary not found (looked for "${binary}"). Install Trishul, or set "trishul.path" to its location.`,
        openDocs,
        openSettings
      )
      .then((choice) => {
        if (choice === openDocs) {
          // User-initiated: opens the public docs page in their browser.
          void vscode.env.openExternal(vscode.Uri.parse(INSTALL_DOCS_URL));
        } else if (choice === openSettings) {
          void vscode.commands.executeCommand(
            "workbench.action.openSettings",
            "trishul.path"
          );
        }
      });
    return;
  }

  vscode.window.showErrorMessage(`Trishul: failed to run scanner — ${message}`);
}

/** Map a SARIF result level to a VS Code diagnostic severity. */
function levelToSeverity(level: string): vscode.DiagnosticSeverity {
  switch ((level || "").toLowerCase()) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "note":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/** Map a Trishul/JSON severity string to a VS Code diagnostic severity. */
function severityStringToSeverity(sev: string): vscode.DiagnosticSeverity {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    case "LOW":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/** Parse SARIF 2.1.0 output into normalized findings. */
function parseSarif(raw: string): Finding[] {
  const doc = parseJsonLoose(raw) as SarifLog;
  const findings: Finding[] = [];
  for (const run of doc.runs ?? []) {
    for (const res of run.results ?? []) {
      const loc = res.locations?.[0]?.physicalLocation;
      const region = loc?.region;
      findings.push({
        file: loc?.artifactLocation?.uri ?? "",
        line: region?.startLine ?? 0,
        column: region?.startColumn ?? 0,
        endLine: region?.endLine ?? region?.startLine ?? 0,
        endColumn: region?.endColumn ?? 0,
        severity: levelToSeverity(res.level ?? "warning"),
        ruleId: res.ruleId ?? "",
        message: res.message?.text ?? res.ruleId ?? "Trishul finding",
      });
    }
  }
  return findings;
}

/**
 * Parse Trishul's native JSON best-effort. Handles either a flat array of
 * finding objects or an object whose values are arrays of findings. Each
 * finding may use file/path and line/startLine field names.
 */
function parseJson(raw: string): Finding[] {
  const doc = parseJsonLoose(raw);
  const out: Finding[] = [];
  const collect = (items: unknown[]): void => {
    for (const item of items) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const m = item as Record<string, unknown>;
      const file = str(m.file ?? m.path ?? m.filename);
      if (!file) {
        continue;
      }
      out.push({
        file,
        line: num(m.line ?? m.startLine ?? m.start_line),
        column: num(m.column ?? m.startColumn ?? m.start_col),
        endLine: num(m.endLine ?? m.end_line ?? m.line ?? m.startLine),
        endColumn: num(m.endColumn ?? m.end_col),
        severity: severityStringToSeverity(str(m.severity)),
        ruleId: str(m.rule_id ?? m.ruleId ?? m.check_id ?? m.id),
        message: str(m.message ?? m.title) || str(m.rule_id) || "Trishul finding",
      });
    }
  };
  if (Array.isArray(doc)) {
    collect(doc);
  } else if (doc && typeof doc === "object") {
    for (const value of Object.values(doc as Record<string, unknown>)) {
      if (Array.isArray(value)) {
        collect(value);
      }
    }
  }
  return out;
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function num(v: unknown): number {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v;
  }
  if (typeof v === "string") {
    const n = parseInt(v, 10);
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}

/**
 * JSON.parse that tolerates leading/trailing non-JSON noise (e.g. a banner
 * line printed before the document) by falling back to the widest { } or [ ]
 * slice.
 */
function parseJsonLoose(raw: string): unknown {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    const firstObj = trimmed.indexOf("{");
    const firstArr = trimmed.indexOf("[");
    let start = -1;
    let end = -1;
    if (firstObj === -1 && firstArr === -1) {
      throw new Error("no JSON object or array found in output");
    }
    if (firstArr === -1 || (firstObj !== -1 && firstObj < firstArr)) {
      start = firstObj;
      end = trimmed.lastIndexOf("}");
    } else {
      start = firstArr;
      end = trimmed.lastIndexOf("]");
    }
    if (start === -1 || end === -1 || end <= start) {
      throw new Error("could not isolate a JSON document in output");
    }
    return JSON.parse(trimmed.slice(start, end + 1));
  }
}

/**
 * Turn findings into diagnostics grouped by file URI and publish them. When
 * singleFile is set, findings whose file does not resolve to it are ignored, so
 * a single-file scan never writes diagnostics onto unrelated files.
 */
function applyDiagnostics(
  findings: Finding[],
  base: string,
  replaceAll: boolean,
  singleFile?: vscode.Uri
): void {
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    if (!f.file) {
      continue;
    }
    const absolute = path.isAbsolute(f.file)
      ? f.file
      : path.join(base, f.file);
    const uri = vscode.Uri.file(absolute);
    if (singleFile && uri.fsPath !== singleFile.fsPath) {
      continue;
    }
    const startLine = Math.max(0, f.line - 1);
    const startCol = Math.max(0, f.column - 1);
    const endLine = Math.max(startLine, (f.endLine || f.line) - 1);
    const endCol = f.endColumn > 0 ? f.endColumn - 1 : startCol + 1;
    const range = new vscode.Range(startLine, startCol, endLine, endCol);

    const diag = new vscode.Diagnostic(range, f.message, f.severity);
    diag.source = "trishul";
    if (f.ruleId) {
      diag.code = f.ruleId;
    }
    const list = byFile.get(uri.fsPath) ?? [];
    list.push(diag);
    byFile.set(uri.fsPath, list);
  }

  if (replaceAll) {
    diagnostics.clear();
  }
  for (const [fsPath, diags] of byFile) {
    diagnostics.set(vscode.Uri.file(fsPath), diags);
  }
}

// ---- Minimal SARIF shape (only the fields we read) ----
interface SarifLog {
  runs?: SarifRun[];
}
interface SarifRun {
  results?: SarifResult[];
}
interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: {
        startLine?: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }>;
}
