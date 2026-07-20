import { Router, Request, Response } from "express";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { scan } from "@chainproof/core";
import type { ScanConfig, Severity } from "@chainproof/core";

const router = Router();

// ─── Types ────────────────────────────────────────────────────────────────────

interface InlineFile {
  path: string;
  content: string;
}

interface ScanRequestBody {
  files?: InlineFile[];
  config?: {
    useLLM?: boolean;
    useSlither?: boolean;
    useMetrics?: boolean;
    minSeverity?: Severity;
    apiKey?: string;
    llmProvider?: string;
    llmModel?: string;
  };
}

interface FileScanRequestBody {
  path: string;
  config?: ScanRequestBody["config"];
}

// ─── POST /scan ───────────────────────────────────────────────────────────────

/**
 * POST /scan
 *
 * Accepts Solidity file contents inline and returns a full ScanResult.
 *
 * Request body:
 * {
 *   "files": [{ "path": "contracts/Vault.sol", "content": "pragma solidity ..." }],
 *   "config": { "useLLM": false, "minSeverity": "medium" }
 * }
 */
router.post("/", async (req: Request, res: Response): Promise<void> => {
  const body = req.body as ScanRequestBody;

  if (!body.files || !Array.isArray(body.files) || body.files.length === 0) {
    res.status(400).json({
      error: "Missing required field: files (array of { path, content })",
    });
    return;
  }

  // Validate each file entry
  for (const f of body.files) {
    if (typeof f.path !== "string" || typeof f.content !== "string") {
      res.status(400).json({
        error: 'Each file entry must have string fields "path" and "content"',
      });
      return;
    }
  }

  // Write inline files to a temp directory so the core scanner can read them
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "chainproof-"));
  const tmpPaths: string[] = [];

  try {
    for (const f of body.files) {
      // Sanitize: only allow relative paths to prevent directory traversal
      const safeName = path.basename(f.path);
      const tmpPath = path.join(tmpDir, safeName);
      fs.writeFileSync(tmpPath, f.content, "utf-8");
      tmpPaths.push(tmpPath);
    }

    const cfg = body.config ?? {};
    const config: ScanConfig = {
      targets: tmpPaths,
      useSlither: cfg.useSlither ?? false,
      useLLM: cfg.useLLM ?? false,
      useMetrics: cfg.useMetrics ?? true,
      minSeverity: cfg.minSeverity ?? "low",
      apiKey: cfg.apiKey ?? process.env.ANTHROPIC_API_KEY,
      llmProvider: cfg.llmProvider,
      llmModel: cfg.llmModel,
    };

    const result = await scan(config);

    // Remap temp file paths back to original user-supplied paths
    for (const fileResult of result.files) {
      const idx = tmpPaths.findIndex((p) => p === fileResult.file);
      if (idx !== -1 && body.files) {
        fileResult.file = body.files[idx].path;
        fileResult.findings.forEach((finding) => {
          finding.file = body.files![idx].path;
        });
        fileResult.gasHints.forEach((hint) => {
          hint.file = body.files![idx].path;
        });
      }
    }

    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: `Scan failed: ${message}` });
  } finally {
    // Always clean up temp files
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
});

// ─── POST /scan/file ──────────────────────────────────────────────────────────

/**
 * POST /scan/file
 *
 * Scans a file path on the server filesystem.
 * Only available when the server is started with --allow-fs flag.
 *
 * Request body:
 * { "path": "/workspace/contracts/Vault.sol", "config": { ... } }
 */
router.post("/file", async (req: Request, res: Response): Promise<void> => {
  if (!process.env.CHAINPROOF_ALLOW_FS) {
    res.status(403).json({
      error:
        "Filesystem access is disabled. Start the server with --allow-fs to enable POST /scan/file.",
    });
    return;
  }

  const body = req.body as FileScanRequestBody;

  if (!body.path || typeof body.path !== "string") {
    res.status(400).json({ error: 'Missing required field: "path" (string)' });
    return;
  }

  // Security: resolve and validate the path doesn't escape allowed roots
  const resolvedPath = path.resolve(body.path);
  if (!fs.existsSync(resolvedPath)) {
    res.status(404).json({ error: `File not found: ${body.path}` });
    return;
  }

  const stat = fs.statSync(resolvedPath);
  if (!stat.isFile() && !stat.isDirectory()) {
    res.status(400).json({ error: "Path must be a file or directory" });
    return;
  }

  try {
    const cfg = body.config ?? {};
    const config: ScanConfig = {
      targets: [resolvedPath],
      useSlither: cfg.useSlither ?? false,
      useLLM: cfg.useLLM ?? false,
      useMetrics: cfg.useMetrics ?? true,
      minSeverity: cfg.minSeverity ?? "low",
      apiKey: cfg.apiKey ?? process.env.ANTHROPIC_API_KEY,
      llmProvider: cfg.llmProvider,
      llmModel: cfg.llmModel,
    };


    const result = await scan(config);
    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: `Scan failed: ${message}` });
  }
});

export default router;
