import * as fs from "fs";
import * as path from "path";
import type { ASTNode } from "../types";
import { parseSolidity, visit } from "./parser";

export interface ParsedSolidityFile {
  filePath: string;
  absolutePath: string;
  source: string;
  ast: ASTNode;
}

export interface ImportGraph {
  files: Map<string, ParsedSolidityFile>;
  /** Resolved absolute path -> list of imported absolute paths */
  edges: Map<string, string[]>;
  topologicalOrder: string[];
  warnings: string[];
}

export interface ContractInfo {
  name: string;
  filePath: string;
  node: ASTNode;
  baseNames: string[];
}

export interface MergedMember {
  kind: "function" | "modifier" | "stateVariable";
  name: string;
  node: ASTNode;
  definedIn: string;
  source: string;
}

export interface MergedContractView {
  name: string;
  file: string;
  source: string;
  node: ASTNode;
  ancestors: ContractInfo[];
  members: MergedMember[];
  importPath: string[];
}

interface ImportRecord {
  resolvedPath: string;
  symbolNames: string[];
}

/**
 * Parse Solidity files and build a dependency graph from import statements.
 * Automatically includes locally resolvable imports discovered on disk.
 */
export function buildImportGraph(filePaths: string[]): ImportGraph {
  const files = new Map<string, ParsedSolidityFile>();
  const edges = new Map<string, string[]>();
  const warnings: string[] = [];
  const queue = [...new Set(filePaths.map((f) => path.resolve(f)))];

  while (queue.length > 0) {
    const absolutePath = queue.shift()!;
    if (files.has(absolutePath)) continue;

    if (!fs.existsSync(absolutePath)) {
      warnings.push(`Could not read file: ${absolutePath}`);
      continue;
    }

    let source: string;
    try {
      source = fs.readFileSync(absolutePath, "utf-8");
    } catch {
      warnings.push(`Could not read file: ${absolutePath}`);
      continue;
    }

    const { ast, error } = parseSolidity(source, absolutePath);
    if (!ast) {
      warnings.push(error ?? `Parse error in ${absolutePath}`);
      continue;
    }

    const parsed: ParsedSolidityFile = {
      filePath: filePaths.find((f) => path.resolve(f) === absolutePath) ?? absolutePath,
      absolutePath,
      source,
      ast,
    };

    files.set(absolutePath, parsed);
    edges.set(absolutePath, []);

    const imports = extractImports(ast, absolutePath, files, warnings);
    for (const imp of imports) {
      if (imp.resolvedPath && !files.has(imp.resolvedPath)) {
        queue.push(imp.resolvedPath);
      }
    }
  }

  for (const [absolutePath, parsed] of files) {
    const imports = extractImports(parsed.ast, parsed.absolutePath, files, warnings);
    const resolved = imports.map((i) => i.resolvedPath).filter(Boolean);
    edges.set(absolutePath, [...new Set(resolved)]);
  }

  const { order, cycleWarning } = topologicalSort(edges);
  if (cycleWarning) {
    warnings.push(cycleWarning);
  }

  return { files, edges, topologicalOrder: order, warnings };
}

function extractImports(
  ast: ASTNode,
  fromFile: string,
  knownFiles: Map<string, ParsedSolidityFile>,
  warnings: string[]
): ImportRecord[] {
  const records: ImportRecord[] = [];

  visit(ast, {
    ImportDirective(node: ASTNode) {
      const imp = node as {
        path?: string;
        symbolAliases?: Array<{ foreign?: { name?: string } }>;
        symbolAliasesIdentifiers?: Array<{ foreign?: { name?: string } }>;
      };

      const importPath = imp.path ?? "";
      const symbolNames =
        imp.symbolAliases?.map((a) => a.foreign?.name).filter(Boolean) as string[] ??
        imp.symbolAliasesIdentifiers
          ?.map((a) => a.foreign?.name)
          .filter(Boolean) as string[] ??
        [];

      const resolvedPath = resolveImportPath(importPath, fromFile, knownFiles);
      if (!resolvedPath) {
        if (importPath.startsWith(".") || importPath.startsWith("/")) {
          warnings.push(
            `Could not resolve import "${importPath}" from ${fromFile}`
          );
        }
        return;
      }

      records.push({ resolvedPath, symbolNames });
    },
  });

  return records;
}

/**
 * Resolve relative, absolute, and node_modules import paths.
 */
export function resolveImportPath(
  importPath: string,
  fromFile: string,
  knownFiles: Map<string, ParsedSolidityFile>
): string | null {
  const candidates: string[] = [];

  if (importPath.startsWith(".")) {
    candidates.push(path.resolve(path.dirname(fromFile), importPath));
  } else if (path.isAbsolute(importPath)) {
    candidates.push(importPath);
  } else {
    const fromDir = path.dirname(fromFile);
    candidates.push(
      path.resolve(fromDir, importPath),
      path.resolve(fromDir, "node_modules", importPath),
      path.resolve(process.cwd(), "node_modules", importPath)
    );

    // Walk up directory tree looking for node_modules
    let dir = fromDir;
    for (let i = 0; i < 6; i++) {
      candidates.push(path.resolve(dir, "node_modules", importPath));
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }

  for (const candidate of candidates) {
    const normalized = normalizeSolPath(candidate);
    if (knownFiles.has(normalized)) return normalized;
    if (fs.existsSync(normalized)) return normalized;
  }

  return null;
}

function normalizeSolPath(filePath: string): string {
  const resolved = path.resolve(filePath);
  return resolved.endsWith(".sol") ? resolved : `${resolved}.sol`;
}

function topologicalSort(edges: Map<string, string[]>): {
  order: string[];
  cycleWarning?: string;
} {
  const inDegree = new Map<string, number>();
  const adj = new Map<string, string[]>();

  for (const node of edges.keys()) {
    inDegree.set(node, 0);
    adj.set(node, []);
  }

  for (const [from, imports] of edges) {
    for (const to of imports) {
      if (!inDegree.has(to)) {
        inDegree.set(to, 0);
        adj.set(to, []);
      }
      adj.get(to)!.push(from);
      inDegree.set(from, (inDegree.get(from) ?? 0) + 1);
    }
  }

  const queue = [...inDegree.entries()]
    .filter(([, deg]) => deg === 0)
    .map(([node]) => node);
  const order: string[] = [];

  while (queue.length > 0) {
    const node = queue.shift()!;
    order.push(node);

    for (const dependent of adj.get(node) ?? []) {
      const next = (inDegree.get(dependent) ?? 0) - 1;
      inDegree.set(dependent, next);
      if (next === 0) queue.push(dependent);
    }
  }

  if (order.length !== inDegree.size) {
    const remaining = [...inDegree.entries()]
      .filter(([, deg]) => deg > 0)
      .map(([node]) => path.basename(node));
    return {
      order,
      cycleWarning: `Circular import detected among: ${remaining.join(", ")}. Analysis may be incomplete.`,
    };
  }

  return { order };
}

/**
 * Index all contract definitions across parsed files.
 */
export function indexContracts(graph: ImportGraph): Map<string, ContractInfo> {
  const index = new Map<string, ContractInfo>();

  for (const parsed of graph.files.values()) {
    visit(parsed.ast, {
      ContractDefinition(node: ASTNode) {
        const contract = node as {
          name?: string;
          baseContracts?: Array<{
            baseName?: { namePath?: string; name?: string };
          }>;
        };
        if (!contract.name) return;

        const baseNames =
          contract.baseContracts?.map(
            (b) => b.baseName?.namePath ?? b.baseName?.name ?? ""
          ).filter(Boolean) ?? [];

        index.set(contract.name, {
          name: contract.name,
          filePath: parsed.absolutePath,
          node,
          baseNames,
        });
      },
    });
  }

  return index;
}

/**
 * Collect import chain from child file to ancestor file (if reachable).
 */
function resolveImportChain(
  fromFile: string,
  toFile: string,
  edges: Map<string, string[]>
): string[] {
  if (fromFile === toFile) return [fromFile];

  const queue: Array<{ file: string; chain: string[] }> = [{ file: fromFile, chain: [fromFile] }];
  const visited = new Set<string>([fromFile]);

  while (queue.length > 0) {
    const { file, chain } = queue.shift()!;
    for (const imported of edges.get(file) ?? []) {
      if (visited.has(imported)) continue;
      const nextChain = [...chain, imported];
      if (imported === toFile) return nextChain;
      visited.add(imported);
      queue.push({ file: imported, chain: nextChain });
    }
  }

  return [fromFile, toFile];
}

function extractMembers(parsed: ParsedSolidityFile, contractNode: ASTNode): MergedMember[] {
  const members: MergedMember[] = [];

  visit(contractNode, {
    FunctionDefinition(node: ASTNode) {
      const fn = node as { name?: string; isConstructor?: boolean };
      if (fn.isConstructor) return;
      members.push({
        kind: "function",
        name: fn.name ?? "",
        node,
        definedIn: parsed.absolutePath,
        source: parsed.source,
      });
    },
    ModifierDefinition(node: ASTNode) {
      const mod = node as { name?: string };
      members.push({
        kind: "modifier",
        name: mod.name ?? "",
        node,
        definedIn: parsed.absolutePath,
        source: parsed.source,
      });
    },
    StateVariableDeclaration(node: ASTNode) {
      const decl = node as { variables?: Array<{ name?: string }> };
      for (const v of decl.variables ?? []) {
        if (!v.name) continue;
        members.push({
          kind: "stateVariable",
          name: v.name,
          node,
          definedIn: parsed.absolutePath,
          source: parsed.source,
        });
      }
    },
  });

  return members;
}

/**
 * Resolve inheritance chain and merge ancestor contract members.
 */
export function buildMergedContractViews(graph: ImportGraph): MergedContractView[] {
  const contractIndex = indexContracts(graph);
  const views: MergedContractView[] = [];

  for (const parsed of graph.files.values()) {
    visit(parsed.ast, {
      ContractDefinition(node: ASTNode) {
        const contract = node as {
          name?: string;
          baseContracts?: Array<{
            baseName?: { namePath?: string; name?: string };
          }>;
        };
        if (!contract.name) return;

        const ancestors: ContractInfo[] = [];
        const seen = new Set<string>();
        const queue = [...(contractIndex.get(contract.name)?.baseNames ?? [])];

        while (queue.length > 0) {
          const baseName = queue.shift()!;
          if (seen.has(baseName)) continue;
          seen.add(baseName);

          const info = contractIndex.get(baseName);
          if (!info) continue;

          ancestors.push(info);
          queue.push(...info.baseNames);
        }

        const members: MergedMember[] = extractMembers(parsed, node);
        let importPath: string[] = [parsed.absolutePath];

        for (const ancestor of ancestors) {
          const ancestorParsed = graph.files.get(ancestor.filePath);
          if (!ancestorParsed) continue;

          members.push(...extractMembers(ancestorParsed, ancestor.node));

          const chain = resolveImportChain(
            parsed.absolutePath,
            ancestor.filePath,
            graph.edges
          );
          if (chain.length > importPath.length) {
            importPath = chain;
          }
        }

        views.push({
          name: contract.name!,
          file: parsed.absolutePath,
          source: parsed.source,
          node,
          ancestors,
          members,
          importPath,
        });
      },
    });
  }

  return views;
}

/**
 * Returns true if any parsed file contains import directives.
 */
export function hasImportDirectives(graph: ImportGraph): boolean {
  for (const parsed of graph.files.values()) {
    let found = false;
    visit(parsed.ast, {
      ImportDirective() {
        found = true;
      },
    });
    if (found) return true;
  }
  return false;
}
