import * as fs from "fs";
import * as path from "path";
import type { ChainProofPlugin, PluginRule } from "./types";

/**
 * Load a single plugin from an npm package name or file path.
 *
 * Supports:
 * - npm packages: `"@myteam/chainproof-rules"`
 * - relative paths: `"./local-rules/my-plugin.js"`
 * - absolute paths: `"/full/path/to/plugin.js"`
 *
 * @param specifier - npm package name or file path to the plugin
 * @param cwd - Base directory for resolving relative paths (defaults to `process.cwd()`)
 * @returns The loaded {@link ChainProofPlugin}, or `null` if it failed to load (non-fatal)
 *
 * @example
 * ```typescript
 * import { loadPlugin } from '@chainproof/core';
 *
 * const plugin = loadPlugin('@myteam/chainproof-rules');
 * if (plugin) {
 *   console.log(`Loaded ${plugin.rules.length} rules from ${plugin.name}`);
 * }
 * ```
 */
export function loadPlugin(
  specifier: string,
  cwd: string = process.cwd(),
): ChainProofPlugin | null {
  try {
    let modulePath: string;

    // Determine if this is a file path or npm package
    if (specifier.startsWith(".") || specifier.startsWith("/")) {
      // File path
      modulePath = path.isAbsolute(specifier)
        ? specifier
        : path.resolve(cwd, specifier);

      if (!fs.existsSync(modulePath)) {
        console.warn(`[ChainProof] Plugin not found: ${modulePath}`);
        return null;
      }
    } else {
      // Try npm package first, then fallback to relative path
      try {
        modulePath = require.resolve(specifier, {
          paths: [cwd, process.cwd()],
        });
      } catch (e) {
        // Try as a relative file path
        const asFile = path.resolve(cwd, specifier);
        if (fs.existsSync(asFile)) {
          modulePath = asFile;
        } else {
          console.warn(`[ChainProof] Could not resolve plugin: ${specifier}`);
          return null;
        }
      }
    }

    // Load and validate the plugin
    const plugin = require(modulePath);
    const loaded = plugin.default || plugin;

    if (!isValidPlugin(loaded)) {
      console.warn(
        `[ChainProof] Plugin at ${specifier} does not export a valid ChainProofPlugin. ` +
          `Expected { name, version, rules }. Got: ${JSON.stringify(Object.keys(loaded))}`,
      );
      return null;
    }

    return loaded;
  } catch (error) {
    console.warn(
      `[ChainProof] Failed to load plugin "${specifier}": ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return null;
  }
}

/**
 * Load multiple plugins, returning only the ones that loaded successfully.
 *
 * Failed plugins are silently skipped with a console warning so a single
 * bad plugin cannot break the entire scan.
 *
 * @param specifiers - Array of npm package names or file paths
 * @param cwd - Base directory for resolving relative paths
 * @returns Array of successfully loaded {@link ChainProofPlugin} instances
 *
 * @example
 * ```typescript
 * import { loadPlugins, scan } from '@chainproof/core';
 *
 * const plugins = loadPlugins(['@myteam/chainproof-rules', './custom-rules.js']);
 * const result = await scan({ targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false, plugins });
 * ```
 */
export function loadPlugins(
  specifiers: string[],
  cwd?: string,
): ChainProofPlugin[] {
  return specifiers
    .map((spec) => loadPlugin(spec, cwd))
    .filter((plugin): plugin is ChainProofPlugin => plugin !== null);
}

/**
 * Validate that an object is a valid ChainProofPlugin.
 */
function isValidPlugin(obj: unknown): obj is ChainProofPlugin {
  if (typeof obj !== "object" || obj === null) return false;

  const p = obj as Record<string, unknown>;
  return (
    typeof p.name === "string" &&
    typeof p.version === "string" &&
    Array.isArray(p.rules) &&
    p.rules.every(isValidRule)
  );
}

/**
 * Validate that an object is a valid PluginRule.
 */
function isValidRule(obj: unknown): obj is PluginRule {
  if (typeof obj !== "object" || obj === null) return false;

  const r = obj as Record<string, unknown>;
  return (
    typeof r.id === "string" &&
    typeof r.title === "string" &&
    typeof r.severity === "string" &&
    typeof r.description === "string" &&
    typeof r.detect === "function"
  );
}
