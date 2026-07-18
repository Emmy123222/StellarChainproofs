import * as fs from "fs";
import * as path from "path";
import { loadPlugins } from "./plugins";
import type { ScanConfig, ChainProofPlugin } from "./types";

export interface ChainProofConfig {
  plugins?: string[];
  [key: string]: unknown;
}

/**
 * Load `.chainproofrc.json` from the given directory or any parent directory
 * (up to 5 levels).
 *
 * @param startDir - Directory to start searching from (defaults to `process.cwd()`)
 * @returns The parsed config object, or `null` if no config file was found
 *
 * @example
 * ```typescript
 * import { loadConfigFile, mergePluginsFromConfig, scan } from '@chainproof/core';
 *
 * const configFile = loadConfigFile();
 * const config = mergePluginsFromConfig(
 *   { targets: ['contracts/'], useSlither: false, useLLM: false, useMetrics: false },
 *   configFile,
 * );
 * const result = await scan(config);
 * ```
 */
export function loadConfigFile(
  startDir: string = process.cwd(),
): ChainProofConfig | null {
  let dir = path.resolve(startDir);

  // Search up to 5 levels up the directory tree
  for (let i = 0; i < 5; i++) {
    const configPath = path.join(dir, ".chainproofrc.json");

    if (fs.existsSync(configPath)) {
      try {
        const content = fs.readFileSync(configPath, "utf-8");
        return JSON.parse(content);
      } catch (error) {
        console.warn(`[ChainProof] Failed to parse ${configPath}: ${error}`);
        return null;
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) break; // reached root
    dir = parent;
  }

  return null;
}

/**
 * Merges plugins discovered from a `.chainproofrc.json` config file into a
 * {@link ScanConfig}.
 *
 * Plugins already set on `config.plugins` take precedence over file-level plugins.
 *
 * @param config - Base scan configuration
 * @param configFile - Config object loaded by {@link loadConfigFile}, or `null`
 * @returns A new {@link ScanConfig} with plugins merged in
 */
export function mergePluginsFromConfig(
  config: ScanConfig,
  configFile?: ChainProofConfig | null,
): ScanConfig {
  if (!configFile?.plugins || config.plugins) {
    // config.plugins already set or no file plugins
    return config;
  }

  const filePlugins = loadPlugins(configFile.plugins);
  return {
    ...config,
    plugins: filePlugins,
  };
}
