import * as path from "path";
import type { HardhatRuntimeEnvironment } from "hardhat/types";
import type { ScanConfig, Severity } from "@chainproof/core";
import type { ChainProofUserConfig } from "./type-extensions";

export interface ResolvedChainProofConfig {
  targets: string[];
  minSeverity: Severity;
  useSlither: boolean;
  useLLM: boolean;
  apiKey?: string;
  runOnCompile: boolean;
  failOnCompile: boolean;
}

const DEFAULTS: Required<
  Pick<
    ChainProofUserConfig,
    "targets" | "minSeverity" | "useSlither" | "useLLM" | "runOnCompile" | "failOnCompile"
  >
> = {
  targets: ["contracts/"],
  minSeverity: "high",
  useSlither: true,
  useLLM: false,
  runOnCompile: false,
  failOnCompile: false,
};

export function resolveChainProofConfig(
  hre: HardhatRuntimeEnvironment
): ResolvedChainProofConfig {
  const user = hre.config.chainproof ?? {};

  return {
    targets: (user.targets ?? DEFAULTS.targets).map((target) =>
      path.isAbsolute(target)
        ? target
        : path.join(hre.config.paths.root, target)
    ),
    minSeverity: user.minSeverity ?? DEFAULTS.minSeverity,
    useSlither: user.useSlither ?? DEFAULTS.useSlither,
    useLLM: user.useLLM ?? DEFAULTS.useLLM,
    apiKey: user.apiKey ?? process.env.ANTHROPIC_API_KEY,
    runOnCompile: user.runOnCompile ?? DEFAULTS.runOnCompile,
    failOnCompile: user.failOnCompile ?? DEFAULTS.failOnCompile,
  };
}

export function toScanConfig(
  resolved: ResolvedChainProofConfig,
  overrides?: Partial<ScanConfig>
): ScanConfig {
  return {
    targets: resolved.targets,
    useSlither: resolved.useSlither,
    useLLM: resolved.useLLM,
    useMetrics: false,
    apiKey: resolved.apiKey,
    minSeverity: resolved.minSeverity,
    ...overrides,
  };
}
