import type { Severity } from "@chainproof/core";

export interface ChainProofUserConfig {
  /** Paths to .sol files or directories (relative to Hardhat project root) */
  targets?: string[];
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Run Slither if installed */
  useSlither?: boolean;
  /** Send findings to LLM for explanation */
  useLLM?: boolean;
  /** Anthropic API key (defaults to ANTHROPIC_API_KEY env var) */
  apiKey?: string;
  /** Scan automatically after `npx hardhat compile` */
  runOnCompile?: boolean;
  /** Fail the compile step when critical/high findings are detected */
  failOnCompile?: boolean;
}

declare module "hardhat/types/config" {
  interface HardhatUserConfig {
    chainproof?: ChainProofUserConfig;
  }

  interface HardhatConfig {
    chainproof: ChainProofUserConfig;
  }
}

declare module "hardhat/types/runtime" {
  interface HardhatRuntimeEnvironment {
    chainproof: {
      lastResult?: import("@chainproof/core").ScanResult;
    };
  }
}

export {};
