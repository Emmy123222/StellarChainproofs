import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@chainproof/hardhat-plugin";

const config: HardhatUserConfig = {
  solidity: "0.8.20",
  chainproof: {
    targets: ["contracts/"],
    minSeverity: "high",
    useSlither: false,
    useLLM: false,
    runOnCompile: false,
    failOnCompile: false,
  },
};

export default config;
