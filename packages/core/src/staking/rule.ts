import type { ASTNode, Finding } from "../types";
import { analyzeStakingSource } from "./api";

const STAKING_SOURCE_SIGNAL = /\b(?:stakingToken|stakeToken|totalStaked|rewardToken|rewardAsset|rewardRate|rewardPerToken|rewardPerShare|rewardIndex|globalIndex|userIndex|indexPaid|rewardDebt|accRewardPerShare|accumulatedRewardPer|userRewardPerTokenPaid|queuedRewards|periodFinish|rewardsDuration|emergencyWithdraw|notifyRewardAmount|vestingStart|vestingDuration|vestedAmount|cliff)\b/i;

/**
 * Scanner adapter for the production staking accounting engine.
 * The AST parameter preserves the built-in rule signature; the staking model
 * reparses with its own explicit resource budget and error isolation.
 */
export function detectStakingAccounting(
  _ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  // Avoid building a second specialized model for ordinary vault/token files.
  // The signal catalog is deliberately limited to fields that the model can
  // consume; generic words such as "reward" or "deposit" are not sufficient.
  if (!STAKING_SOURCE_SIGNAL.test(source)) return [];
  const report = analyzeStakingSource({ file: filePath, source });
  return report.files.flatMap((file) => file.findings.map((finding): Finding => ({
    id: finding.ruleId,
    title: finding.title,
    description: finding.description,
    recommendation: finding.recommendation,
    severity: finding.severity,
    file: finding.location.file,
    line: finding.location.line,
    lineEnd: finding.location.lineEnd,
    confidence: finding.confidence,
    assumptions: finding.assumptions,
    evidence: finding.evidence.map((evidence) => ({
      description: evidence.description + (evidence.snippet ? `: ${evidence.snippet}` : ""),
      file: evidence.location.file,
      line: evidence.location.line,
    })),
  })));
}
