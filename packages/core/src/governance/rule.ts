import type { ASTNode, Finding } from "../types";
import { analyzeGovernanceSource } from "./api";

const GOVERNANCE_PREFILTER =
  /\b(?:Governor|TimelockController|proposalThreshold|proposalSnapshot|votingDelay|votingPeriod|castVote|getPastVotes|getPriorVotes|quorum|scheduleBatch|hashOperation|predecessor|guardian|emergencyCouncil|execTransaction|checkSignatures|processedMessages|receiveMessage)\b/;

/** Integrates the specialized governance engine into the ordinary ChainProof scan. */
export function detectGovernanceSafety(
  _ast: ASTNode,
  source: string,
  filePath: string,
): Finding[] {
  // Most contracts are unrelated. Avoid a second parse/model pass unless strong governance signals exist.
  if (!GOVERNANCE_PREFILTER.test(stripCommentsAndStrings(source))) return [];
  const report = analyzeGovernanceSource(source, filePath);
  return report.files.flatMap((file) => file.findings.map((finding): Finding => ({
    id: finding.ruleId,
    title: finding.title,
    description: finding.description,
    recommendation: finding.recommendation,
    severity: finding.severity,
    file: finding.location.file,
    line: finding.location.line,
    ...(finding.location.lineEnd ? { lineEnd: finding.location.lineEnd } : {}),
    evidence: finding.evidence.map((evidence) => ({
      description: evidence.description,
      file: evidence.location.file,
      line: evidence.location.line,
    })),
    assumptions: finding.assumptions,
    confidence: finding.confidence,
  })));
}

function stripCommentsAndStrings(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n\r]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, " ");
}
