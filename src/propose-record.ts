import { extractSymbolsFromText } from "./extract-symbols.js";
import { findFixCommitUrl, findNpmPackages, type OsvRecord } from "./osv.js";
import {
  Confidence,
  ECOSYSTEM_NPM,
  EvidenceSource,
  type AffectedPackage,
  type Evidence,
  type SymbolRecord,
} from "./types.js";

/** OSV id prefix used for malicious-package reports. */
const MALICIOUS_ADVISORY_PREFIX = "MAL-";

/**
 * Phrases identifying a malicious package reported under a GHSA id rather than
 * a MAL- one. The prefix check alone misses these, and their prose describes
 * what the malware calls ("uses randomBytes", "runs eval"), which reads as a
 * list of vulnerable exports when it is nothing of the sort.
 */
const MALICIOUS_PROSE_PATTERN =
  /\b(?:malicious code|contains? malware|is malicious|embedded malware|malicious functionality|steals?|exfiltrat)/i;

/**
 * Turns one OSV advisory into a proposed symbol record.
 *
 * Returns null whenever the advisory cannot be reduced to a confident claim.
 * Proposing nothing is always correct here: a missing record leaves a finding
 * in the queue, whereas a wrong one silently suppresses a real vulnerability.
 */
export function proposeRecord(record: OsvRecord): SymbolRecord | null {
  if (record.withdrawn !== undefined) {
    return null;
  }

  // Malicious-package advisories are categorically out of scope. They say the
  // whole package is hostile, not that one export is faulty, so the remedy is
  // removal and reachability is meaningless. Their prose also describes
  // attacker behaviour ("uses child_process"), which reads as symbol names.
  if (record.id.startsWith(MALICIOUS_ADVISORY_PREFIX)) {
    return null;
  }

  const packageNames = findNpmPackages(record);
  if (packageNames.length === 0) {
    return null;
  }

  const prose = [record.summary, record.details].filter(text => text !== undefined).join(". ");
  if (MALICIOUS_PROSE_PATTERN.test(prose)) {
    return null;
  }

  const extraction = extractSymbolsFromText(prose);
  if (extraction.symbols.length === 0) {
    return null;
  }

  // A candidate equal to an affected package name is the package being named
  // in prose, not one of its exports.
  const packageNameSet = new Set(packageNames.map(name => name.toLowerCase()));
  const symbols = extraction.symbols.filter(
    symbol => !packageNameSet.has(symbol.toLowerCase()),
  );
  if (symbols.length === 0) {
    return null;
  }

  const affected: AffectedPackage[] = packageNames.map(name => ({
    package: { ecosystem: ECOSYSTEM_NPM, name },
    symbols,
  }));

  return {
    id: record.id,
    aliases: [...(record.aliases ?? [])],
    affected,
    evidence: buildEvidence(record, extraction.excerpt),
  };
}

/**
 * Records where the symbols came from.
 *
 * Prose alone is Medium: the advisory naming a function is good evidence, but
 * it is one unverified source. High is reserved for the case where a fix-commit
 * diff independently agrees, which the extraction pipeline does not yet do.
 */
function buildEvidence(record: OsvRecord, excerpt?: string): Evidence {
  const fixCommit = findFixCommitUrl(record);
  return {
    source: EvidenceSource.AdvisoryText,
    confidence: Confidence.Medium,
    ...(fixCommit !== null ? { fixCommit } : {}),
    ...(excerpt !== undefined ? { excerpt } : {}),
  };
}
