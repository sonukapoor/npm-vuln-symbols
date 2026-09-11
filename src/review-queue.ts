import { Confidence, type SymbolRecord } from "./types.js";

/**
 * Combines the two independent signals into one ordered worklist.
 *
 * Neither signal settles a record alone. The export check cannot see every way
 * a name becomes reachable, and corroboration cannot tell a genuine miss from a
 * diff that simply does not mention the symbol. Together they sort the work:
 * where both agree a reviewer skims, where they disagree a reviewer thinks.
 */

/** What the export checker concluded for one package. */
export const ExportVerdict = {
  Confirmed: "confirmed",
  NotFound: "not_found",
  Unknown: "unknown",
} as const;

export type ExportVerdict = (typeof ExportVerdict)[keyof typeof ExportVerdict];

/**
 * Review bands, ordered by how much of a reviewer's attention they repay.
 *
 * The ordering is deliberate. `LikelyWrong` comes before `LikelyRight` because
 * rejecting a bad record removes a hazard and yields a regression test, while
 * confirming a good one only moves it along.
 */
export const Band = {
  /** Both signals say the symbol is wrong. Reject, and add a test. */
  LikelyWrong: "likely_wrong",
  /** The signals disagree. This is where judgement is actually needed. */
  Conflicting: "conflicting",
  /** Both signals agree the symbol is right. Confirm and move on. */
  LikelyRight: "likely_right",
  /** One signal is positive, the other silent. Light check. */
  WeakSupport: "weak_support",
  /** Nothing is known either way. Research from scratch. */
  Unsupported: "unsupported",
} as const;

export type Band = (typeof Band)[keyof typeof Band];

/** Presentation order, cheapest and highest yield first. */
export const BAND_ORDER: readonly Band[] = [
  Band.LikelyWrong,
  Band.Conflicting,
  Band.LikelyRight,
  Band.WeakSupport,
  Band.Unsupported,
];

export interface QueueEntry {
  readonly id: string;
  readonly band: Band;
  readonly packages: readonly string[];
  readonly symbols: readonly string[];
  /** True when the fix commit diff referenced every named symbol. */
  readonly corroborated: boolean;
  readonly exportVerdict: ExportVerdict;
  readonly note: string;
}

/**
 * Reduces a record's per-package export verdicts to one.
 *
 * Confirmed anywhere wins: lodash's UMD bundle is unreadable while lodash-es
 * confirms the same symbols, and one sibling proving the export exists settles
 * it for the advisory.
 */
export function combineVerdicts(verdicts: readonly ExportVerdict[]): ExportVerdict {
  if (verdicts.includes(ExportVerdict.Confirmed)) {
    return ExportVerdict.Confirmed;
  }
  if (verdicts.includes(ExportVerdict.NotFound)) {
    return ExportVerdict.NotFound;
  }
  return ExportVerdict.Unknown;
}

interface BandInput {
  readonly corroborated: boolean;
  readonly hasFixCommit: boolean;
  readonly exportVerdict: ExportVerdict;
}

/** Places a record in a band, and explains why in one line. */
export function classify(input: BandInput): { band: Band; note: string } {
  const { corroborated, hasFixCommit, exportVerdict } = input;

  if (exportVerdict === ExportVerdict.NotFound) {
    if (hasFixCommit && !corroborated) {
      return {
        band: Band.LikelyWrong,
        note: "the package does not appear to export this, and the fix commit never mentions it",
      };
    }
    if (corroborated) {
      return {
        band: Band.Conflicting,
        note: "the fix commit mentions this symbol but the package does not appear to export it",
      };
    }
    return {
      band: Band.WeakSupport,
      note: "the package does not appear to export this, and there is no fix commit to check",
    };
  }

  if (exportVerdict === ExportVerdict.Confirmed) {
    if (corroborated) {
      return { band: Band.LikelyRight, note: "exported by the package and named in the fix commit" };
    }
    if (hasFixCommit) {
      return {
        band: Band.Conflicting,
        note: "exported by the package but the fix commit never mentions it",
      };
    }
    return { band: Band.WeakSupport, note: "exported by the package, no fix commit to check" };
  }

  if (corroborated) {
    return { band: Band.WeakSupport, note: "named in the fix commit, exports could not be read" };
  }
  return {
    band: Band.Unsupported,
    note: "exports could not be read and no fix commit corroborates it",
  };
}

/** Builds one queue entry from a record and its export verdicts. */
export function buildEntry(
  record: SymbolRecord,
  exportVerdicts: readonly ExportVerdict[],
): QueueEntry {
  const exportVerdict = combineVerdicts(exportVerdicts);
  const corroborated = record.evidence.confidence === Confidence.High;
  const hasFixCommit = record.evidence.fixCommit !== undefined;
  const { band, note } = classify({ corroborated, hasFixCommit, exportVerdict });
  return {
    id: record.id,
    band,
    packages: record.affected.map(entry => entry.package.name),
    symbols: [...new Set(record.affected.flatMap(entry => [...entry.symbols]))],
    corroborated,
    exportVerdict,
    note,
  };
}
