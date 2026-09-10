import { buildCallPattern } from "./jelly-vulnerability.js";
import type { OsvAffectedEntry } from "./osv-ranges.js";
import type { SymbolRecord } from "./types.js";

/**
 * Pure logic behind the reachability probe, separated from process handling so
 * the interesting behaviour can be tested without invoking the analyzer.
 */

/** Distinguishes the two rungs measured in a single analysis run. */
export const PACKAGE_SUFFIX = "::pkg";
export const SYMBOL_SUFFIX = "::sym";

export interface JellyEntry {
  readonly osv: { id: string; affected: OsvAffectedEntry[] };
  readonly patterns: string[];
}

/**
 * Builds a package-level and a symbol-level entry for one advisory.
 *
 * Both are needed because the meaningful figure is not "how many findings
 * disappear" but "how many disappear that a package-level scan would have
 * kept". Measuring against the weaker baseline would flatter the result.
 */
export function buildEntries(
  record: SymbolRecord,
  affected: readonly OsvAffectedEntry[],
): JellyEntry[] {
  const names = new Set(record.affected.map(entry => entry.package.name));
  const relevant = affected.filter(entry => names.has(entry.package.name));
  if (relevant.length === 0) {
    return [];
  }
  const symbolPatterns = record.affected
    .filter(entry => names.has(entry.package.name) && entry.symbols.length > 0)
    .map(entry => buildCallPattern(entry.package.name, entry.symbols));
  if (symbolPatterns.length === 0) {
    return [];
  }
  return [
    {
      osv: { id: `${record.id}${PACKAGE_SUFFIX}`, affected: [...relevant] },
      patterns: relevant.map(entry => `import <${entry.package.name}>`),
    },
    { osv: { id: `${record.id}${SYMBOL_SUFFIX}`, affected: [...relevant] }, patterns: symbolPatterns },
  ];
}

export interface Tally {
  readonly imported: string[];
  readonly reachable: string[];
}

/** Splits Jelly's match output back into the two rungs. */
export function tally(matches: Record<string, readonly unknown[]>): Tally {
  const imported: string[] = [];
  const reachable: string[] = [];
  for (const [id, hits] of Object.entries(matches)) {
    if (hits.length === 0) {
      continue;
    }
    if (id.endsWith(PACKAGE_SUFFIX)) {
      imported.push(id.slice(0, -PACKAGE_SUFFIX.length));
    } else if (id.endsWith(SYMBOL_SUFFIX)) {
      reachable.push(id.slice(0, -SYMBOL_SUFFIX.length));
    }
  }
  return { imported: imported.sort(), reachable: reachable.sort() };
}

/**
 * Elimination rate relative to the package-level baseline.
 *
 * Returns 0 rather than dividing by zero when nothing was imported, since an
 * empty run has eliminated nothing rather than everything.
 */
export function eliminationRate(result: Tally): number {
  if (result.imported.length === 0) {
    return 0;
  }
  const eliminated = result.imported.length - result.reachable.length;
  return (eliminated / result.imported.length) * 100;
}
