/**
 * The subset of the OSV record this project reads.
 *
 * Deliberately partial: the dataset only needs the identifiers, the affected
 * package and the description prose. Modelling the full schema would couple
 * this repo to OSV changes it does not care about.
 */

export interface OsvAffectedPackage {
  readonly ecosystem?: string;
  readonly name?: string;
}

export interface OsvAffected {
  readonly package?: OsvAffectedPackage;
}

export interface OsvReference {
  readonly type?: string;
  readonly url?: string;
}

export interface OsvRecord {
  readonly id: string;
  readonly aliases?: readonly string[];
  readonly summary?: string;
  readonly details?: string;
  readonly affected?: readonly OsvAffected[];
  readonly references?: readonly OsvReference[];
  readonly withdrawn?: string;
}

/** OSV reference type marking the commit that fixed the advisory. */
const REFERENCE_TYPE_FIX = "FIX";

/** Returns the fix commit URL when the advisory records one. */
export function findFixCommitUrl(record: OsvRecord): string | null {
  for (const reference of record.references ?? []) {
    if (reference.type === REFERENCE_TYPE_FIX && reference.url !== undefined) {
      return reference.url;
    }
  }
  return null;
}

/**
 * Returns every npm package an advisory affects, deduplicated and sorted.
 *
 * Advisories for popular libraries routinely list several package names, so
 * collapsing to one would discard the most widely depended-on entries.
 */
export function findNpmPackages(record: OsvRecord): string[] {
  const names = new Set<string>();
  for (const affected of record.affected ?? []) {
    const { ecosystem, name } = affected.package ?? {};
    if (ecosystem === "npm" && name !== undefined && name.length > 0) {
      names.add(name);
    }
  }
  return [...names].sort();
}
