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

/**
 * Matches a commit URL on the common forges.
 *
 * Reference *type* cannot be used to find these. The OSV schema defines a FIX
 * type, but across all 7,020 live GHSA advisories in the npm feed it is used
 * exactly zero times: every reference is WEB, ADVISORY or PACKAGE. Meanwhile
 * 51.2% of advisories do link their fixing commit, filed under WEB alongside
 * vendor bulletins and NVD mirrors.
 *
 * So the commit has to be recognised by URL shape. That is a heuristic, and it
 * is weaker than reading a schema field would have been.
 */
const COMMIT_URL_PATTERN =
  /^https?:\/\/(?:github\.com|gitlab\.com|bitbucket\.org|git\.[^/]+)\/[^/]+\/[^/]+\/(?:commit|commits|-\/commit)\/[0-9a-f]{7,40}/i;

/**
 * Returns the URL of the commit that fixed the advisory, when one is linked.
 *
 * Prefers a reference explicitly typed FIX, in case the field ever starts being
 * populated, and otherwise falls back to URL shape.
 */
export function findFixCommitUrl(record: OsvRecord): string | null {
  const references = record.references ?? [];
  for (const reference of references) {
    if (reference.type === "FIX" && reference.url !== undefined) {
      return reference.url;
    }
  }
  for (const reference of references) {
    if (reference.url !== undefined && COMMIT_URL_PATTERN.test(reference.url)) {
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
