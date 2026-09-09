import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * Supplies the affected version ranges a reachability run needs.
 *
 * The dataset deliberately stores only symbols. Version ranges already live in
 * OSV and duplicating them here would create a second copy to keep in sync.
 * Jelly, however, will not match a package at all without them: it has to
 * establish that the installed version is affected before asking whether the
 * vulnerable function is reached. So they are merged back in at probe time.
 */

const OSV_API_BASE_URL = "https://api.osv.dev/v1/vulns";
const JSON_EXTENSION = ".json";

export interface OsvRange {
  readonly events: { introduced?: string; fixed?: string; last_affected?: string }[];
}

export interface OsvAffectedEntry {
  readonly package: { name: string };
  readonly ranges?: OsvRange[];
  readonly versions?: string[];
}

interface RawOsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: OsvRange[];
  versions?: string[];
}

/** Extracts npm affected entries, dropping other ecosystems. */
function toNpmAffected(raw: readonly RawOsvAffected[]): OsvAffectedEntry[] {
  const entries: OsvAffectedEntry[] = [];
  for (const item of raw) {
    const name = item.package?.name;
    if (item.package?.ecosystem !== "npm" || name === undefined) {
      continue;
    }
    entries.push({
      package: { name },
      ...(item.ranges !== undefined ? { ranges: item.ranges } : {}),
      ...(item.versions !== undefined ? { versions: item.versions } : {}),
    });
  }
  return entries;
}

/** Reads affected ranges from a local unzipped OSV feed directory. */
export function readAffectedFromDir(osvDir: string, advisoryId: string): OsvAffectedEntry[] {
  const filePath = path.join(osvDir, `${advisoryId}${JSON_EXTENSION}`);
  try {
    const parsed = JSON.parse(readFileSync(filePath, "utf8")) as { affected?: RawOsvAffected[] };
    return toNpmAffected(parsed.affected ?? []);
  } catch {
    return [];
  }
}

/** Fetches affected ranges from the OSV API when no local feed is available. */
export async function fetchAffected(advisoryId: string): Promise<OsvAffectedEntry[]> {
  const response = await fetch(`${OSV_API_BASE_URL}/${advisoryId}`);
  if (!response.ok) {
    return [];
  }
  const parsed = (await response.json()) as { affected?: RawOsvAffected[] };
  return toNpmAffected(parsed.affected ?? []);
}
