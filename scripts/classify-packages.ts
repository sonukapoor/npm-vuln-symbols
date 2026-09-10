import { readFileSync, writeFileSync } from "node:fs";

/**
 * Classifies each sampled advisory's package as a library, an application, or
 * a malicious package, using npm registry metadata rather than judgement.
 *
 * The trigger classification was done by reading advisories, and repeated
 * readings disagreed on near-identical cases. This split has to be reproducible
 * instead, because the headline number depends on it: lumping CLIs, servers and
 * malware in with libraries overstates how often reachability analysis fails on
 * the dependencies a developer actually imports.
 */

const REGISTRY_BASE_URL = "https://registry.npmjs.org";
const JSON_INDENT = 2;
const REQUEST_CONCURRENCY = 8;

export const PackageKind = {
  /** Exposes an importable entry point. Reachability is meaningful. */
  Library: "library",
  /** Ships only an executable. Nothing imports it, so nothing can call into it. */
  Application: "application",
  /** Advisory says the package is malware. Remedy is removal, not analysis. */
  Malicious: "malicious",
  /** Unpublished or unreachable on the registry. */
  Unknown: "unknown",
} as const;

export type PackageKind = (typeof PackageKind)[keyof typeof PackageKind];

/** Phrases identifying a malicious-package report, matching the extractor's. */
const MALICIOUS_PROSE_PATTERN =
  /\b(?:malicious code|contains? malware|is malicious|embedded malware|malicious functionality|contained malware|steals?|exfiltrat)/i;

interface RegistryManifest {
  versions?: Record<string, { main?: unknown; exports?: unknown; module?: unknown; bin?: unknown }>;
  "dist-tags"?: { latest?: string };
}

/**
 * A package is a library if its latest manifest declares any import entry
 * point. `bin` alone means it is only ever executed, never imported.
 */
function kindFromManifest(manifest: RegistryManifest): PackageKind {
  const latest = manifest["dist-tags"]?.latest;
  const version = latest === undefined ? undefined : manifest.versions?.[latest];
  if (version === undefined) {
    return PackageKind.Unknown;
  }
  const hasEntryPoint =
    version.main !== undefined || version.exports !== undefined || version.module !== undefined;
  if (hasEntryPoint) {
    return PackageKind.Library;
  }
  return version.bin !== undefined ? PackageKind.Application : PackageKind.Library;
}

async function fetchKind(packageName: string): Promise<PackageKind> {
  try {
    const response = await fetch(`${REGISTRY_BASE_URL}/${encodeURIComponent(packageName)}`);
    if (!response.ok) {
      return PackageKind.Unknown;
    }
    return kindFromManifest((await response.json()) as RegistryManifest);
  } catch {
    return PackageKind.Unknown;
  }
}

interface SampleRow {
  id: string;
  packages: string[];
  digest: string;
}

/** Runs lookups in small batches so the registry is not hit all at once. */
async function classifyAll(rows: readonly SampleRow[]): Promise<Map<string, PackageKind>> {
  const kinds = new Map<string, PackageKind>();
  const names = [...new Set(rows.flatMap(row => row.packages))];
  for (let i = 0; i < names.length; i += REQUEST_CONCURRENCY) {
    const slice = names.slice(i, i + REQUEST_CONCURRENCY);
    const results = await Promise.all(slice.map(fetchKind));
    slice.forEach((name, index) => kinds.set(name, results[index] ?? PackageKind.Unknown));
  }
  return kinds;
}

async function run(): Promise<void> {
  const rows = JSON.parse(readFileSync("study/sample.json", "utf8")) as SampleRow[];
  const kinds = await classifyAll(rows);

  const out = rows.map(row => {
    // The advisory's own words decide malware, since such packages are often
    // unpublished and would otherwise resolve to unknown.
    if (MALICIOUS_PROSE_PATTERN.test(row.digest)) {
      return { id: row.id, packages: row.packages, kind: PackageKind.Malicious };
    }
    const found = row.packages.map(name => kinds.get(name) ?? PackageKind.Unknown);
    const kind = found.includes(PackageKind.Library) ? PackageKind.Library : (found[0] ?? PackageKind.Unknown);
    return { id: row.id, packages: row.packages, kind };
  });

  writeFileSync("study/package-kinds.json", `${JSON.stringify(out, null, JSON_INDENT)}\n`, "utf8");
  process.stdout.write(`classified ${out.length} advisories by package kind\n`);
}

await run();
