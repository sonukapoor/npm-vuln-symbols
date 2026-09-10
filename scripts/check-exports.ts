import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, existsSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { scanExports, ExportScanResult } from "../src/package-exports.js";
import { readAffectedFromDir, fetchAffected, type OsvAffectedEntry } from "../src/osv-ranges.js";
import { newestAffected } from "../src/semver-lite.js";
import type { SymbolRecord } from "../src/types.js";

/**
 * Checks each record's symbols against what the package actually exports.
 *
 * This is the one filter that needs no judgement. If `question` is not an
 * export of `@fuel-ts/account`, the record is wrong, and no reviewer has to
 * form an opinion about it. Everything the checker can settle mechanically is
 * work a human does not have to do.
 *
 * It reads the package by parsing, never by importing. Some advisories here are
 * for packages that shipped malware, and requiring one to enumerate its keys
 * would execute it.
 */

const DATA_DIRS = ["advisories", "proposals"] as const;
const JSON_EXTENSION = ".json";
const REGISTRY_BASE_URL = "https://registry.npmjs.org";
const REPORT_PATH = "study/export-check.json";
const JSON_INDENT = 2;
const MAX_BUFFER_BYTES = 64 * 1024 * 1024;

const Verdict = {
  /** The package exports every symbol the record names. */
  Confirmed: "confirmed",
  /**
   * Exports were read and a named symbol was not among them.
   *
   * This is a suspicion, not a verdict of wrong. A parser cannot see every way
   * a name becomes reachable, and an earlier version reported real functions
   * absent because they were prototype methods rather than top-level exports.
   */
  NotFound: "not_found",
  /** The export surface could not be determined. Proves nothing. */
  Unknown: "unknown",
} as const;

type Verdict = (typeof Verdict)[keyof typeof Verdict];

interface RegistryVersion {
  readonly main?: string;
  readonly module?: string;
  readonly dist?: { tarball?: string };
}

interface RegistryManifest {
  readonly versions?: Record<string, RegistryVersion>;
}

function readFlag(argv: readonly string[], flag: string): string | null {
  const index = argv.indexOf(flag);
  return index === -1 ? null : (argv[index + 1] ?? null);
}

async function fetchManifest(packageName: string): Promise<RegistryManifest | null> {
  try {
    const response = await fetch(`${REGISTRY_BASE_URL}/${encodeURIComponent(packageName)}`);
    return response.ok ? ((await response.json()) as RegistryManifest) : null;
  } catch {
    return null;
  }
}

/** Downloads and unpacks a version, returning the extracted package directory. */
function unpackTarball(tarballUrl: string, workDir: string): string | null {
  const archive = path.join(workDir, "package.tgz");
  try {
    execFileSync("curl", ["-sSL", "-o", archive, tarballUrl], { stdio: "ignore" });
    execFileSync("tar", ["-xzf", archive, "-C", workDir], {
      stdio: "ignore",
      maxBuffer: MAX_BUFFER_BYTES,
    });
  } catch {
    return null;
  }
  const root = path.join(workDir, "package");
  return existsSync(root) ? root : null;
}

/**
 * Pulls candidate paths out of a conditional `exports` field.
 *
 * Modern packages declare no `main` at all, which is why five of the first
 * forty had "no resolvable entry point".
 */
function candidatesFromExportsField(value: unknown, found: string[]): void {
  if (typeof value === "string") {
    found.push(value);
    return;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return;
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    // Skip anything that is not the root or a runtime condition we care about.
    if (key.startsWith(".") || ["import", "require", "default", "node"].includes(key)) {
      candidatesFromExportsField(nested, found);
    }
  }
}

/** Resolves the module file a consumer would load. */
function findEntryFile(packageDir: string): string | null {
  let manifest: { main?: unknown; module?: unknown; exports?: unknown } = {};
  try {
    manifest = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8")) as typeof manifest;
  } catch {
    return null;
  }
  const fromExports: string[] = [];
  candidatesFromExportsField(manifest.exports, fromExports);
  const candidates = [manifest.module, manifest.main, ...fromExports, "index.js", "index.mjs", "index.cjs"];
  for (const candidate of candidates) {
    if (typeof candidate !== "string") {
      continue;
    }
    const direct = path.join(packageDir, candidate);
    if (isReadableFile(direct)) {
      return direct;
    }
    for (const suffix of [".js", ".cjs", ".mjs", "/index.js", "/index.cjs", "/index.mjs"]) {
      const withSuffix = `${direct}${suffix}`;
      if (isReadableFile(withSuffix)) {
        return withSuffix;
      }
    }
  }
  return null;
}

/**
 * True only for a readable regular file.
 *
 * `existsSync` is true for directories too, so a candidate like
 * `lib/parser` that happens to be a folder passed the check and then threw
 * EISDIR on read, aborting a full run partway through.
 */
function isReadableFile(candidate: string): boolean {
  try {
    return existsSync(candidate) && statSync(candidate).isFile();
  } catch {
    return false;
  }
}

/** Resolves a relative specifier to a file, trying the usual extensions. */
function resolveRelative(fromDir: string, specifier: string): string | null {
  if (!specifier.startsWith(".")) {
    return null;
  }
  const base = path.resolve(fromDir, specifier);
  const candidates = [base, `${base}.js`, `${base}.cjs`, `${base}.mjs`, path.join(base, "index.js")];
  for (const candidate of candidates) {
    if (isReadableFile(candidate)) {
      return candidate;
    }
  }
  return null;
}

interface CheckOutcome {
  readonly verdict: Verdict;
  readonly missing: readonly string[];
  readonly reason?: string;
}

async function checkPackage(
  packageName: string,
  symbols: readonly string[],
  fixed: string | null,
  lastAffected: string | null,
): Promise<CheckOutcome> {
  const manifest = await fetchManifest(packageName);
  if (manifest?.versions === undefined) {
    return { verdict: Verdict.Unknown, missing: [], reason: "package not on the registry" };
  }
  const version = newestAffected(Object.keys(manifest.versions), fixed, lastAffected);
  const tarball = version === null ? undefined : manifest.versions[version]?.dist?.tarball;
  if (tarball === undefined) {
    return { verdict: Verdict.Unknown, missing: [], reason: "no affected version to inspect" };
  }

  const workDir = mkdtempSync(path.join(tmpdir(), "npm-vuln-exports-"));
  try {
    const packageDir = unpackTarball(tarball, workDir);
    if (packageDir === null) {
      return { verdict: Verdict.Unknown, missing: [], reason: "could not unpack the tarball" };
    }
    const entry = findEntryFile(packageDir);
    if (entry === null) {
      return { verdict: Verdict.Unknown, missing: [], reason: "no resolvable entry point" };
    }
    const scan = scanExports(entry, readFileSync(entry, "utf8"));
    const names = new Set(scan.names);
    let resolved = scan.result;

    // A module that hands its exports to another file is the largest single
    // reason a scan fails. Following one level recovers most of them without
    // reimplementing Node's resolver.
    if (resolved === ExportScanResult.Unknown && scan.delegatesTo !== undefined) {
      for (const specifier of scan.delegatesTo) {
        const target = resolveRelative(path.dirname(entry), specifier);
        if (target === null) {
          continue;
        }
        const inner = scanExports(target, readFileSync(target, "utf8"));
        for (const name of inner.names) {
          names.add(name);
        }
        if (inner.result === ExportScanResult.Parsed) {
          resolved = ExportScanResult.Parsed;
        }
      }
    }

    if (resolved === ExportScanResult.Unknown) {
      return { verdict: Verdict.Unknown, missing: [], reason: scan.reason ?? "exports unreadable" };
    }
    const exported = names;
    const missing = symbols.filter(symbol => !exported.has(symbol));
    return missing.length === 0
      ? { verdict: Verdict.Confirmed, missing: [] }
      : { verdict: Verdict.NotFound, missing };
  } finally {
    // Cleanup must never abort the run. Some packages ship read-only files, and
    // an EACCES while unlinking a README killed a full pass partway through.
    // A leaked temp directory is a far smaller problem than a lost run.
    try {
      rmSync(workDir, { recursive: true, force: true });
    } catch {
      process.stderr.write(`could not remove ${workDir}\n`);
    }
  }
}

interface ReportRow {
  readonly id: string;
  readonly package: string;
  readonly symbols: readonly string[];
  readonly verdict: Verdict;
  readonly missing: readonly string[];
  readonly reason?: string;
}

/**
 * Reads the version bounds for one package out of the advisory.
 *
 * Without these the newest release gets inspected, which is the version *after*
 * the fix. A fix may rename or delete the vulnerable function, so checking it
 * would report correct records as not found.
 */
function boundsFor(
  affected: readonly OsvAffectedEntry[],
  packageName: string,
): { fixed: string | null; lastAffected: string | null } {
  for (const entry of affected) {
    if (entry.package.name !== packageName) {
      continue;
    }
    for (const range of entry.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed !== undefined) {
          return { fixed: event.fixed, lastAffected: null };
        }
        if (event.last_affected !== undefined) {
          return { fixed: null, lastAffected: event.last_affected };
        }
      }
    }
  }
  return { fixed: null, lastAffected: null };
}

async function run(): Promise<void> {
  const argv = process.argv.slice(2);
  const limit = Number(readFlag(argv, "--limit") ?? Number.MAX_SAFE_INTEGER);
  const osvDir = readFlag(argv, "--osv-dir");
  const rows: ReportRow[] = [];

  for (const dir of DATA_DIRS) {
    for (const name of readdirSync(dir).filter(f => f.endsWith(JSON_EXTENSION))) {
      if (rows.length >= limit) {
        break;
      }
      const record = JSON.parse(readFileSync(path.join(dir, name), "utf8")) as SymbolRecord;
      const affected =
        osvDir !== null ? readAffectedFromDir(osvDir, record.id) : await fetchAffected(record.id);

      // Every affected package is checked, not only the first. A symbol valid
      // for `lodash` may not exist in `lodash.template`.
      for (const entry of record.affected) {
        if (rows.length >= limit) {
          break;
        }
        const { fixed, lastAffected } = boundsFor(affected, entry.package.name);
        // One unusual package must not end the pass. Anything unexpected is
        // recorded as unknown, which is the honest verdict for "we could not
        // look", and the run continues.
        let outcome: CheckOutcome;
        try {
          outcome = await checkPackage(entry.package.name, entry.symbols, fixed, lastAffected);
        } catch (error) {
          outcome = {
            verdict: Verdict.Unknown,
            missing: [],
            reason: `check failed: ${(error as Error).message.slice(0, 80)}`,
          };
        }
        rows.push({
          id: record.id,
          package: entry.package.name,
          symbols: entry.symbols,
          verdict: outcome.verdict,
          missing: outcome.missing,
          ...(outcome.reason !== undefined ? { reason: outcome.reason } : {}),
        });
      }
    }
  }

  writeFileSync(REPORT_PATH, `${JSON.stringify(rows, null, JSON_INDENT)}\n`, "utf8");
  const counts = { confirmed: 0, not_found: 0, unknown: 0 };
  for (const row of rows) {
    counts[row.verdict] += 1;
  }
  process.stdout.write(`checked   : ${rows.length}\n`);
  process.stdout.write(`confirmed : ${counts.confirmed}\n`);
  process.stdout.write(`not found : ${counts.not_found}   <- suspicious, needs a human, NOT proof of wrong\n`);
  process.stdout.write(`unknown   : ${counts.unknown}   <- exports unreadable, proves nothing\n`);
  process.stdout.write(`report    : ${REPORT_PATH}\n`);
}

await run();
