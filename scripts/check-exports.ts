import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { scanExports, ExportScanResult } from "../src/package-exports.js";
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

/** Resolves the module file a consumer would load. */
function findEntryFile(packageDir: string): string | null {
  let manifest: { main?: unknown; module?: unknown } = {};
  try {
    manifest = JSON.parse(readFileSync(path.join(packageDir, "package.json"), "utf8")) as typeof manifest;
  } catch {
    return null;
  }
  const candidates = [manifest.module, manifest.main, "index.js", "index.mjs", "index.cjs"];
  for (const candidate of candidates) {
    if (typeof candidate !== "string") {
      continue;
    }
    const direct = path.join(packageDir, candidate);
    if (existsSync(direct) && !direct.endsWith("/")) {
      return direct;
    }
    const asIndex = path.join(direct, "index.js");
    if (existsSync(asIndex)) {
      return asIndex;
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
    if (scan.result === ExportScanResult.Unknown) {
      return { verdict: Verdict.Unknown, missing: [], reason: scan.reason ?? "exports unreadable" };
    }
    const exported = new Set(scan.names);
    const missing = symbols.filter(symbol => !exported.has(symbol));
    return missing.length === 0
      ? { verdict: Verdict.Confirmed, missing: [] }
      : { verdict: Verdict.NotFound, missing };
  } finally {
    rmSync(workDir, { recursive: true, force: true });
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

async function run(): Promise<void> {
  const limit = Number(readFlag(process.argv.slice(2), "--limit") ?? Number.MAX_SAFE_INTEGER);
  const rows: ReportRow[] = [];

  for (const dir of DATA_DIRS) {
    for (const name of readdirSync(dir).filter(f => f.endsWith(JSON_EXTENSION))) {
      if (rows.length >= limit) {
        break;
      }
      const record = JSON.parse(readFileSync(path.join(dir, name), "utf8")) as SymbolRecord;
      const first = record.affected[0];
      if (first === undefined) {
        continue;
      }
      const outcome = await checkPackage(first.package.name, first.symbols, null, null);
      rows.push({
        id: record.id,
        package: first.package.name,
        symbols: first.symbols,
        verdict: outcome.verdict,
        missing: outcome.missing,
        ...(outcome.reason !== undefined ? { reason: outcome.reason } : {}),
      });
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
