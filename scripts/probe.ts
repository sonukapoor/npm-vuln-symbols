import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync, mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  buildEntries,
  eliminationRate,
  tally,
  type JellyEntry,
  type Tally,
} from "../src/probe-analysis.js";
import { readAffectedFromDir, fetchAffected, type OsvAffectedEntry } from "../src/osv-ranges.js";
import { readInstalledPackages } from "../src/installed-packages.js";
import type { SymbolRecord } from "../src/types.js";

/**
 * Measures what symbol-level reachability adds over package-level analysis.
 *
 * The comparison matters because a dependency scanner already tells you which
 * packages you import. The dataset only earns its place if knowing the
 * vulnerable *function* eliminates findings that survive that weaker check, so
 * the probe measures both rungs in one run rather than reporting a headline
 * number against the easiest possible baseline.
 */

const ERR_MISSING_PROJECT =
  "Missing --project. Pass the path to a project with node_modules installed.";
const ADVISORIES_DIR = "advisories";
const JSON_EXTENSION = ".json";
const JSON_INDENT = 2;
const JELLY_MAX_BUFFER_BYTES = 64 * 1024 * 1024;

/**
 * Bounds how far the analyzer follows indirect flows.
 *
 * A full analysis keeps every package in scope but did not complete on a
 * 365-package project even with a 16 GB heap. This bound keeps every package in
 * scope and completes in about a second. Jelly's own documentation is explicit
 * that this yields partial, unsound results, so a "not reachable" verdict under
 * this setting is weaker than one from a full analysis and must not be treated
 * as proof. It is the difference between a probe and a suppression tool.
 */
const DEFAULT_MAX_INDIRECTIONS = "1";

interface ProbeOptions {
  readonly projectPath: string;
  readonly datasetDir: string;
  readonly osvDir: string | null;
  readonly entry: string;
  /** Empty string requests a full, unbounded analysis. */
  readonly maxIndirections: string;
}

function readFlag(argv: readonly string[], flag: string): string | null {
  const index = argv.indexOf(flag);
  if (index === -1) {
    return null;
  }
  return argv[index + 1] ?? null;
}

function parseArgs(argv: readonly string[]): ProbeOptions {
  const projectPath = readFlag(argv, "--project");
  if (projectPath === null) {
    throw new Error(ERR_MISSING_PROJECT);
  }
  return {
    projectPath,
    datasetDir: readFlag(argv, "--dataset") ?? ADVISORIES_DIR,
    osvDir: readFlag(argv, "--osv-dir"),
    entry: readFlag(argv, "--entry") ?? projectPath,
    maxIndirections: readFlag(argv, "--max-indirections") ?? DEFAULT_MAX_INDIRECTIONS,
  };
}

function loadDataset(dir: string): SymbolRecord[] {
  return readdirSync(dir)
    .filter(name => name.endsWith(JSON_EXTENSION))
    .map(name => JSON.parse(readFileSync(path.join(dir, name), "utf8")) as SymbolRecord);
}

async function resolveAffected(
  record: SymbolRecord,
  osvDir: string | null,
): Promise<OsvAffectedEntry[]> {
  if (osvDir !== null) {
    return readAffectedFromDir(osvDir, record.id);
  }
  return fetchAffected(record.id);
}

/**
 * Runs the analyzer, letting its output through.
 *
 * Its diagnostics are the only signal when an analysis aborts, so swallowing
 * them makes a failure impossible to diagnose.
 */
function runJelly(
  vulnsPath: string,
  matchesPath: string,
  entry: string,
  maxIndirections: string,
): void {
  const args = ["jelly", "-v", vulnsPath, "--matches-file", matchesPath];
  if (maxIndirections !== "") {
    args.push("--max-indirections", maxIndirections);
  }
  args.push(entry);
  execFileSync("npx", args, {
    stdio: ["ignore", "inherit", "inherit"],
    maxBuffer: JELLY_MAX_BUFFER_BYTES,
  });
}

function report(candidates: number, result: Tally): void {
  const { imported, reachable } = result;
  const eliminated = imported.length - reachable.length;
  const rate = eliminationRate(result);

  process.stdout.write(`\nadvisories with dataset coverage : ${candidates}\n`);
  process.stdout.write(`package is imported              : ${imported.length}\n`);
  process.stdout.write(`vulnerable symbol is reached     : ${reachable.length}\n`);
  process.stdout.write(`eliminated by symbol analysis    : ${eliminated}\n`);
  process.stdout.write(`elimination rate                 : ${rate.toFixed(1)}%\n`);
  if (imported.length === 0) {
    // Distinguishing "nothing to eliminate" from "the analysis found nothing"
    // matters: both print zero, and only one of them is a result.
    process.stdout.write(
      "\nNo package was imported from the entry point, so there was nothing to\n" +
        "eliminate. This is not an elimination rate of zero, it is no measurement.\n",
    );
  }
  process.stdout.write("\n");

  const reachableSet = new Set(reachable);
  for (const id of imported) {
    const verdict = reachableSet.has(id) ? "REACHABLE    " : "not reachable";
    process.stdout.write(`  ${verdict}  ${id}\n`);
  }
}

async function run(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (!existsSync(options.projectPath)) {
    throw new Error(`Project path does not exist: ${options.projectPath}`);
  }

  const records = loadDataset(options.datasetDir);
  const installed = readInstalledPackages(options.projectPath);
  if (installed.size === 0) {
    throw new Error(
      `No readable package-lock.json in ${options.projectPath}. ` +
        "The probe needs the installed package list to avoid asking the analyzer " +
        "about advisories the project cannot be affected by.",
    );
  }

  const relevant = records.filter(record =>
    record.affected.some(entry => installed.has(entry.package.name)),
  );
  process.stdout.write(
    `dataset records: ${records.length}, relevant to installed packages: ${relevant.length}\n`,
  );

  const entries: JellyEntry[] = [];
  for (const record of relevant) {
    const affected = await resolveAffected(record, options.osvDir);
    entries.push(...buildEntries(record, affected));
  }

  const workDir = mkdtempSync(path.join(tmpdir(), "npm-vuln-symbols-probe-"));
  const vulnsPath = path.join(workDir, "vulnerabilities.json");
  const matchesPath = path.join(workDir, "matches.json");
  writeFileSync(vulnsPath, JSON.stringify(entries, null, JSON_INDENT), "utf8");

  runJelly(vulnsPath, matchesPath, options.entry, options.maxIndirections);

  const matches = JSON.parse(readFileSync(matchesPath, "utf8")) as Record<string, unknown[]>;
  report(entries.length / 2, tally(matches));
}

await run();
