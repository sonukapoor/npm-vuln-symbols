import { readdirSync, readFileSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

import { proposeRecord } from "../src/propose-record.js";
import type { OsvRecord } from "../src/osv.js";
import type { SymbolRecord } from "../src/types.js";

const ERR_MISSING_OSV_DIR =
  "Missing --osv-dir. Pass the directory of unzipped OSV npm advisories, " +
  "downloaded from https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip";

const JSON_EXTENSION = ".json";
const JSON_INDENT = 2;

interface ExtractOptions {
  readonly osvDir: string;
  readonly outDir: string | null;
}

interface ExtractStats {
  advisoriesRead: number;
  proposalsMade: number;
}

function parseArgs(argv: readonly string[]): ExtractOptions {
  const osvDir = readFlag(argv, "--osv-dir");
  if (osvDir === null) {
    throw new Error(ERR_MISSING_OSV_DIR);
  }
  return { osvDir, outDir: readFlag(argv, "--out") };
}

function readFlag(argv: readonly string[], flag: string): string | null {
  const index = argv.indexOf(flag);
  if (index === -1) {
    return null;
  }
  return argv[index + 1] ?? null;
}

/** Parses one advisory file, returning null when it is not readable JSON. */
function readAdvisory(filePath: string): OsvRecord | null {
  try {
    return JSON.parse(readFileSync(filePath, "utf8")) as OsvRecord;
  } catch {
    return null;
  }
}

function writeProposal(outDir: string, record: SymbolRecord): void {
  const target = path.join(outDir, `${record.id}${JSON_EXTENSION}`);
  writeFileSync(target, `${JSON.stringify(record, null, JSON_INDENT)}\n`, "utf8");
}

function run(): void {
  const options = parseArgs(process.argv.slice(2));
  if (options.outDir !== null) {
    mkdirSync(options.outDir, { recursive: true });
  }

  const stats: ExtractStats = { advisoriesRead: 0, proposalsMade: 0 };
  const files = readdirSync(options.osvDir).filter(name => name.endsWith(JSON_EXTENSION));

  for (const name of files) {
    const advisory = readAdvisory(path.join(options.osvDir, name));
    if (advisory === null) {
      continue;
    }
    stats.advisoriesRead += 1;

    const proposal = proposeRecord(advisory);
    if (proposal === null) {
      continue;
    }
    stats.proposalsMade += 1;
    if (options.outDir !== null) {
      writeProposal(options.outDir, proposal);
    }
  }

  reportStats(stats);
}

function reportStats(stats: ExtractStats): void {
  const rate =
    stats.advisoriesRead === 0 ? 0 : (stats.proposalsMade / stats.advisoriesRead) * 100;
  process.stdout.write(`advisories read : ${stats.advisoriesRead}\n`);
  process.stdout.write(`symbols proposed: ${stats.proposalsMade}\n`);
  process.stdout.write(`coverage        : ${rate.toFixed(1)}%\n`);
}

run();
