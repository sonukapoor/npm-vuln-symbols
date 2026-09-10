import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import { corroborateSymbols } from "../src/commit-corroboration.js";
import { Confidence, EvidenceSource, type SymbolRecord } from "../src/types.js";

/**
 * Raises record confidence where the fix commit's diff agrees with the prose.
 *
 * The dataset's whole claim is negative, so a record only earns `high` when two
 * independent sources say the same thing. Until the fix-commit half existed,
 * nothing could reach it and every record sat at `medium`.
 */

const DATA_DIRS = ["advisories", "proposals"] as const;
const JSON_EXTENSION = ".json";
const JSON_INDENT = 2;
const GITHUB_COMMIT_PATTERN =
  /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/commits?\/([0-9a-f]{7,40})/i;
const MAX_BUFFER_BYTES = 32 * 1024 * 1024;

interface Stats {
  withCommit: number;
  fetched: number;
  fetchFailed: number;
  notGithub: number;
  upgraded: number;
  contradicted: number;
}

/** Fetches a commit's combined patch text, or null when unavailable. */
function fetchPatch(owner: string, repo: string, sha: string): string | null {
  try {
    const json = execFileSync(
      "gh",
      ["api", `repos/${owner}/${repo}/commits/${sha}`, "--jq", "[.files[]?.patch // empty] | join(\"\\n\")"],
      { encoding: "utf8", maxBuffer: MAX_BUFFER_BYTES, stdio: ["ignore", "pipe", "ignore"] },
    );
    const patch = json.trim();
    return patch.length > 0 ? patch : null;
  } catch {
    return null;
  }
}

function loadRecords(dir: string): { file: string; record: SymbolRecord }[] {
  return readdirSync(dir)
    .filter(name => name.endsWith(JSON_EXTENSION))
    .map(name => {
      const file = path.join(dir, name);
      return { file, record: JSON.parse(readFileSync(file, "utf8")) as SymbolRecord };
    });
}

/** All symbols the record names, across every affected package. */
function allSymbols(record: SymbolRecord): string[] {
  return [...new Set(record.affected.flatMap(entry => [...entry.symbols]))];
}

function processRecord(file: string, record: SymbolRecord, stats: Stats): void {
  const url = record.evidence.fixCommit;
  if (url === undefined) {
    return;
  }
  stats.withCommit += 1;

  const match = GITHUB_COMMIT_PATTERN.exec(url);
  if (match === null) {
    stats.notGithub += 1;
    return;
  }
  const [, owner, repo, sha] = match;
  if (owner === undefined || repo === undefined || sha === undefined) {
    stats.notGithub += 1;
    return;
  }

  const patch = fetchPatch(owner, repo, sha);
  if (patch === null) {
    stats.fetchFailed += 1;
    return;
  }
  stats.fetched += 1;

  const symbols = allSymbols(record);
  const { corroborated, uncorroborated } = corroborateSymbols(patch, symbols);
  if (corroborated.length === 0) {
    // The diff never mentions what the prose named. That is a disagreement
    // worth surfacing to a reviewer, not a reason to change the record.
    stats.contradicted += 1;
    return;
  }
  if (uncorroborated.length > 0) {
    return;
  }

  const updated: SymbolRecord = {
    ...record,
    evidence: {
      ...record.evidence,
      source: EvidenceSource.Both,
      confidence: Confidence.High,
    },
  };
  writeFileSync(file, `${JSON.stringify(updated, null, JSON_INDENT)}\n`, "utf8");
  stats.upgraded += 1;
}

function run(): void {
  const stats: Stats = {
    withCommit: 0,
    fetched: 0,
    fetchFailed: 0,
    notGithub: 0,
    upgraded: 0,
    contradicted: 0,
  };
  for (const dir of DATA_DIRS) {
    for (const { file, record } of loadRecords(dir)) {
      processRecord(file, record, stats);
    }
  }
  process.stdout.write(`records with a fix commit : ${stats.withCommit}\n`);
  process.stdout.write(`  patch fetched           : ${stats.fetched}\n`);
  process.stdout.write(`  not a GitHub commit     : ${stats.notGithub}\n`);
  process.stdout.write(`  fetch failed            : ${stats.fetchFailed}\n`);
  process.stdout.write(`  upgraded to high        : ${stats.upgraded}\n`);
  process.stdout.write(`  diff mentions none      : ${stats.contradicted}\n`);
}

run();
