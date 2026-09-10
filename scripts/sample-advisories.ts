import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import type { OsvRecord } from "../src/osv.js";

/**
 * Draws a reproducible random sample of npm GHSA advisories for manual
 * classification.
 *
 * Determinism is the point. The finding is a percentage derived from human
 * judgement on a subset, so anyone checking it must be able to regenerate the
 * exact same subset and disagree with individual calls.
 */

const ERR_MISSING_OSV_DIR =
  "Missing --osv-dir. Pass the directory of unzipped OSV npm advisories from " +
  "https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip";

const GHSA_PREFIX = "GHSA-";
const JSON_EXTENSION = ".json";
const DEFAULT_SAMPLE_SIZE = 150;
const DEFAULT_SEED = 20260910;
const DIGEST_CHAR_LIMIT = 420;
const JSON_INDENT = 2;

/** mulberry32: small, seedable, and identical across platforms. */
function createRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Fisher-Yates using the seeded generator, so the draw is reproducible. */
function sample<T>(items: readonly T[], count: number, random: () => number): T[] {
  const pool = [...items];
  const picked: T[] = [];
  const limit = Math.min(count, pool.length);
  for (let i = 0; i < limit; i += 1) {
    const index = i + Math.floor(random() * (pool.length - i));
    const chosen = pool[index];
    const current = pool[i];
    if (chosen === undefined || current === undefined) {
      continue;
    }
    pool[index] = current;
    pool[i] = chosen;
    picked.push(chosen);
  }
  return picked;
}

function readFlag(argv: readonly string[], flag: string): string | null {
  const index = argv.indexOf(flag);
  return index === -1 ? null : (argv[index + 1] ?? null);
}

/** Collapses an advisory to the text a classifier actually needs. */
function digest(record: OsvRecord): string {
  const text = `${record.summary ?? ""}. ${record.details ?? ""}`
    .replace(/\s+/g, " ")
    .trim();
  return text.slice(0, DIGEST_CHAR_LIMIT);
}

function npmPackages(record: OsvRecord): string[] {
  const names = new Set<string>();
  for (const affected of record.affected ?? []) {
    if (affected.package?.ecosystem === "npm" && affected.package.name !== undefined) {
      names.add(affected.package.name);
    }
  }
  return [...names];
}

function run(): void {
  const argv = process.argv.slice(2);
  const osvDir = readFlag(argv, "--osv-dir");
  if (osvDir === null) {
    throw new Error(ERR_MISSING_OSV_DIR);
  }
  const size = Number(readFlag(argv, "--size") ?? DEFAULT_SAMPLE_SIZE);
  const seed = Number(readFlag(argv, "--seed") ?? DEFAULT_SEED);
  const outPath = readFlag(argv, "--out") ?? "study/sample.json";

  // Sorted so the file listing order cannot vary between machines.
  const names = readdirSync(osvDir)
    .filter(name => name.startsWith(GHSA_PREFIX) && name.endsWith(JSON_EXTENSION))
    .sort();

  // Withdrawn advisories are duplicates or retractions, 4.7% of the feed. They
  // describe nothing a consumer should act on, so including them would pad the
  // population with rows that are not really advisories.
  const live = names.filter(name => {
    const record = JSON.parse(readFileSync(path.join(osvDir, name), "utf8")) as OsvRecord;
    return record.withdrawn === undefined;
  });

  const picked = sample(live, size, createRandom(seed));
  const rows = picked.map(name => {
    const record = JSON.parse(readFileSync(path.join(osvDir, name), "utf8")) as OsvRecord;
    return {
      id: record.id,
      packages: npmPackages(record),
      digest: digest(record),
      trigger: "",
      note: "",
    };
  });

  writeFileSync(outPath, `${JSON.stringify(rows, null, JSON_INDENT)}\n`, "utf8");
  process.stdout.write(`population : ${live.length} live GHSA advisories (${names.length - live.length} withdrawn, excluded)\n`);
  process.stdout.write(`sampled    : ${rows.length} (seed ${seed})\n`);
  process.stdout.write(`written to : ${outPath}\n`);
}

run();
