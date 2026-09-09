import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { validateRecord } from "../src/validate-record.js";

const ADVISORIES_DIR = "advisories";
const JSON_EXTENSION = ".json";
const REGISTRY_BASE_URL = "https://registry.npmjs.org";
const EXIT_FAILURE = 1;

const ERR_FILENAME_MISMATCH = "filename must match the record id";

interface FileProblem {
  readonly file: string;
  readonly problems: readonly string[];
}

function readJson(filePath: string): unknown {
  return JSON.parse(readFileSync(filePath, "utf8")) as unknown;
}

/** Confirms the package exists on the registry, catching typos in the name. */
async function checkPackageExists(packageName: string): Promise<boolean> {
  const response = await fetch(`${REGISTRY_BASE_URL}/${encodeURIComponent(packageName)}`, {
    method: "HEAD",
  });
  return response.ok;
}

function validateFile(dir: string, name: string): FileProblem | null {
  const filePath = path.join(dir, name);
  let parsed: unknown;
  try {
    parsed = readJson(filePath);
  } catch (error) {
    return { file: name, problems: [`not valid JSON: ${(error as Error).message}`] };
  }

  const problems = [...validateRecord(parsed)];
  const record = parsed as { id?: unknown };
  if (typeof record.id === "string" && `${record.id}${JSON_EXTENSION}` !== name) {
    problems.push(ERR_FILENAME_MISMATCH);
  }
  return problems.length > 0 ? { file: name, problems } : null;
}

/** Collects every package name referenced across all records. */
function collectPackageNames(dir: string, names: readonly string[]): Set<string> {
  const packages = new Set<string>();
  for (const name of names) {
    try {
      const parsed = readJson(path.join(dir, name)) as {
        affected?: { package?: { name?: unknown } }[];
      };
      for (const entry of parsed.affected ?? []) {
        if (typeof entry.package?.name === "string") {
          packages.add(entry.package.name);
        }
      }
    } catch {
      // Shape problems are already reported by validateFile.
    }
  }
  return packages;
}

async function run(): Promise<void> {
  const dir = path.resolve(ADVISORIES_DIR);
  const names = readdirSync(dir).filter(name => name.endsWith(JSON_EXTENSION));

  const failures: FileProblem[] = [];
  for (const name of names) {
    const problem = validateFile(dir, name);
    if (problem !== null) {
      failures.push(problem);
    }
  }

  const missingPackages: string[] = [];
  for (const packageName of collectPackageNames(dir, names)) {
    if (!(await checkPackageExists(packageName))) {
      missingPackages.push(packageName);
    }
  }

  report(names.length, failures, missingPackages);
  if (failures.length > 0 || missingPackages.length > 0) {
    process.exitCode = EXIT_FAILURE;
  }
}

function report(total: number, failures: readonly FileProblem[], missing: readonly string[]): void {
  for (const failure of failures) {
    process.stdout.write(`${failure.file}\n`);
    for (const problem of failure.problems) {
      process.stdout.write(`  ${problem}\n`);
    }
  }
  for (const packageName of missing) {
    process.stdout.write(`package not found on the npm registry: ${packageName}\n`);
  }
  process.stdout.write(`\nrecords checked: ${total}\n`);
  process.stdout.write(`invalid records: ${failures.length}\n`);
  process.stdout.write(`unknown packages: ${missing.length}\n`);
}

await run();
