import { readFileSync } from "node:fs";
import path from "node:path";

/**
 * Lists the packages actually installed in a project.
 *
 * The probe needs this because asking a whole-program analyzer about
 * advisories for packages the project does not have is not merely wasteful:
 * on a real dependency tree it exhausts the V8 heap and the analysis aborts.
 * Filtering first turned a 576-entry run into a 4-entry one.
 */

const LOCKFILE_NAME = "package-lock.json";
const NODE_MODULES_SEGMENT = "node_modules/";

interface PackageLock {
  packages?: Record<string, unknown>;
  dependencies?: Record<string, unknown>;
}

/** Recovers the package name from a lockfile path key. */
function toPackageName(lockPath: string): string | null {
  const index = lockPath.lastIndexOf(NODE_MODULES_SEGMENT);
  if (index === -1) {
    return null;
  }
  const name = lockPath.slice(index + NODE_MODULES_SEGMENT.length);
  return name.length > 0 ? name : null;
}

/**
 * Reads every installed package name, including transitive dependencies.
 * Returns an empty set when there is no readable lockfile, which callers must
 * treat as "unknown" rather than "nothing installed".
 */
export function readInstalledPackages(projectPath: string): Set<string> {
  const names = new Set<string>();
  let lock: PackageLock;
  try {
    lock = JSON.parse(readFileSync(path.join(projectPath, LOCKFILE_NAME), "utf8")) as PackageLock;
  } catch {
    return names;
  }

  for (const lockPath of Object.keys(lock.packages ?? {})) {
    const name = toPackageName(lockPath);
    if (name !== null) {
      names.add(name);
    }
  }
  // npm v6 lockfiles nest under "dependencies" with bare names as keys.
  for (const name of Object.keys(lock.dependencies ?? {})) {
    names.add(name);
  }
  return names;
}
