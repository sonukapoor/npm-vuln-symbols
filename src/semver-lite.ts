/**
 * Just enough semantic version handling to pick a version to inspect.
 *
 * A full semver implementation is not needed here and would be a runtime
 * dependency for one comparison. Prereleases sort before their release, which
 * is the only subtlety that matters for picking the newest affected version.
 */

interface Parsed {
  readonly parts: readonly number[];
  readonly prerelease: string | null;
}

const VERSION_PATTERN = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/;

export function parseVersion(version: string): Parsed | null {
  const match = VERSION_PATTERN.exec(version.trim());
  if (match === null) {
    return null;
  }
  const [, major, minor, patch, prerelease] = match;
  return {
    parts: [Number(major), Number(minor), Number(patch)],
    prerelease: prerelease ?? null,
  };
}

/** Returns negative, zero or positive, like a comparator. */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left === null || right === null) {
    return a.localeCompare(b);
  }
  for (let i = 0; i < 3; i += 1) {
    const difference = (left.parts[i] ?? 0) - (right.parts[i] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  if (left.prerelease === right.prerelease) {
    return 0;
  }
  // A prerelease precedes its own release: 1.0.0-rc.1 comes before 1.0.0.
  if (left.prerelease === null) {
    return 1;
  }
  if (right.prerelease === null) {
    return -1;
  }
  return left.prerelease.localeCompare(right.prerelease);
}

/**
 * Picks the newest version that the advisory still affects.
 *
 * That version is the one whose exports should be inspected: the fix, by
 * definition, may have renamed or removed the vulnerable function, so checking
 * the latest release would give the wrong answer.
 */
export function newestAffected(
  available: readonly string[],
  fixed: string | null,
  lastAffected: string | null,
): string | null {
  // Prefer the newest affected stable release. Taking `last_affected`
  // literally can land on a prerelease: web3-core-subscriptions records
  // `2.0.0-alpha.1`, and inspecting an alpha instead of the release people
  // install reported its real `attachToObject` method as not found.
  const stable = available.filter(version => {
    if (parseVersion(version)?.prerelease != null) {
      return false;
    }
    if (fixed !== null) {
      return compareVersions(version, fixed) < 0;
    }
    if (lastAffected !== null) {
      return compareVersions(version, lastAffected) <= 0;
    }
    return true;
  });
  const newestStable = [...stable].sort(compareVersions).at(-1);
  if (newestStable !== undefined) {
    return newestStable;
  }
  // Only when no stable release is affected at all does the prerelease bound
  // become the best available answer.
  if (lastAffected !== null && available.includes(lastAffected)) {
    return lastAffected;
  }
  return null;
}
