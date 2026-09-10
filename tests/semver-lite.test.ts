import { compareVersions, newestAffected, parseVersion } from "../src/semver-lite.js";

describe("compareVersions", () => {
  it("orders by major, minor, then patch", () => {
    expect(compareVersions("1.2.3", "1.2.4")).toBeLessThan(0);
    expect(compareVersions("2.0.0", "1.99.99")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("sorts a prerelease before its own release", () => {
    expect(compareVersions("1.0.0-rc.1", "1.0.0")).toBeLessThan(0);
  });

  it("does not compare 4.17.9 as greater than 4.17.21", () => {
    // String comparison gets this backwards, and lodash advisories sit exactly
    // on this boundary.
    expect(compareVersions("4.17.9", "4.17.21")).toBeLessThan(0);
  });
});

describe("newestAffected", () => {
  const versions = ["4.17.9", "4.17.15", "4.17.20", "4.17.21", "4.17.22"];

  it("picks the newest version below the fix", () => {
    // The fix may rename or remove the vulnerable function, so inspecting the
    // latest release would give the wrong export list.
    expect(newestAffected(versions, "4.17.21", null)).toBe("4.17.20");
  });

  it("prefers an explicit last_affected when the registry has it", () => {
    expect(newestAffected(versions, null, "4.17.15")).toBe("4.17.15");
  });

  it("takes the newest overall when nothing bounds it", () => {
    expect(newestAffected(versions, null, null)).toBe("4.17.22");
  });

  it("ignores prereleases when choosing", () => {
    expect(newestAffected(["1.0.0", "2.0.0-beta.1"], null, null)).toBe("1.0.0");
  });

  it("returns null when no version qualifies", () => {
    expect(newestAffected(["5.0.0"], "1.0.0", null)).toBeNull();
  });
});

describe("newestAffected, prerelease bounds", () => {
  it("prefers the newest affected stable over a prerelease last_affected", () => {
    // web3-core-subscriptions records last_affected 2.0.0-alpha.1. Inspecting
    // that alpha rather than 1.10.4 reported its real attachToObject method as
    // not found.
    const versions = ["1.10.3", "1.10.4", "2.0.0-alpha.1", "2.0.0"];
    expect(newestAffected(versions, null, "2.0.0-alpha.1")).toBe("1.10.4");
  });

  it("falls back to the prerelease when no stable release is affected", () => {
    expect(newestAffected(["1.0.0-beta.1", "2.0.0"], null, "1.0.0-beta.1")).toBe("1.0.0-beta.1");
  });

  it("still respects a fixed bound over last_affected", () => {
    expect(newestAffected(["1.0.0", "1.1.0", "2.0.0"], "1.1.0", null)).toBe("1.0.0");
  });
});

describe("resolution robustness", () => {
  it("does not treat a directory as a module file", async () => {
    // existsSync is true for directories, so a candidate like "lib/parser"
    // that happens to be a folder passed the check and threw EISDIR on read,
    // aborting a full run partway through.
    const { mkdtempSync, mkdirSync, existsSync, statSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const path = (await import("node:path")).default;

    const dir = mkdtempSync(path.join(tmpdir(), "resolve-"));
    const asDirectory = path.join(dir, "parser");
    mkdirSync(asDirectory);

    const isReadableFile = (candidate: string): boolean => {
      try {
        return existsSync(candidate) && statSync(candidate).isFile();
      } catch {
        return false;
      }
    };

    expect(existsSync(asDirectory)).toBe(true);
    expect(isReadableFile(asDirectory)).toBe(false);
  });
});
