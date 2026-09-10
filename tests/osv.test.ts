import { findFixCommitUrl, findNpmPackages } from "../src/osv.js";
import type { OsvRecord } from "../src/osv.js";

describe("findFixCommitUrl", () => {
  it("finds a commit linked under type WEB", () => {
    // GHSA-35jh-r3h4-6jhm, verbatim. The FIX reference type is used zero times
    // across the whole npm GHSA feed, so filtering on it found nothing at all.
    const record: OsvRecord = {
      id: "GHSA-35jh-r3h4-6jhm",
      references: [
        { type: "ADVISORY", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" },
        {
          type: "WEB",
          url: "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c",
        },
        { type: "WEB", url: "https://www.oracle.com/security-alerts/cpuoct2021.html" },
      ],
    };
    expect(findFixCommitUrl(record)).toBe(
      "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c",
    );
  });

  it("prefers an explicitly typed FIX reference when one exists", () => {
    const record: OsvRecord = {
      id: "GHSA-test",
      references: [
        { type: "WEB", url: "https://github.com/o/r/commit/aaaaaaa" },
        { type: "FIX", url: "https://github.com/o/r/commit/bbbbbbb" },
      ],
    };
    expect(findFixCommitUrl(record)).toBe("https://github.com/o/r/commit/bbbbbbb");
  });

  it("ignores repository and advisory links that are not commits", () => {
    const record: OsvRecord = {
      id: "GHSA-test",
      references: [
        { type: "PACKAGE", url: "https://github.com/lodash/lodash" },
        { type: "WEB", url: "https://github.com/lodash/lodash/blob/ddfd9b1/lodash.js#L14851" },
        { type: "ADVISORY", url: "https://snyk.io/vuln/SNYK-JS-LODASH-1040724" },
      ],
    };
    expect(findFixCommitUrl(record)).toBeNull();
  });

  it("matches a GitLab commit path", () => {
    const record: OsvRecord = {
      id: "GHSA-test",
      references: [{ type: "WEB", url: "https://gitlab.com/group/proj/-/commit/1234567890abcdef" }],
    };
    expect(findFixCommitUrl(record)).toContain("/-/commit/");
  });

  it("returns null when there are no references at all", () => {
    expect(findFixCommitUrl({ id: "GHSA-test" })).toBeNull();
  });
});

describe("findNpmPackages", () => {
  it("returns every npm package and drops other ecosystems", () => {
    // The lodash advisory also affects a RubyGems package.
    const record: OsvRecord = {
      id: "GHSA-35jh-r3h4-6jhm",
      affected: [
        { package: { ecosystem: "npm", name: "lodash" } },
        { package: { ecosystem: "npm", name: "lodash-es" } },
        { package: { ecosystem: "RubyGems", name: "lodash-rails" } },
      ],
    };
    expect(findNpmPackages(record)).toEqual(["lodash", "lodash-es"]);
  });
});
