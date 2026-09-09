import {
  buildEntries,
  eliminationRate,
  tally,
  PACKAGE_SUFFIX,
  SYMBOL_SUFFIX,
} from "../src/probe-analysis.js";
import { Confidence, ECOSYSTEM_NPM, EvidenceSource, type SymbolRecord } from "../src/types.js";

const lodashTemplate: SymbolRecord = {
  id: "GHSA-35jh-r3h4-6jhm",
  aliases: ["CVE-2021-23337"],
  affected: [{ package: { ecosystem: ECOSYSTEM_NPM, name: "lodash" }, symbols: ["template"] }],
  evidence: { source: EvidenceSource.AdvisoryText, confidence: Confidence.Medium },
};

const lodashAffected = [
  { package: { name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] },
];

describe("buildEntries", () => {
  it("emits both a package-level and a symbol-level entry", () => {
    const entries = buildEntries(lodashTemplate, lodashAffected);
    expect(entries.map(e => e.osv.id)).toEqual([
      `GHSA-35jh-r3h4-6jhm${PACKAGE_SUFFIX}`,
      `GHSA-35jh-r3h4-6jhm${SYMBOL_SUFFIX}`,
    ]);
  });

  it("carries the OSV version ranges onto both entries", () => {
    // Without ranges the analyzer cannot establish that the installed version
    // is affected, and reports no match at all.
    for (const entry of buildEntries(lodashTemplate, lodashAffected)) {
      expect(entry.osv.affected[0]?.ranges).toBeDefined();
    }
  });

  it("uses an import pattern for the package rung and a call pattern for the symbol rung", () => {
    const [pkg, sym] = buildEntries(lodashTemplate, lodashAffected);
    expect(pkg?.patterns).toEqual(["import <lodash>"]);
    expect(sym?.patterns).toEqual(["call <lodash>.template"]);
  });

  it("emits nothing when the advisory does not affect a package we have ranges for", () => {
    expect(buildEntries(lodashTemplate, [{ package: { name: "something-else" } }])).toEqual([]);
  });
});

describe("tally", () => {
  it("separates the two rungs and ignores empty matches", () => {
    const result = tally({
      [`GHSA-1${PACKAGE_SUFFIX}`]: [{}, {}],
      [`GHSA-1${SYMBOL_SUFFIX}`]: [],
      [`GHSA-2${PACKAGE_SUFFIX}`]: [{}],
      [`GHSA-2${SYMBOL_SUFFIX}`]: [{}],
    });
    expect(result.imported).toEqual(["GHSA-1", "GHSA-2"]);
    expect(result.reachable).toEqual(["GHSA-2"]);
  });
});

describe("eliminationRate", () => {
  it("measures against the package-level baseline", () => {
    expect(eliminationRate({ imported: ["a", "b"], reachable: ["b"] })).toBe(50);
  });

  it("is zero when nothing was imported, not a division by zero", () => {
    expect(eliminationRate({ imported: [], reachable: [] })).toBe(0);
  });

  it("is zero when everything imported is also reachable", () => {
    expect(eliminationRate({ imported: ["a"], reachable: ["a"] })).toBe(0);
  });
});
