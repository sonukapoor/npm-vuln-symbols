import { validateRecord } from "../src/validate-record.js";
import { Confidence, ECOSYSTEM_NPM, EvidenceSource } from "../src/types.js";

function record(extra: Record<string, unknown>): unknown {
  return {
    id: "GHSA-35jh-r3h4-6jhm",
    aliases: [],
    affected: [{ package: { ecosystem: ECOSYSTEM_NPM, name: "lodash" }, symbols: ["template"] }],
    evidence: { source: EvidenceSource.AdvisoryText, confidence: Confidence.Medium },
    ...extra,
  };
}

describe("reviewMethod", () => {
  it("accepts a review claim that states its method", () => {
    for (const method of ["human", "assisted", "machine"]) {
      const errors = validateRecord(
        record({ reviewedBy: "someone", reviewedAt: "2026-09-12", reviewMethod: method }),
      );
      expect(errors).toEqual([]);
    }
  });

  it("rejects a review claim with no method", () => {
    // The ambiguity this field exists to remove: reviewedBy alone spans a person
    // reading the advisory and an agent reading it with a glance from a human,
    // and a consumer cannot tell which.
    const errors = validateRecord(record({ reviewedBy: "someone", reviewedAt: "2026-09-12" }));
    expect(errors).toContain(
      "reviewedBy requires reviewMethod, so the claim says how it was produced",
    );
  });

  it("rejects a method with nobody attached to it", () => {
    expect(validateRecord(record({ reviewMethod: "human" }))).toContain(
      "reviewMethod requires reviewedBy",
    );
  });

  it("rejects an unrecognised method", () => {
    const errors = validateRecord(record({ reviewedBy: "someone", reviewMethod: "eyeballed" }));
    expect(errors).toContain("reviewMethod must be 'human', 'assisted' or 'machine'");
  });

  it("leaves unreviewed records alone", () => {
    // Most of the dataset has never been reviewed, and saying nothing is the
    // honest state for those.
    expect(validateRecord(record({}))).toEqual([]);
  });
});
