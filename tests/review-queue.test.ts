import { Band, ExportVerdict, buildEntry, classify, combineVerdicts } from "../src/review-queue.js";
import { Confidence, ECOSYSTEM_NPM, EvidenceSource, type SymbolRecord } from "../src/types.js";

describe("combineVerdicts", () => {
  it("lets one confirming package settle the advisory", () => {
    // lodash's UMD bundle is unreadable while lodash-es confirms the same
    // symbols. One sibling proving the export exists is enough.
    expect(combineVerdicts([ExportVerdict.Unknown, ExportVerdict.Confirmed])).toBe(
      ExportVerdict.Confirmed,
    );
  });

  it("prefers not_found over unknown, since not_found carries information", () => {
    expect(combineVerdicts([ExportVerdict.Unknown, ExportVerdict.NotFound])).toBe(
      ExportVerdict.NotFound,
    );
  });

  it("is unknown when nothing could be read", () => {
    expect(combineVerdicts([ExportVerdict.Unknown])).toBe(ExportVerdict.Unknown);
  });
});

describe("classify", () => {
  it("bands both signals negative as likely wrong", () => {
    const result = classify({
      corroborated: false,
      hasFixCommit: true,
      exportVerdict: ExportVerdict.NotFound,
    });
    expect(result.band).toBe(Band.LikelyWrong);
  });

  it("bands both signals positive as likely right", () => {
    const result = classify({
      corroborated: true,
      hasFixCommit: true,
      exportVerdict: ExportVerdict.Confirmed,
    });
    expect(result.band).toBe(Band.LikelyRight);
  });

  it("bands a disagreement as conflicting, in both directions", () => {
    expect(
      classify({ corroborated: true, hasFixCommit: true, exportVerdict: ExportVerdict.NotFound })
        .band,
    ).toBe(Band.Conflicting);
    expect(
      classify({ corroborated: false, hasFixCommit: true, exportVerdict: ExportVerdict.Confirmed })
        .band,
    ).toBe(Band.Conflicting);
  });

  it("does not call a record likely wrong when there was no fix commit to check", () => {
    // One negative signal and one silence is not two negatives. Treating it as
    // such would send a reviewer to reject records on half the evidence.
    const result = classify({
      corroborated: false,
      hasFixCommit: false,
      exportVerdict: ExportVerdict.NotFound,
    });
    expect(result.band).toBe(Band.WeakSupport);
  });

  it("bands a record with no signal at all as unsupported", () => {
    const result = classify({
      corroborated: false,
      hasFixCommit: false,
      exportVerdict: ExportVerdict.Unknown,
    });
    expect(result.band).toBe(Band.Unsupported);
  });

  it("always explains itself", () => {
    for (const exportVerdict of Object.values(ExportVerdict)) {
      for (const corroborated of [true, false]) {
        for (const hasFixCommit of [true, false]) {
          const { note } = classify({ corroborated, hasFixCommit, exportVerdict });
          expect(note.length).toBeGreaterThan(10);
        }
      }
    }
  });
});

describe("buildEntry", () => {
  const record: SymbolRecord = {
    id: "GHSA-35jh-r3h4-6jhm",
    aliases: ["CVE-2021-23337"],
    affected: [
      { package: { ecosystem: ECOSYSTEM_NPM, name: "lodash" }, symbols: ["template"] },
      { package: { ecosystem: ECOSYSTEM_NPM, name: "lodash-es" }, symbols: ["template"] },
    ],
    evidence: {
      source: EvidenceSource.Both,
      confidence: Confidence.High,
      fixCommit: "https://github.com/lodash/lodash/commit/3469357",
    },
  };

  it("treats high confidence as corroborated", () => {
    const entry = buildEntry(record, [ExportVerdict.Unknown, ExportVerdict.Confirmed]);
    expect(entry.corroborated).toBe(true);
    expect(entry.band).toBe(Band.LikelyRight);
  });

  it("deduplicates symbols across affected packages", () => {
    expect(buildEntry(record, [ExportVerdict.Confirmed]).symbols).toEqual(["template"]);
  });

  it("lists every affected package", () => {
    expect(buildEntry(record, [ExportVerdict.Confirmed]).packages).toEqual(["lodash", "lodash-es"]);
  });
});
