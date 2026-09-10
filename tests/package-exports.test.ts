import { scanExports, ExportScanResult } from "../src/package-exports.js";

describe("scanExports, CommonJS", () => {
  it("reads exports.name assignments", () => {
    const scan = scanExports("index.js", "exports.trim = function (s) {};\nexports.trimEnd = function () {};");
    expect(scan.result).toBe(ExportScanResult.Parsed);
    expect(scan.names).toEqual(["trim", "trimEnd"]);
  });

  it("reads module.exports object literals", () => {
    const scan = scanExports("index.js", "function a(){}\nfunction b(){}\nmodule.exports = { a, b };");
    expect(scan.names).toEqual(["a", "b"]);
  });

  it("reads module.exports.name assignments", () => {
    expect(scanExports("index.js", "module.exports.parseLookup = fn;").names).toEqual(["parseLookup"]);
  });
});

describe("scanExports, ESM", () => {
  it("reads exported function and const declarations", () => {
    const scan = scanExports("index.ts", "export function template(){}\nexport const VERSION = '1';");
    expect(scan.names).toEqual(["VERSION", "template"]);
  });

  it("reads named export clauses", () => {
    expect(scanExports("index.js", "function x(){}\nexport { x };").names).toEqual(["x"]);
  });
});

describe("scanExports, honest unknowns", () => {
  // Every case here must report Unknown rather than an empty export list.
  // Absence of a name only means something if the scan was complete, and a
  // wrong rejection here would delete a correct record.

  it("is unknown when the module re-exports from elsewhere", () => {
    const scan = scanExports("index.js", "export * from './lib.js';\nexport function local(){}");
    expect(scan.result).toBe(ExportScanResult.Unknown);
  });

  it("is unknown when module.exports is assigned a require call", () => {
    const scan = scanExports("index.js", "module.exports = require('./lib');");
    expect(scan.result).toBe(ExportScanResult.Unknown);
  });

  it("is unknown when module.exports is assigned a function", () => {
    // The UMD and single-function packages that this covers are common.
    const scan = scanExports("index.js", "module.exports = function kill(pid) {};");
    expect(scan.result).toBe(ExportScanResult.Unknown);
  });

  it("is unknown for a minified bundle", () => {
    const scan = scanExports("index.min.js", `var a=1;${"x".repeat(2500)}`);
    expect(scan.result).toBe(ExportScanResult.Unknown);
    expect(scan.reason).toContain("minified");
  });

  it("is unknown when nothing is exported at all", () => {
    expect(scanExports("index.js", "const x = 1;").result).toBe(ExportScanResult.Unknown);
  });
});
