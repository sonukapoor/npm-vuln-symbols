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

describe("scanExports, methods reachable through an export", () => {
  // Collecting only top-level exports reported these absent, which would have
  // told a reviewer to delete correct records.

  it("finds a prototype method", () => {
    // web3-core-subscriptions, the shape its advisory names.
    const source = "function Subscription(){}\nSubscription.prototype.attachToObject = function (obj) {};\nmodule.exports = { Subscription };";
    expect(scanExports("index.js", source).names).toContain("attachToObject");
  });

  it("finds a class method", () => {
    const source = "export class LinkifyIt {\n  test(text) { return true; }\n}";
    expect(scanExports("index.ts", source).names).toContain("test");
  });

  it("finds methods on a prototype object literal", () => {
    const source = "function L(){}\nL.prototype = { test(t) { return true; } };\nmodule.exports = L;";
    expect(scanExports("index.js", source).names).toContain("test");
  });

  it("does not harvest unrelated object literals as exports", () => {
    // lodash's HTML entity table was collected as 258 "exports", after which
    // the scanner declared `template` absent with apparent confidence.
    const source = [
      "var htmlEscapes = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };",
      "exports.escape = function (s) { return s; };",
    ].join("\n");
    const names = scanExports("index.js", source).names;
    expect(names).toEqual(["escape"]);
    expect(names).not.toContain("&amp;");
  });
});

describe("scanExports, detecting incomplete understanding", () => {
  it("is unknown when a large file yields implausibly few exports", () => {
    // lodash's 530KB entry builds its exports inside a UMD closure. The parser
    // recovers about thirty prototype methods and none of the main functions,
    // so reporting `template` absent would be a confident wrong answer.
    const filler = "\n// padding line to grow the file without adding exports";
    const source = `exports.only = function () {};${filler.repeat(2000)}`;
    const scan = scanExports("big.js", source);
    expect(scan.result).toBe(ExportScanResult.Unknown);
    expect(scan.reason).toContain("not understood");
  });

  it("stays parsed for a small file with few exports", () => {
    const scan = scanExports("small.js", "exports.customAlphabet = function () {};");
    expect(scan.result).toBe(ExportScanResult.Parsed);
  });
});

describe("scanExports, TypeScript declarations", () => {
  // A .d.ts states the export surface directly, so it reads cleanly where a
  // bundle does not. handlebars' lib/index.js yields nothing while its
  // types/index.d.ts yields 64 names.

  it("reads declared function exports", () => {
    const source = "export declare function create(options?: object): Handlebars;";
    expect(scanExports("index.d.ts", source).names).toContain("create");
  });

  it("reads declared class exports", () => {
    expect(scanExports("index.d.ts", "export declare class AxiosHeaders {}").names).toContain(
      "AxiosHeaders",
    );
  });

  it("reads declared const exports", () => {
    const source = "export declare const ECONNABORTED: string;";
    expect(scanExports("index.d.ts", source).names).toContain("ECONNABORTED");
  });

  it("is unknown for a barrel that only re-exports", () => {
    // A declaration file forwarding to other files is not the whole surface,
    // and treating it as complete would produce false not-found suspicions.
    const scan = scanExports("index.d.ts", 'export * from "./client";');
    expect(scan.result).toBe(ExportScanResult.Unknown);
  });
});
