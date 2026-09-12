import { extractSymbolsFromText } from "../src/extract-symbols.js";

describe("extractSymbolsFromText", () => {
  it("reads a single unmarked function name from real advisory prose", () => {
    // GHSA-35jh-r3h4-6jhm / CVE-2021-23337, verbatim.
    const details =
      "`lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the template function.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["template"]);
  });

  it("reads a backticked list of function names", () => {
    // GHSA-29mw-wpgm-hmr9 / CVE-2020-28500, verbatim.
    const details =
      "All versions of package lodash prior to 4.17.21 are vulnerable to Regular " +
      "Expression Denial of Service (ReDoS) via the `toNumber`, `trim` and `trimEnd` functions.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["toNumber", "trim", "trimEnd"]);
  });

  it("returns nothing when the advisory names no function", () => {
    // GHSA-hrpp-h998-j3pp / CVE-2022-24999. Names a property, not a function.
    const details =
      "qs before 6.10.3 allows attackers to cause a Node process hang because an " +
      "`__proto__` key can be used.";
    expect(extractSymbolsFromText(details).symbols).toEqual([]);
  });

  it("keeps the excerpt so a reviewer can see the source sentence", () => {
    const details = "Vulnerable to prototype pollution via the `merge` function.";
    expect(extractSymbolsFromText(details).excerpt).toContain("merge");
  });

  it("strips call parentheses", () => {
    expect(extractSymbolsFromText("Prototype pollution via the `merge()` method.").symbols).toEqual(
      ["merge"],
    );
  });

  it("takes the export name from a dotted reference", () => {
    expect(extractSymbolsFromText("Exploitable via the lodash.template function.").symbols).toEqual(
      ["template"],
    );
  });

  it("ignores prose words that are not identifiers", () => {
    expect(extractSymbolsFromText("Patched the vulnerable function in 1.2.3.").symbols).toEqual([]);
  });

  it("prefers backticked names over surrounding prose in the same span", () => {
    const details = "Reachable through the exported `parse` function.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["parse"]);
  });

  it("deduplicates repeated names", () => {
    const details = "Via the `trim`, `trim` and `trimEnd` functions.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["trim", "trimEnd"]);
  });

  it("returns nothing for empty input", () => {
    expect(extractSymbolsFromText("").symbols).toEqual([]);
  });
});

describe("ambiguous words", () => {
  it("accepts a common noun when the advisory marks it as code", () => {
    // jsuites, real advisory: "in the Editor() function".
    expect(extractSymbolsFromText("Reachable in the Editor() function.").symbols).toEqual([
      "Editor",
    ]);
  });

  it("rejects the same word used as prose", () => {
    // @oneuptime/common, real advisory: "in proxies, but it still forwards".
    expect(
      extractSymbolsFromText("Fails in proxies, but it still forwards the method calls.").symbols,
    ).toEqual([]);
  });

  it("rejects a path segment rather than splitting it into a symbol", () => {
    // vm2, real advisory: "In lib/setup-sandbox.js, the callback function".
    expect(
      extractSymbolsFromText("In lib/setup-sandbox.js, the callback function is reached.").symbols,
    ).toEqual([]);
  });

  it("rejects a sentence-initial prose word", () => {
    // flowise, real advisory: "However, it is also NOT protected by the ... API".
    expect(
      extractSymbolsFromText("Listed in `WHITELIST_URLS`. However, it is exposed by the API.")
        .symbols,
    ).toEqual([]);
  });
});

describe("negation", () => {
  it("does not extract a symbol from a sentence saying it is safe", () => {
    // h3, real advisory: "using `path.join()` are not affected since ...".
    const details = "Callers using `path.join()` are not affected since %2e%2e is not resolved.";
    expect(extractSymbolsFromText(details).symbols).toEqual([]);
  });

  it("still extracts when the negation is in an unrelated later sentence", () => {
    const details = "Prototype pollution via the `merge` function. Version 2.0 is not affected.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["merge"]);
  });
});

describe("query operators", () => {
  it("rejects $-prefixed operator names", () => {
    // "selectors on `$where` clauses are passed to a Function" describes a data
    // key, not an export. A call pattern for it can never match, and that
    // no-match would read as proof of safety.
    const details = "In the DocumentMatcher class, selectors on `$where` clauses are passed to a Function.";
    expect(extractSymbolsFromText(details).symbols).not.toContain("$where");
  });
});

describe("rejections found by reviewing the likely-wrong band", () => {
  // Each case below is a real record that was proposed, adjudicated as wrong,
  // and deleted. The test is what stops the extractor producing that shape
  // again, which is the part of review that compounds.

  it("takes the symbol after the 'entry function(s)' stock phrase, not the word entry", () => {
    // GHSA-hjwq-mjwj-4x6c, @intlify/shared, verbatim. The general patterns read
    // "the <X> function" and took the literal word "entry".
    const details =
      "@intlify/shared is vulnerable to Prototype Pollution through the entry " +
      "function(s) `lib.deepCopy`. An attacker can supply a payload.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["deepCopy"]);
  });

  it("handles the same phrase with a bare name", () => {
    // GHSA-p2ph-7g93-hw3m.
    const details = "vulnerable to Prototype Pollution through the entry function(s) `handleFlatJson`.";
    expect(extractSymbolsFromText(details).symbols).toEqual(["handleFlatJson"]);
  });

  it("rejects a proper noun standing before API", () => {
    // eta, "using the Express API". Express is a different package entirely.
    expect(extractSymbolsFromText("Vulnerable when using the Express API.").symbols).toEqual([]);
  });

  it("rejects JavaScript builtins named as the sink", () => {
    // vm2 "using the host `apply` method", mversion "inside the exec function",
    // flowise "`globalThis` and `eval`". None are exports of those packages.
    expect(extractSymbolsFromText("Escape using the host `apply` method.").symbols).toEqual([]);
    expect(extractSymbolsFromText("Injection inside the exec function.").symbols).toEqual([]);
  });

  it("rejects an endpoint or feature name standing before API", () => {
    // flowise "in Prediction API", @node-red/runtime "via the Projects API".
    expect(extractSymbolsFromText("Unauthorised access in Prediction API.").symbols).toEqual([]);
    expect(extractSymbolsFromText("Path traversal via the Projects API.").symbols).toEqual([]);
  });

  it("rejects English nouns listed before APIs", () => {
    // axios, "in panels, or microservice APIs".
    expect(extractSymbolsFromText("SSRF in panels, or microservice APIs.").symbols).toEqual([]);
  });
});
