import { corroborateSymbols, isFullyCorroborated } from "../src/commit-corroboration.js";

// Excerpt from the real lodash fix, commit 3469357c, for GHSA-35jh-r3h4-6jhm.
const LODASH_PATCH = [
  "@@ -19,7 +19,8 @@",
  "-      FUNC_ERROR_TEXT = 'Expected a function';",
  "+      FUNC_ERROR_TEXT = 'Expected a function',",
  "+      INVALID_TEMPL_VAR_ERROR_TEXT = 'Invalid `variable` option passed into `_.template`';",
  "@@ -14866,6 +14879,12 @@",
  "+      else if (reForbiddenIdentifierChars.test(variable)) {",
  "+        throw new Error(INVALID_TEMPL_VAR_ERROR_TEXT);",
  "+      }",
].join("\n");

describe("corroborateSymbols", () => {
  it("corroborates a symbol the diff references as a member access", () => {
    // The fix changes code *inside* template and never declares it, naming it
    // only in an error string as `_.template`. That still counts.
    const result = corroborateSymbols(LODASH_PATCH, ["template"]);
    expect(result.corroborated).toEqual(["template"]);
    expect(result.uncorroborated).toEqual([]);
  });

  it("does not corroborate a symbol the diff never mentions", () => {
    const result = corroborateSymbols(LODASH_PATCH, ["zipObjectDeep"]);
    expect(result.corroborated).toEqual([]);
    expect(result.uncorroborated).toEqual(["zipObjectDeep"]);
  });

  it("separates corroborated from uncorroborated in a mixed set", () => {
    const result = corroborateSymbols(LODASH_PATCH, ["template", "merge"]);
    expect(result.corroborated).toEqual(["template"]);
    expect(result.uncorroborated).toEqual(["merge"]);
  });

  it("does not treat a bare word inside an unrelated identifier as a mention", () => {
    // "TEMPL" appears in INVALID_TEMPL_VAR_ERROR_TEXT. A looser matcher would
    // corroborate anything, which would make the confidence upgrade worthless.
    const patch = "+ var INVALID_TEMPL_VAR_ERROR_TEXT = 'nope';";
    expect(corroborateSymbols(patch, ["TEMPL"]).corroborated).toEqual([]);
  });

  it("recognises a function declaration", () => {
    const patch = "+function parseLookup(path) {";
    expect(corroborateSymbols(patch, ["parseLookup"]).corroborated).toEqual(["parseLookup"]);
  });

  it("recognises an exports assignment", () => {
    const patch = "-exports.trim = function (str) {";
    expect(corroborateSymbols(patch, ["trim"]).corroborated).toEqual(["trim"]);
  });
});

describe("isFullyCorroborated", () => {
  it("is true only when every named symbol is referenced", () => {
    expect(isFullyCorroborated(LODASH_PATCH, ["template"])).toBe(true);
    expect(isFullyCorroborated(LODASH_PATCH, ["template", "merge"])).toBe(false);
  });

  it("is false for an empty symbol list", () => {
    // Nothing to agree about is not agreement.
    expect(isFullyCorroborated(LODASH_PATCH, [])).toBe(false);
  });
});

describe("short symbols need declaration-strength evidence", () => {
  // Names like set, get and add appear in a calling position in almost any
  // JavaScript diff, so a member access is a coincidence rather than
  // corroboration. 50 of 171 upgraded records had a symbol of five characters
  // or fewer, which made their "high" confidence unfounded.

  it("does not corroborate a short symbol from a member access alone", () => {
    const patch = "+  cache.set(key, value);\n+  other.set(a, b);";
    expect(corroborateSymbols(patch, ["set"]).corroborated).toEqual([]);
  });

  it("does corroborate a short symbol that is declared in the diff", () => {
    const patch = "+exports.set = function (obj, path, value) {";
    expect(corroborateSymbols(patch, ["set"]).corroborated).toEqual(["set"]);
  });

  it("corroborates a short symbol defined as an arrow function", () => {
    const patch = "+const exec = (cmd) => spawn(cmd);";
    expect(corroborateSymbols(patch, ["exec"]).corroborated).toEqual(["exec"]);
  });

  it("still corroborates a distinctive symbol from use alone", () => {
    // "zipObjectDeep" appearing anywhere in a diff is informative by itself.
    const patch = "+  const result = _.zipObjectDeep(props, values);";
    expect(corroborateSymbols(patch, ["zipObjectDeep"]).corroborated).toEqual(["zipObjectDeep"]);
  });
});
