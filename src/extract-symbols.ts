/**
 * Reads vulnerable function names out of advisory description prose.
 *
 * npm advisories carry no machine-readable field naming the vulnerable export,
 * but they very often name it in English: "vulnerable to Command Injection via
 * the `template` function". This module recovers those names so a human only
 * has to confirm them rather than research them.
 *
 * It is deliberately conservative. A false positive here suppresses a real
 * vulnerability downstream, so anything ambiguous is dropped rather than
 * guessed at.
 */

/**
 * Grammar words that can never be an export name. Rejected unconditionally.
 */
const NEVER_SYMBOL_WORDS = new Set([
  "the", "a", "an", "this", "that", "it", "its", "their", "other", "others",
  "new", "any", "some", "such", "these", "those", "and", "or", "however",
  "many", "most", "all", "both", "each", "every", "only", "also", "still",
  "then", "when", "where", "which", "while", "with", "without", "for", "from",
  "into", "onto", "over", "under", "above", "below", "same", "given",
  "certain", "specific", "arbitrary", "malicious", "crafted", "untrusted",
  "unsanitized", "unvalidated", "vulnerable", "affected", "following",
  "underlying", "internal", "exported", "default", "main",
  "arrow", "anonymous", "ui", "env", "clipboard",
]);

/**
 * Words that are ordinary English nouns but also plausible export names.
 *
 * Rejected only when the advisory did not mark the candidate as code. An
 * advisory writing `Editor()` or `` `path` `` means the identifier; one writing
 * "in proxies, but it still forwards" means the English word.
 */
const AMBIGUOUS_SYMBOL_WORDS = new Set([
  "lib", "src", "dist", "node", "npm", "package", "packages", "module",
  "modules", "library", "version", "versions", "server", "client", "request",
  "response", "user", "users", "input", "output", "value", "values", "object",
  "objects", "string", "array", "path", "paths", "file", "files", "board",
  "proxies", "proxy", "sandbox", "editor", "render", "component", "remote",
  "local", "public", "private", "constructor", "callback", "handler",
  "helper", "utility",
]);

/** JavaScript identifiers, allowing the `$` and `_` that npm packages use. */
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * Source file extensions. A dotted reference ending in one of these is a
 * filename such as `Render.tsx`, not a package export, and the segment after
 * the dot must not be mistaken for a symbol.
 */
const FILE_EXTENSIONS = new Set(["ts", "tsx", "js", "jsx", "mjs", "cjs", "json", "md", "html"]);

/**
 * Phrases that introduce a list of function names. The captured group is the
 * span between the introducer and the word "function", which is then split
 * into candidate identifiers.
 */
const INTRODUCERS = "via|in|through|using|within|inside";

/**
 * The span may not itself contain another introducer or a sentence break.
 *
 * Without that restriction the match runs from the first "in" in the summary
 * all the way to a "function" several clauses later, and the span then
 * contains the backticked *package* name, which is picked up as the symbol.
 * Anchoring to the nearest introducer keeps the span to one clause.
 */
const SPAN = `(?:(?!\\b(?:${INTRODUCERS})\\b|\\.\\s)[^;:]){1,120}?`;

const SYMBOL_PHRASE_PATTERNS: readonly RegExp[] = [
  new RegExp(`(?:${INTRODUCERS})\\s+(?:the\\s+)?(${SPAN})\\s+(?:function|method|api)s?\\b`, "gi"),
  new RegExp(`\\bthe\\s+(${SPAN})\\s+(?:function|method|api)s?\\s+(?:is|are|was|were)\\s+vulnerable`, "gi"),
];

/** Splits a captured span on commas and conjunctions. */
const LIST_SEPARATOR_PATTERN = /\s*(?:,|\band\b|\bor\b)\s*/;

const BACKTICKED_PATTERN = /`([^`]+)`/g;

/**
 * A period followed by whitespace ends a sentence. A period inside an
 * identifier (`lodash.template`) does not, which is why this is not simply
 * excluded from the captured span.
 */
const SENTENCE_BREAK_PATTERN = /\.\s/g;

const MAX_SYMBOL_LENGTH = 64;

/**
 * Names beginning with `$` are overwhelmingly query or template operators
 * (`$where`, `$gt`, `$ne`), which are data keys rather than callable exports.
 * A call pattern for one can never match, and the resulting no-match reads as
 * "not reachable". Rejecting them keeps the finding in the queue instead.
 */
const OPERATOR_PREFIX = "$";

/**
 * Phrases marking a span as describing what is *not* vulnerable.
 *
 * Advisories routinely contrast the broken path with a safe one ("callers
 * using `path.join()` are not affected"). Extracting from those sentences
 * produces a symbol that is provably the wrong answer, so the whole match is
 * discarded rather than trusted.
 */
const NEGATION_PATTERN = /\b(?:not affected|unaffected|is not vulnerable|are not vulnerable|no longer|safe|mitigat|fixed in|patched in)\b/i;

/**
 * Strips call parentheses and surrounding punctuation from one candidate.
 * Returns null when what is left is not a plausible export name.
 */
function normaliseCandidate(raw: string, isMarkedAsCode: boolean): string | null {
  const hasCallParens = /\(\s*\)\s*$/.test(raw.trim());
  const trimmed = raw.trim().replace(/\(\s*\)$/, "").replace(/^[`'"]|[`'".,]$/g, "").trim();
  if (trimmed.length === 0 || trimmed.length > MAX_SYMBOL_LENGTH) {
    return null;
  }
  // A path segment means this is a file reference, not an export name.
  if (trimmed.includes("/") || trimmed.includes("\\")) {
    return null;
  }
  // Dotted forms such as `lodash.template` name the export after the dot.
  const lastSegment = trimmed.includes(".") ? (trimmed.split(".").pop() ?? trimmed) : trimmed;
  if (FILE_EXTENSIONS.has(lastSegment.toLowerCase())) {
    return null;
  }
  if (!IDENTIFIER_PATTERN.test(lastSegment)) {
    return null;
  }
  if (lastSegment.startsWith(OPERATOR_PREFIX)) {
    return null;
  }
  const lowered = lastSegment.toLowerCase();
  if (NEVER_SYMBOL_WORDS.has(lowered)) {
    return null;
  }
  if (!isMarkedAsCode && !hasCallParens && AMBIGUOUS_SYMBOL_WORDS.has(lowered)) {
    return null;
  }
  return lastSegment;
}

/**
 * Pulls candidates out of one captured span.
 *
 * Backticked names are strongly preferred: when an advisory marks up any of the
 * names, unmarked words in the same span are prose rather than identifiers.
 */
function candidatesFromSpan(span: string): string[] {
  const breaks = [...span.matchAll(SENTENCE_BREAK_PATTERN)];
  const lastBreak = breaks.at(-1);
  const scoped = lastBreak === undefined ? span : span.slice(lastBreak.index + lastBreak[0].length);
  const backticked = [...scoped.matchAll(BACKTICKED_PATTERN)].map(match => match[1] ?? "");
  const isMarkedAsCode = backticked.length > 0;
  const parts = isMarkedAsCode ? backticked : scoped.split(LIST_SEPARATOR_PATTERN);
  const symbols: string[] = [];
  for (const part of parts) {
    const symbol = normaliseCandidate(part, isMarkedAsCode);
    if (symbol !== null) {
      symbols.push(symbol);
    }
  }
  return symbols;
}

export interface ExtractionResult {
  readonly symbols: readonly string[];
  /** The sentence the names were read from, kept for reviewer context. */
  readonly excerpt?: string;
}

/**
 * Extracts vulnerable symbol names from advisory description text.
 * Returns an empty result when nothing can be established confidently.
 */
export function extractSymbolsFromText(details: string): ExtractionResult {
  for (const pattern of SYMBOL_PHRASE_PATTERNS) {
    pattern.lastIndex = 0;
    for (const match of details.matchAll(pattern)) {
      const span = match[1];
      if (span === undefined) {
        continue;
      }
      if (NEGATION_PATTERN.test(match[0])) {
        continue;
      }
      const symbols = candidatesFromSpan(span);
      if (symbols.length > 0) {
        return { symbols: [...new Set(symbols)], excerpt: match[0].trim() };
      }
    }
  }
  return { symbols: [] };
}
