/**
 * Checks whether a fix commit's diff references a symbol the advisory prose
 * named.
 *
 * This raises confidence, not coverage. The schema defines `high` as prose and
 * fix commit independently agreeing, and until now nothing could reach it
 * because only the prose half existed.
 *
 * It deliberately does not try to *discover* symbols from a diff. Doing that
 * soundly means resolving which function encloses each changed line, which
 * needs the whole file parsed rather than the patch alone. The lodash command
 * injection fix demonstrates why: the change sits inside `template`, but the
 * patch never declares it, and names it only inside a comment and an error
 * string.
 */

/** Escapes a symbol for safe use inside a generated pattern. */
function escapeForPattern(symbol: string): string {
  return symbol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Symbols at or below this length are too common for a loose match to mean
 * anything. Names like `set`, `get`, `add`, `exec` and `parse` appear in almost
 * any JavaScript diff, so `.set(` is a coincidence rather than corroboration.
 */
const SHORT_SYMBOL_LENGTH = 5;

/**
 * Matches that only count as evidence for a distinctive name.
 *
 * A member access or a bare call is weak: it says the token appears in a
 * calling position somewhere in the diff, which for a common name is nearly
 * guaranteed.
 */
function looseMentionPatterns(name: string): RegExp[] {
  return [
    new RegExp(`\\.${name}\\s*[(=,;)\\]}]`),
    new RegExp(`\\.${name}\\b`),
    new RegExp(`\\b${name}\\s*\\(`),
  ];
}

/**
 * Matches that state the symbol is defined or exported here, not merely used.
 * These are the only ones trusted for a short, common name.
 */
function declarationPatterns(name: string): RegExp[] {
  return [
    new RegExp(`\\bfunction\\s+${name}\\b`),
    new RegExp(`\\bexports\\.${name}\\s*=`),
    new RegExp(`\\bmodule\\.exports\\.${name}\\s*=`),
    new RegExp(`\\b${name}\\s*[:=]\\s*(?:async\\s+)?function\\b`),
    new RegExp(`\\b${name}\\s*[:=]\\s*\\([^)]*\\)\\s*=>`),
    new RegExp(`\\b(?:const|let|var)\\s+${name}\\s*=`),
    new RegExp(`\\bclass\\s+${name}\\b`),
  ];
}

/**
 * Contexts that mark a mention as code rather than coincidence.
 *
 * Distinctive names may be recognised by use, since seeing `zipObjectDeep` in a
 * diff is itself informative. Short names must be seen being defined.
 */
function buildMentionPatterns(symbol: string): RegExp[] {
  const name = escapeForPattern(symbol);
  const declarations = declarationPatterns(name);
  if (symbol.length <= SHORT_SYMBOL_LENGTH) {
    return declarations;
  }
  return [...declarations, ...looseMentionPatterns(name)];
}

/** Only added and removed lines count. Context lines were not changed. */
function changedLines(patch: string): string {
  return patch
    .split("\n")
    .filter(line => (line.startsWith("+") || line.startsWith("-")) && !line.startsWith("+++") && !line.startsWith("---"))
    .join("\n");
}

export interface CorroborationResult {
  readonly corroborated: readonly string[];
  readonly uncorroborated: readonly string[];
}

/**
 * Splits the advisory's symbols by whether the diff references them.
 *
 * Searches the whole patch rather than only changed lines, because a fix often
 * touches the inside of a function while naming it in adjacent context. Changed
 * lines alone missed the lodash case entirely.
 */
export function corroborateSymbols(
  patch: string,
  symbols: readonly string[],
): CorroborationResult {
  const corroborated: string[] = [];
  const uncorroborated: string[] = [];
  for (const symbol of symbols) {
    const patterns = buildMentionPatterns(symbol);
    if (patterns.some(pattern => pattern.test(patch))) {
      corroborated.push(symbol);
    } else {
      uncorroborated.push(symbol);
    }
  }
  return { corroborated, uncorroborated };
}

/** True when every symbol the advisory named is referenced by the diff. */
export function isFullyCorroborated(patch: string, symbols: readonly string[]): boolean {
  if (symbols.length === 0) {
    return false;
  }
  return corroborateSymbols(patch, symbols).uncorroborated.length === 0;
}

export { changedLines };
