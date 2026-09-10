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
 * Contexts that mark a mention as code rather than coincidence.
 *
 * A bare word match is far too loose: "template" appears inside
 * `INVALID_TEMPL_VAR_ERROR_TEXT` and in prose comments that have nothing to do
 * with the export. Requiring a call, a member access, a declaration or an
 * object key keeps the signal meaningful.
 */
function buildMentionPatterns(symbol: string): RegExp[] {
  const name = escapeForPattern(symbol);
  return [
    new RegExp(`\\bfunction\\s+${name}\\b`),
    new RegExp(`\\.${name}\\s*[(=,;)\\]}]`),
    new RegExp(`\\.${name}\\b`),
    new RegExp(`\\b${name}\\s*[:=]\\s*function\\b`),
    new RegExp(`\\bexports\\.${name}\\b`),
    new RegExp(`\\b${name}\\s*\\(`),
  ];
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
