/**
 * Confidence that the named symbols are the ones actually carrying the
 * vulnerability.
 *
 * This is load-bearing rather than decorative. The only claim the dataset
 * supports is the negative one ("your code never calls this, so you are not
 * affected"), so a wrong symbol silently suppresses a real vulnerability.
 * Consumers are expected to treat anything below High as advisory only.
 */
export const Confidence = {
  /** Advisory prose and the fix commit independently agree. */
  High: "high",
  /** Exactly one source names the symbols, and nothing contradicts it. */
  Medium: "medium",
  /** Inferred, incomplete, or disputed. Do not suppress findings on this. */
  Low: "low",
} as const;

export type Confidence = (typeof Confidence)[keyof typeof Confidence];

/** Where the symbol names came from. */
export const EvidenceSource = {
  /** Named in the advisory's own description text. */
  AdvisoryText: "advisory_text",
  /** Derived from the diff of the commit that fixed the advisory. */
  FixCommit: "fix_commit",
  /** Both of the above, in agreement. */
  Both: "advisory_text+fix_commit",
  /** Entered by a human with no automated corroboration. */
  Manual: "manual",
} as const;

export type EvidenceSource = (typeof EvidenceSource)[keyof typeof EvidenceSource];

/**
 * How a vulnerability is triggered.
 *
 * Reachability by call pattern only answers for `Call`. Some advisories are
 * triggered by passing a value, not by invoking an export: marsdb's
 * GHSA-5mrr-rgp6-x4gr fires when a query object contains a `$where` key, which
 * no call to a named export can express.
 *
 * The distinction is safety-critical. On OWASP Juice Shop that advisory was
 * reported "not reachable" while `routes/chat.ts:149` passes `$where` with
 * concatenated user input, which is a live NoSQL injection. Marking the trigger
 * lets a consumer report "cannot determine" instead of silently clearing it.
 */
export const Trigger = {
  /** Calling a named export. Resolvable by call-pattern reachability. */
  Call: "call",
  /** Passing a value or option key. NOT resolvable by call patterns. */
  DataValue: "data_value",
} as const;

export type Trigger = (typeof Trigger)[keyof typeof Trigger];

/** The only ecosystem this dataset covers. */
export const ECOSYSTEM_NPM = "npm";

export interface PackageRef {
  readonly ecosystem: typeof ECOSYSTEM_NPM;
  readonly name: string;
}

export interface Evidence {
  readonly source: EvidenceSource;
  readonly confidence: Confidence;
  /** URL of the commit that fixed the advisory, when one is known. */
  readonly fixCommit?: string;
  /** The sentence the symbol names were read out of, for reviewer context. */
  readonly excerpt?: string;
}

/**
 * One advisory's vulnerable symbols.
 *
 * Shaped to mirror the `ecosystem_specific` convention Go and Rust already use
 * in OSV, so that contributing this upstream is a copy rather than a migration.
 */
export interface AffectedPackage {
  readonly package: PackageRef;
  /**
   * Names of the vulnerable exports, as a consumer would import them.
   * An empty array is not valid: an entry with no symbols carries no
   * information and would read downstream as "nothing here is reachable",
   * which is the unsafe answer.
   */
  readonly symbols: readonly string[];
  /** Optional subpath export, for advisories scoped to one entry point. */
  readonly modulePath?: string;
}

/**
 * One advisory's vulnerable symbols, per affected package.
 *
 * Mirrors OSV's own `affected[]` structure rather than flattening to a single
 * package. Popular libraries are republished under several npm names
 * (`lodash`, `lodash-es`, `lodash.template`), and a one-package-per-record
 * model silently drops exactly those widely-depended-on advisories.
 */
export interface SymbolRecord {
  /** OSV identifier, normally a GHSA id. */
  readonly id: string;
  readonly aliases: readonly string[];
  readonly affected: readonly AffectedPackage[];
  /**
   * Defaults to Call when absent. A DataValue record must never be used to
   * eliminate a finding, because absence of a matching call proves nothing.
   */
  readonly trigger?: Trigger;
  readonly evidence: Evidence;
  readonly notes?: string;
  readonly reviewedBy?: string;
  /** ISO date, YYYY-MM-DD. */
  readonly reviewedAt?: string;
}
