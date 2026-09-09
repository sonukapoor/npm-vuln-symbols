import { Confidence, ECOSYSTEM_NPM, EvidenceSource, type SymbolRecord } from "./types.js";

/**
 * Shape validation for a dataset record.
 *
 * Hand-written rather than schema-driven so the failure messages name the file
 * and the offending field. `schema/advisory.schema.json` remains the contract
 * published for external consumers; this enforces the same rules in CI.
 */

const ADVISORY_ID_PATTERN = /^(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|CVE-\d{4}-\d{4,})$/;
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

const CONFIDENCE_VALUES = new Set<string>(Object.values(Confidence));
const EVIDENCE_SOURCE_VALUES = new Set<string>(Object.values(EvidenceSource));

function isRecordObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateIdentity(record: Record<string, unknown>, errors: string[]): void {
  if (typeof record["id"] !== "string" || !ADVISORY_ID_PATTERN.test(record["id"])) {
    errors.push("id must be a GHSA or CVE identifier");
  }
  if (!Array.isArray(record["aliases"])) {
    errors.push("aliases must be an array");
  }
}

function validateSymbols(symbols: unknown, label: string, errors: string[]): void {
  if (!Array.isArray(symbols) || symbols.length === 0) {
    // An entry naming no symbols carries no information and would be read
    // downstream as "nothing here is reachable", which is the unsafe answer.
    errors.push(`${label}.symbols must be a non-empty array`);
    return;
  }
  for (const symbol of symbols) {
    if (typeof symbol !== "string" || !IDENTIFIER_PATTERN.test(symbol)) {
      errors.push(`${label}: symbol ${JSON.stringify(symbol)} is not a valid identifier`);
    }
  }
  if (new Set(symbols).size !== symbols.length) {
    errors.push(`${label}.symbols must not contain duplicates`);
  }
}

function validateAffected(record: Record<string, unknown>, errors: string[]): void {
  const affected = record["affected"];
  if (!Array.isArray(affected) || affected.length === 0) {
    errors.push("affected must be a non-empty array");
    return;
  }
  const seen = new Set<string>();
  affected.forEach((entry, index) => {
    const label = `affected[${index}]`;
    if (!isRecordObject(entry)) {
      errors.push(`${label} must be an object`);
      return;
    }
    const pkg = entry["package"];
    if (!isRecordObject(pkg)) {
      errors.push(`${label}.package must be an object`);
      return;
    }
    if (pkg["ecosystem"] !== ECOSYSTEM_NPM) {
      errors.push(`${label}.package.ecosystem must be "${ECOSYSTEM_NPM}"`);
    }
    const name = pkg["name"];
    if (typeof name !== "string" || name.length === 0) {
      errors.push(`${label}.package.name must be a non-empty string`);
    } else if (seen.has(name)) {
      errors.push(`${label}: package ${name} appears more than once`);
    } else {
      seen.add(name);
    }
    validateSymbols(entry["symbols"], label, errors);
  });
}

function validateEvidence(record: Record<string, unknown>, errors: string[]): void {
  const evidence = record["evidence"];
  if (!isRecordObject(evidence)) {
    errors.push("evidence must be an object");
    return;
  }
  if (typeof evidence["source"] !== "string" || !EVIDENCE_SOURCE_VALUES.has(evidence["source"])) {
    errors.push("evidence.source is not a recognised value");
  }
  if (
    typeof evidence["confidence"] !== "string" ||
    !CONFIDENCE_VALUES.has(evidence["confidence"])
  ) {
    errors.push("evidence.confidence is not a recognised value");
  }
}

function validateReview(record: Record<string, unknown>, errors: string[]): void {
  const reviewedAt = record["reviewedAt"];
  if (reviewedAt !== undefined && (typeof reviewedAt !== "string" || !ISO_DATE_PATTERN.test(reviewedAt))) {
    errors.push("reviewedAt must be an ISO date, YYYY-MM-DD");
  }
}

/** Returns the list of problems with a parsed record. Empty means valid. */
export function validateRecord(value: unknown): string[] {
  if (!isRecordObject(value)) {
    return ["record must be a JSON object"];
  }
  const errors: string[] = [];
  validateIdentity(value, errors);
  validateAffected(value, errors);
  validateEvidence(value, errors);
  validateReview(value, errors);
  return errors;
}

/** Narrowing helper for callers that have already validated. */
export function isSymbolRecord(value: unknown): value is SymbolRecord {
  return validateRecord(value).length === 0;
}
