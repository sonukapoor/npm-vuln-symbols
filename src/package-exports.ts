import ts from "typescript";

/**
 * Enumerates the names a JavaScript module exports, by parsing rather than
 * executing it.
 *
 * Executing is not an option here. Some advisories in this dataset are for
 * packages that shipped malware, and importing one to read its keys would run
 * it. So this parses the entry file and accepts that it will not resolve
 * everything.
 *
 * Three outcomes matter, and the third is the important one: a file this cannot
 * understand must report "unknown", never "no exports". Treating a parse
 * failure as absence would reject correct records.
 */

/** Bundled or minified files cannot be read for exports meaningfully. */
const MINIFIED_LINE_LENGTH = 2000;

/**
 * Below this size, finding few exports is unremarkable.
 */
const LARGE_FILE_BYTES = 50_000;

/**
 * A large file yielding very few names means the parser did not model how this
 * module assembles its exports.
 *
 * lodash is the case that forced this. Its 530KB entry builds the export
 * surface inside a UMD closure, so the parser recovers about thirty prototype
 * methods and none of the main functions. Reporting `template` absent on that
 * basis would tell a reviewer to delete a verified-correct record.
 */
const SUSPICIOUS_BYTES_PER_NAME = 5_000;

export const ExportScanResult = {
  /** Exports were enumerated. `names` is meaningful. */
  Parsed: "parsed",
  /** File could not be understood. `names` says nothing. */
  Unknown: "unknown",
} as const;

export type ExportScanResult = (typeof ExportScanResult)[keyof typeof ExportScanResult];

export interface ExportScan {
  readonly result: ExportScanResult;
  readonly names: readonly string[];
  readonly reason?: string;
}

function addName(names: Set<string>, name: string | undefined): void {
  if (name !== undefined && name.length > 0) {
    names.add(name);
  }
}

/** ESM: export function x, export const x, export { x }, export * from. */
function collectEsmExports(node: ts.Node, names: Set<string>): boolean {
  let sawReExport = false;
  if (ts.isExportDeclaration(node)) {
    if (node.exportClause !== undefined && ts.isNamedExports(node.exportClause)) {
      for (const element of node.exportClause.elements) {
        addName(names, element.name.text);
      }
    } else {
      // `export * from "./other"` hides names in another file.
      sawReExport = true;
    }
  }
  if (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) {
    const isExported = node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    if (isExported) {
      addName(names, node.name?.text);
    }
  }
  if (ts.isVariableStatement(node)) {
    const isExported = node.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    if (isExported) {
      for (const declaration of node.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) {
          addName(names, declaration.name.text);
        }
      }
    }
  }
  return sawReExport;
}

/** Reads property names out of an object literal assigned to module.exports. */
function collectObjectLiteralKeys(expression: ts.Expression, names: Set<string>): void {
  if (!ts.isObjectLiteralExpression(expression)) {
    return;
  }
  for (const property of expression.properties) {
    const name = property.name;
    if (name !== undefined && (ts.isIdentifier(name) || ts.isStringLiteral(name))) {
      addName(names, name.text);
    }
  }
}

/**
 * Methods reachable through an exported object, rather than exported directly.
 *
 * `web3-core-subscriptions` exports a constructor whose prototype carries
 * `attachToObject`, and `linkify-it` exports an instance whose prototype
 * carries `test`. Both are the functions their advisories name.
 *
 * Only object literals assigned to a prototype count. An earlier version
 * collected every object literal in the file, which harvested lodash's HTML
 * entity table as 258 "exports" and then declared `template` absent with
 * apparent confidence. Confident wrong answers are worse than honest unknowns.
 */
function collectMethodNames(node: ts.Node, names: Set<string>): void {
  // Foo.prototype.bar = ...
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    ts.isPropertyAccessExpression(node.left) &&
    ts.isPropertyAccessExpression(node.left.expression) &&
    node.left.expression.name.text === "prototype"
  ) {
    addName(names, node.left.name.text);
    return;
  }
  // Foo.prototype = { bar() {} }
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
    ts.isPropertyAccessExpression(node.left) &&
    node.left.name.text === "prototype"
  ) {
    collectObjectLiteralKeys(node.right, names);
    return;
  }
  // class Foo { bar() {} }
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
    for (const member of node.members) {
      if (
        (ts.isMethodDeclaration(member) || ts.isPropertyDeclaration(member)) &&
        member.name !== undefined &&
        (ts.isIdentifier(member.name) || ts.isStringLiteral(member.name))
      ) {
        addName(names, member.name.text);
      }
    }
  }
}

/** CommonJS: exports.x =, module.exports.x =, module.exports = { x }. */
function collectCommonJsExports(node: ts.Node, names: Set<string>): boolean {
  let sawOpaqueAssignment = false;
  if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) {
    return false;
  }
  const left = node.left;
  if (!ts.isPropertyAccessExpression(left)) {
    return false;
  }
  const target = left.expression;

  // exports.foo = ...
  if (ts.isIdentifier(target) && target.text === "exports") {
    addName(names, left.name.text);
    return false;
  }
  // module.exports.foo = ...
  if (
    ts.isPropertyAccessExpression(target) &&
    ts.isIdentifier(target.expression) &&
    target.expression.text === "module" &&
    target.name.text === "exports"
  ) {
    addName(names, left.name.text);
    return false;
  }
  // module.exports = ...
  if (ts.isIdentifier(target) && target.text === "module" && left.name.text === "exports") {
    if (ts.isObjectLiteralExpression(node.right)) {
      collectObjectLiteralKeys(node.right, names);
    } else {
      // Assigned a function, a require() call, or something computed. The real
      // export surface is elsewhere and cannot be read from here.
      sawOpaqueAssignment = true;
    }
  }
  return sawOpaqueAssignment;
}

function looksMinified(source: string): boolean {
  return source.split("\n").some(line => line.length > MINIFIED_LINE_LENGTH);
}

/**
 * Scans one module's source for the names it exports.
 *
 * Returns Unknown whenever the file re-exports from elsewhere, assigns
 * `module.exports` opaquely, or is minified, because in those cases the names
 * found are not the whole export surface and absence would prove nothing.
 */
export function scanExports(fileName: string, source: string): ExportScan {
  if (looksMinified(source)) {
    return { result: ExportScanResult.Unknown, names: [], reason: "file appears minified or bundled" };
  }

  const sourceFile = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const names = new Set<string>();
  let incomplete = false;

  const visit = (node: ts.Node): void => {
    if (collectEsmExports(node, names)) {
      incomplete = true;
    }
    if (collectCommonJsExports(node, names)) {
      incomplete = true;
    }
    collectMethodNames(node, names);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);

  if (incomplete) {
    return {
      result: ExportScanResult.Unknown,
      names: [...names],
      reason: "module re-exports or assigns exports opaquely",
    };
  }
  if (names.size === 0) {
    return { result: ExportScanResult.Unknown, names: [], reason: "no exports found" };
  }
  if (source.length > LARGE_FILE_BYTES && source.length / names.size > SUSPICIOUS_BYTES_PER_NAME) {
    return {
      result: ExportScanResult.Unknown,
      names: [...names].sort(),
      reason: "large file yielded few exports, so the module shape was not understood",
    };
  }
  return { result: ExportScanResult.Parsed, names: [...names].sort() };
}
