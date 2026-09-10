# Reachability analysis for npm has a data problem

**Status:** measured, reproducible, and negative. September 2026.

Commercial scanners sell "reachability": telling you which of your dependency
vulnerabilities your code can actually trigger. The published research is
encouraging. VFARCHĒ reports [78 to 89 percent false-positive
reduction](https://arxiv.org/pdf/2506.18050v1) in SCA tools once you know which
function is vulnerable.

That result depends on a piece of data. This is a report on trying to obtain it
for npm.

## The missing input

A reachability analysis needs to know **which function** an advisory is about.
For Go, OSV records it directly:

```json
"ecosystem_specific": {
  "imports": [{ "path": "net/http", "symbols": ["ListenAndServe", "Serve"] }]
}
```

For npm, that field is absent. Checked against live records:

```
Go   GO-2022-0969                    ecosystem_specific.imports[].symbols  present
npm  GHSA-35jh-r3h4-6jhm  (lodash)   ecosystem_specific                    ABSENT
npm  GHSA-29mw-wpgm-hmr9  (lodash)   ecosystem_specific                    ABSENT
```

The OSV schema supports it. Go and Rust populate it. npm does not.

This is not an oversight nobody noticed. It is the reason open source
reachability for JavaScript barely exists:

- **OSV-Scanner** tracks call-graph analysis in issue #476: Go, Rust and Java
  done, Python pending. JavaScript is not on the list at all.
- **Jelly**, the best open JS/TS analyzer, accepts a vulnerability file whose
  type is an OSV record *"optionally augmented by a module, a function code
  location, or access paths"*. It has the engine. It asks you to supply the data.
- **Snyk, Endor Labs and Arnica** all ship JavaScript reachability. Each built
  the mapping in house. None publish it.

So the engine is open and the data is not. This report is about what happens
when you try to build the open half.

## What was built

Three pieces, all in this repository:

1. An extractor that reads vulnerable function names out of advisory prose.
2. A dataset of the results, one JSON file per advisory.
3. A probe that runs Jelly against a real project and measures elimination
   **against a package-level baseline**, not against a raw dependency scan.

That last distinction matters. A scanner already tells you which packages you
import: CVE Lite CLI has `--only-used`, which is a regex import scan. Symbol
data only earns its place if it removes findings that survive that weaker check.
Measuring against the raw scan would flatter the result.

## Finding 1: the prose often names the function, but not often enough

Advisories frequently name the vulnerable function in English:

> `lodash` versions prior to 4.17.21 are vulnerable to Command Injection via the
> **`template`** function.

Run over the entire OSV npm feed, 228,895 records of which 7,368 are GHSA
advisories and 221,525 are malicious-package reports:

| | |
|---|---|
| Records proposed | 576 |
| Recall against GHSA | **7.8%** |
| Precision, held-out sample of 20 | **~75%** |

Precision improved from 50% to 75% across four rounds of sampling real output
and fixing what came back wrong, each round on a fresh random seed so the score
was never measured against the sample it was tuned on.

Recall is deliberately the weaker number. The failure directions are not
symmetric. A missing record leaves a finding in the queue, which is annoying and
safe. A wrong record marks a real vulnerability as unreachable, which is silent
and unsafe.

## Finding 2: coverage of a real queue is 4.4%

Measured against OWASP Juice Shop v20.2.0, 1,179 installed packages.

| Stage | Count | |
|---|---|---|
| Distinct advisory ids in the findings | 113 | what a developer faces |
| Covered by the dataset | **5** | **4.4%** |
| Of those, package imported from the entry point | 2 | |
| Of those, vulnerable symbol reached | 2 | |
| Eliminated | **0** | **0.0%** |

**Coverage is the binding constraint, not the analysis.** Even a flawless engine
cannot touch 95.6 percent of that queue, because no symbols exist for it.

The engine itself worked well. It located `jwt.sign` and `jwt.verify` at
`lib/insecurity.ts:54`, `:189`, `routes/verify.ts:125` and inside
`express-jwt/lib/index.js:40`, correctly and with call sites.

Scaling was also not the problem, though it looked like one for a while. A full
analysis exhausted a 16 GB V8 heap on a 365-package project. With Jelly's
`--max-indirections 1`, Juice Shop analysed in 20.5 seconds and 3,477 MB. That
mode is explicitly unsound per Jelly's own documentation, which matters, but it
is tractable.

## Finding 3: not every vulnerability is a function call

This is the part that has no obvious fix, and the part the literature does not
appear to account for.

marsdb `GHSA-5mrr-rgp6-x4gr` reads:

> In the `DocumentMatcher` class, selectors on `$where` clauses are passed to a
> Function

Extraction recorded symbols `DocumentMatcher` and `$where`. That is
linguistically correct and semantically wrong. `$where` is **a key in a query
object**, not a callable export. No call pattern can ever match it, so the
analysis found nothing, and the probe reported the advisory **not reachable**.

Juice Shop, `routes/chat.ts:149`:

```js
db.reviewsCollection.find({ $where: 'this.product == ' + productId })
```

Concatenated user input into a `$where` sink. A live NoSQL injection, and one of
Juice Shop's own documented challenges. **The tool cleared a real, exploitable
vulnerability.**

### Why the precision measurement could not catch it

Extraction precision was assessed by asking "do these look like function names".
They did. The question that mattered was "are these callable exports a
reachability analysis can match", which sampling prose never tested. The
measurement was answering an easier question than the one that decides safety.

### The category

Some vulnerabilities are triggered by **passing a value**, not by invoking an
export: query operators, configuration keys, option flags, template strings. For
these, absence of a matching call proves nothing at all.

Any reachability system that treats "no call found" as "not affected" will
silently clear them. This repository now models the distinction explicitly
(`SymbolRecord.trigger`), refuses to build call patterns for data-triggered
records, and leaves them in the queue.

How large this category is across npm advisories is **unmeasured**, and it is
the most interesting open question here.

## What this means

For anyone hoping to use open data for npm reachability today: the data does not
exist at usable coverage, and the cheap way of producing it tops out under 10
percent. Closing that gap needs fix-commit diff analysis or sustained manual
curation across thousands of advisories, and the value only materialises near
the end.

The published false-positive reduction figures are not wrong. They assume the
vulnerable-function data as an input. For npm, that assumption is the whole
problem.

And the reduction figures may be optimistic for a second reason: if a
meaningful share of advisories are data-triggered rather than call-triggered,
then some portion of what a reachability tool "eliminates" is not eliminated at
all. It is a false negative that looks exactly like a win.

## Reproducing this

```bash
git clone https://github.com/sonukapoor/npm-vuln-symbols
cd npm-vuln-symbols && npm ci

curl -O https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip
mkdir osv-feed && unzip -q all.zip -d osv-feed

npx tsx scripts/extract.ts --osv-dir osv-feed --out proposals
npx tsx scripts/probe.ts --project <a-project> --entry <entry-file> --osv-dir osv-feed
```

Juice Shop needs a lockfile generated first, since it sets `package-lock=false`
in `.npmrc`:

```bash
npm install --package-lock-only --package-lock=true
```

Without that step both CVE Lite CLI and the probe silently under-report: CVE
Lite CLI saw 4 packages instead of 1,179.

## Limitations of this study

- **One application.** Juice Shop is deliberately vulnerable and not
  representative. The 4.4 percent coverage figure is one data point.
- **Small sample.** Two advisories reached the reachability stage. No
  elimination rate computed from that would be meaningful, including this one.
- **Unsound analysis mode.** `--max-indirections 1` gives partial results by
  design, so individual not-reachable verdicts are weaker than a full analysis.
- **Unreviewed dataset.** No record has been human-reviewed. The marsdb defect
  is exactly what review exists to catch.
- **Precision measured by one person** reading 20 records per round.

## Repository

<https://github.com/sonukapoor/npm-vuln-symbols>

Code MIT, data CC-BY-4.0 to match OSV, so it can be contributed upstream without
a licence conflict. The intended end state is for these fields to live in OSV as
`ecosystem_specific` for npm, where Go and Rust already publish theirs, and for
this repository to become unnecessary.
