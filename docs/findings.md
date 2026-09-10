---
id: findings
title: Reachability analysis for npm has a data problem
sidebar_label: Findings
sidebar_position: 1
---

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
| Recall against all GHSA advisories | 7.8% |
| **Recall against advisories that name a callable** | **49%** |
| Same, discounted for precision | **37%** |
| Precision, held-out sample of 20 | ~75% |

The second figure is the meaningful one, and it only became computable after the
classification below. Only advisories naming a callable function can ever have a
symbol recorded, so the achievable set is roughly 1,170 advisories rather than
7,020. Measuring against the larger number understates the result by a factor of
six, which is how it was first reported here.

Precision improved from 50% to 75% across four rounds of sampling real output
and fixing what came back wrong, each round on a fresh random seed so the score
was never measured against the sample it was tuned on.

Recall is deliberately the weaker number. The failure directions are not
symmetric. A missing record leaves a finding in the queue, which is annoying and
safe. A wrong record marks a real vulnerability as unreachable, which is silent
and unsafe.

## Finding 2: coverage of one real queue was 4.4%

**One project. n=1. This number does not generalise and should not be quoted as
if it did.**

OWASP Juice Shop v20.2.0, 1,179 installed packages. It is deliberately stuffed
with outdated vulnerable dependencies, so its finding mix is not typical of a
maintained codebase. A different project would give a different figure, and
nobody has measured the spread.

| Stage | Count | |
|---|---|---|
| Distinct advisory ids in the findings | 113 | what a developer faces |
| Covered by the dataset | **5** | **4.4%** |
| Of those, package imported from the entry point | 2 | |
| Of those, vulnerable symbol reached | 2 | |
| Eliminated | **0** | **0.0%** |

**On this project, coverage was the binding constraint rather than the
analysis.** A flawless engine could not have touched 95.6 percent of that
queue, because no symbols existed for it.

What generalises here is the *reason* coverage is low, which is Finding 3: most
advisories name no callable function, so no dataset can ever cover them. The
specific 4.4 percent is one observation of that.

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

### The category, measured

A 150-advisory random sample from the 7,020 live GHSA records in the OSV npm
feed, classified twice, independently, on reshuffled batches:

| | Round 1 | Round 2 |
|---|---|---|
| Names a callable ("call") | 19 (12.7%) | 25 (16.7%) |
| Names no callable ("data") | 127 (84.7%) | **124 (82.7%)** |
| Unclear | 4 | 1 |

**82.7% of npm advisories do not name a function a developer's code would
call** (95% CI 76.7 to 88.7%). Only about one in six is the shape a reachability
tool can answer.

Reliability: **92% agreement** between rounds, **Cohen's kappa 0.81**, which is
conventionally "almost perfect". Round 1 was less reliable, with per-batch call
rates of 18%, 12% and 8%, because the rubric conflated "does it name something
callable" with "is calling it sufficient to be exploited". Only the first is a
question reachability answers. Round 2 asks that alone and its per-batch rates
tightened to 9, 8 and 8.

The share is flat across package popularity, staying near 85% even for packages
with over a million weekly downloads, so it is not an artefact of sampling
obscure packages.

Every advisory's two classifications, package kind and download count are in
`study/classification.json`, and `scripts/sample-advisories.ts` regenerates the
identical sample from seed 20260910. Individual calls can be disputed.

### Why it happens

Some vulnerabilities are triggered by **passing a value**, not by invoking an
export: query operators, configuration keys, option flags, template strings.
Others live in servers, CLIs and application frameworks with no library API at
all. For all of these, absence of a matching call proves nothing.

Any reachability system that treats "no call found" as "not affected" will
silently clear them. This repository now models the distinction explicitly
(`SymbolRecord.trigger`), refuses to build call patterns for data-triggered
records, and leaves them in the queue.

How large this category is across npm advisories is **unmeasured**, and it is
the most interesting open question here.

## Finding 4: the fix commits are there, but nothing labels them

The OSV schema defines a `FIX` reference type for the commit that resolves an
advisory. Across all **7,020 live GHSA advisories in the npm feed it is used
zero times**. Every reference is `WEB`, `ADVISORY` or `PACKAGE`.

Yet **51.2% of advisories do link their fixing commit**, filed under `WEB`
alongside vendor bulletins and NVD mirrors:

```
GHSA-35jh-r3h4-6jhm references:
  ADVISORY  https://nvd.nist.gov/vuln/detail/CVE-2021-23337
  WEB       https://github.com/lodash/lodash/commit/3469357c...   <- the fix
  WEB       https://www.oracle.com/security-alerts/cpuoct2021.html
  PACKAGE   https://github.com/lodash/lodash
```

This project's own code filtered on `type === "FIX"` and therefore found a fix
commit for exactly none of them, silently, until someone asked to see a raw
record. Matching by URL shape instead recovers a commit for 56% of the proposed
records.

It is the same gap as the missing symbol field, in a different place. The
information exists and is not machine-addressable, so every consumer has to
re-derive it with a heuristic.

## What this means

For anyone hoping to use open data for npm reachability today: the data does not
exist at usable coverage. But the gap is smaller than it first appears, because
most advisories can never be covered at all.

The achievable set is roughly 1,170 advisories, not 7,020. This dataset already
holds about a third to a half of it, and the remaining work is on the order of
700 records rather than 6,400. That makes it a **completable** dataset with a
measured, defensible boundary, which is a very different proposition from an
open-ended curation effort.

What it does not make it is a product. Even complete coverage of the achievable
set touches roughly one advisory in six, and only some of those resolve to
unreachable, so a realistic queue reduction is on the order of 10 percent rather
than the 78 to 89 percent the literature reports.

The published false-positive reduction figures are not wrong. They assume the
vulnerable-function data as an input. For npm, that assumption is the whole
problem.

And the reduction figures may be optimistic for a second reason. Roughly five
in six npm advisories name no callable function at all. Whatever a reachability
tool reports for those, it is not derived from finding or not finding a call,
because there is no call to look for. Any share of them reported as eliminated
is a false negative that looks exactly like a win.

## Which numbers generalise

Not all of these carry the same weight, and the two quoted most often in
conversation are the two that do not.

| Number | Basis | Generalises |
|---|---|---|
| 82.7% name no callable | random sample of 150 advisories, kappa 0.81 | yes, to npm advisories |
| ~1,170 achievable set | derived from that sample | yes |
| 49% of achievable held | measured against the whole feed | yes |
| ~75% extraction precision | held-out samples, four rounds | reasonably |
| 51.2% link a fix commit | whole feed | yes |
| **4.4% coverage of a queue** | **one project** | **no** |
| **0% elimination** | **two advisories** | **no** |

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
  representative. The 4.4 percent coverage figure is a single observation, not
  a measurement of the ecosystem, and it is reported here only as an
  illustration of the mechanism.
- **Small sample.** Two advisories reached the reachability stage. No
  elimination rate computed from that would be meaningful, including the 0
  percent reported above.
- **Unsound analysis mode.** `--max-indirections 1` gives partial results by
  design, so individual not-reachable verdicts are weaker than a full analysis.
- **Unreviewed dataset.** No record has been human-reviewed. The marsdb defect
  is exactly what review exists to catch.
- **Precision measured by one person** reading 20 records per round.
- **The trigger classification was made by language models** reading advisory
  prose, twice, not by a domain expert. Agreement was 92% with kappa 0.81, and
  the full per-advisory record is published for dispute, but it is not the same
  as expert adjudication.
- **Classification used only the advisory text**, capped at 420 characters. A
  longer description or the linked patch might name a callable the digest
  omitted, which would bias the result toward "data".

## Repository

<https://github.com/sonukapoor/npm-vuln-symbols>

Code MIT, data CC-BY-4.0 to match OSV, so it can be contributed upstream without
a licence conflict. The intended end state is for these fields to live in OSV as
`ecosystem_specific` for npm, where Go and Rust already publish theirs, and for
this repository to become unnecessary.
