---
id: limitations
title: Known limitations
sidebar_label: Limitations
sidebar_position: 2
---

## Transitive reachability has no scalable sound answer yet

This is the open question that decides whether the approach is practical.

The analyzer can be run two ways, and neither is currently both correct and
affordable on a real project:

| Mode | Cost on a 365-package project | Packages in scope | Sound |
|---|---|---|---|
| Full analysis | Never completed, OOM at 16 GB | all | yes |
| `--ignore-dependencies` | 101 ms, 48 MB | 1 module, 29 functions | no, and useless |
| `--include-packages <vulnerable>` | 791 ms, 202 MB | 1,177 functions, intermediates dropped | no |
| `--max-indirections 1` (**current default**) | 1,325 ms, 352 MB | 2,722 functions, all packages | no, but bounded |

`--max-indirections 1` is the best of these and is what `scripts/probe.ts` uses.
It keeps every package in scope and bounds how far indirect flows are followed.
Jelly's own documentation is explicit that this produces "partial (unsound)
results", so a not-reachable verdict under it is weaker than one from a full
analysis.

Every affordable mode is explicitly unsound. `--include-packages` is the worst
of them, because it removes the intermediate packages a call path would travel
through, and so answers "does application code call this directly" rather than
"can this be reached at all".

That is the unsafe direction. A path like

```
app -> some-dependency -> js-yaml.load
```

is invisible when `some-dependency` is excluded, and the result reads as
"not reachable" when it is not.

### Why this matters more than it sounds

Transitive dependencies are where the pain is. A direct dependency can usually
just be upgraded. A transitive one needs an override, an upstream release, or a
fork, which is exactly why those findings sit in the queue for months.

So the case the tool most needs to answer is the case it currently cannot
answer soundly.

### What is actually established

- Symbol-level reachability works and is correct for **direct** dependencies.
  `fixtures/sample-app` calls `lodash.trim` and never `lodash.template`, and the
  probe returns exactly that, naming the call site.
- A real-world elimination rate **has not been measured**. On CVE Lite CLI all
  four advisories with dataset coverage are transitive-only and never imported
  by application source, so the probe correctly reports zero of each and yields
  no usable ratio.

### Options not yet tried

- Include the transitive closure between the entry and each vulnerable package,
  rather than only the vulnerable package. Bounded, and possibly still sound for
  the paths that matter.
- Jelly's approximate interpretation and indirection-bounding options, which
  exist precisely to trade precision for tractability.
- A project with vulnerable **direct** dependencies, which would at least
  produce a real number for the case that does work today.

## Coverage is the binding constraint, not the analysis

Measured end to end against OWASP Juice Shop v20.2.0 (1,179 packages).

| Stage | Count | |
|---|---|---|
| Distinct advisory ids in the findings | 113 | what a developer faces |
| Covered by this dataset | **5** | **4.4%** |
| Of those, package imported from the entry point | 2 | |
| Of those, vulnerable symbol reached | 2 | |
| Eliminated | **0** | **0.0%** |

Even with a perfect reachability engine, 95.6% of that queue is untouchable,
because the dataset has no symbols for those advisories. Extraction recall is
7.9% against GHSA and translates to roughly 4.4% against a real project's
findings.

That is the number that decides whether this is worth pursuing. The analysis
works; there is simply almost nothing for it to work on. Useful coverage means
something in the 50 to 80 percent range, and prose extraction plateaus far below
that, so reaching it needs fix-commit analysis or sustained manual curation
rather than the cheap path.

### Scaling, by contrast, is fine

Juice Shop analysed in 20.5 s and 3,477 MB with `--max-indirections 1`. The
earlier heap exhaustion is not a blocker for applications of this size.

## Not every vulnerability is a call to a named export

Found by running the probe against OWASP Juice Shop, and it is the most
important failure this project has hit.

marsdb's GHSA-5mrr-rgp6-x4gr says:

> In the `DocumentMatcher` class, selectors on `$where` clauses are passed to a
> Function

Extraction read that as symbols `DocumentMatcher` and `$where`, which is
linguistically correct and semantically wrong. `$where` is a **key in a query
object**, not a callable export. No call pattern can ever match it.

The probe therefore reported the advisory **not reachable** on Juice Shop, while
`routes/chat.ts:149` does:

```js
db.reviewsCollection.find({ $where: 'this.product == ' + productId })
```

That is concatenated user input reaching a `$where` sink. It is a live NoSQL
injection and one of Juice Shop's own challenges. The tool cleared a real,
exploitable vulnerability.

### Why the precision measurement missed it

Extraction precision was assessed by asking "do these look like function names".
These did. The wrongness is in whether they are *callable exports a reachability
analysis can match*, which is a different question and one that sampling prose
never tested.

### What changed

- `SymbolRecord.trigger` distinguishes `call` from `data_value`.
- `buildEntries` refuses to construct patterns for a `data_value` record, so it
  stays in the queue rather than being silently cleared.
- The extractor rejects `$`-prefixed names, which are almost always query or
  template operators.
- Both are covered by regression tests built from this exact case.

### What has not been solved

Data-triggered vulnerabilities still have **no** reachability story. They can be
flagged as unanswerable, which is the safe behaviour, but the dataset cannot
help with them. How large that category is across npm advisories is unmeasured.

## Extraction precision

Records in `proposals/` are machine-extracted at roughly 75 percent precision
on a held-out sample. Nothing is reviewed. See CONTRIBUTING.md.
