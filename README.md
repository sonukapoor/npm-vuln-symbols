# npm-vuln-symbols

An open dataset mapping npm security advisories to the specific functions that
are actually vulnerable.

> **Status: early, and not yet safe to suppress findings with.**
>
> Nothing here has been reviewed by a human yet.
>
> - `advisories/` holds 11 records, hand-picked from extractor output because
>   their advisory text named the export unambiguously. That was a judgement
>   call by eye, not a review.
> - `proposals/` holds 565 records straight from the extractor, awaiting review.
>
> Extraction measures at roughly 75 percent precision on a held-out sample, so
> expect about one record in four to be wrong. Do not wire this into anything
> that silences vulnerability alerts. Review is what makes a record
> trustworthy, and that work has not started.

## Scope, and why it is smaller than it looks

Most npm advisories can never appear in this dataset. **82.7 percent of them do
not name a function a developer's code would call** (measured, 150-advisory
sample, 92 percent inter-rater agreement, Cohen's kappa 0.81). They describe an
option key, a config value, a crafted input, or an application's behaviour, and
there is no symbol to record.

That puts a hard ceiling on the whole idea:

| | |
|---|---|
| Live GHSA npm advisories | 7,020 |
| Of those, ones that can ever have a symbol | **~1,170** |
| Records held here | 576 |
| Share of the achievable set | **~49%**, or ~37% discounted for precision |
| Records still to find | **~700** |

So this is a **completable** dataset with a measured boundary, not an open-ended
curation effort. It is also not a route to the 78 to 89 percent false-positive
reduction reported in the literature: covering the achievable set entirely still
only touches about one advisory in six.

See [docs/findings.md](docs/findings.md) for the measurement and
[docs/limitations.md](docs/limitations.md) for what is unsolved.

## The problem

A security advisory today says:

> lodash prior to 4.17.21 is vulnerable to Command Injection.

It does not say, in any machine-readable field, *which part* of lodash is
broken. That missing detail is why a dependency scan shows dozens of alerts
with no way to tell which ones your code can actually reach.

The information exists for other ecosystems. A Go advisory records it directly:

```json
"ecosystem_specific": {
  "imports": [{ "path": "net/http", "symbols": ["ListenAndServe", "Serve"] }]
}
```

npm advisories carry no equivalent. Commercial scanners each rebuild this
mapping privately, which is precisely why reachability analysis is a paid
feature.

## What this is

One JSON file per advisory, naming the vulnerable exports:

```json
{
  "id": "GHSA-35jh-r3h4-6jhm",
  "aliases": ["CVE-2021-23337"],
  "package": { "ecosystem": "npm", "name": "lodash" },
  "symbols": ["template"],
  "evidence": {
    "source": "advisory_text",
    "confidence": "high"
  }
}
```

That is the whole dataset. No server, no API, no database to operate.

## What this is not

- **Not a scanner.** Use one you already have.
- **Not a call-graph engine.** [Jelly](https://github.com/cs-au-dk/jelly) does
  that well and is already open source. This dataset is the input it currently
  asks you to supply by hand.

Both halves already exist and are free. They cannot be joined up because the
mapping in the middle is missing. This is the missing middle.

## Reachability is not exploitability

The only claim this data supports is the negative one.

- **Not reachable implies not exploitable.** If nothing in your code can call
  the vulnerable function, that advisory cannot fire through it.
- **Reachable does not imply exploitable.** You may call it, but never with
  attacker-controlled input.

So this eliminates noise. It does not rank threats. Findings that cannot be
resolved statically are reported as undetermined and must never be treated as
safe.

## Measuring whether this is worth doing

`scripts/probe.ts` measures what symbol-level reachability adds **over
package-level analysis**, not over a raw dependency scan. That distinction
matters: a scanner already tells you which packages you import, so the dataset
only earns its place if knowing the vulnerable function eliminates findings
that survive the weaker check.

```
npx tsx scripts/probe.ts --project <path> --entry <entry-file> [--osv-dir <feed>]
```

On `fixtures/sample-app`, which calls `lodash.trim` and never `lodash.template`:

```
package is imported           : 2
vulnerable symbol is reached  : 1
elimination rate              : 50.0%

  REACHABLE      GHSA-29mw-wpgm-hmr9   (trim, called at src/index.js:13:10)
  not reachable  GHSA-35jh-r3h4-6jhm   (template, never called)
```

That is the known-correct answer for that fixture. A package-level scan keeps
both advisories, because lodash *is* imported.

## Documentation

- [Review queue](docs/review-queue.md) - every record sorted by what is known
  about it, so a reviewer knows where to start
- [Findings](docs/findings.md) - what measuring this actually showed, with
  reproduction steps
- [Limitations](docs/limitations.md) - transitive reachability, and the
  categories this approach cannot answer

## Goal

To make this data unnecessary, by getting these fields upstream into OSV as
`ecosystem_specific` for npm, where Go and Rust already publish theirs.

## Licence

Code is MIT. The contents of `advisories/` are CC-BY-4.0, matching OSV, so the
data can be redistributed and contributed upstream without conflict.
