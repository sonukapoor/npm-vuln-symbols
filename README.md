# npm-vuln-symbols

An open dataset mapping npm security advisories to the specific functions that
are actually vulnerable.

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

## Goal

To make this data unnecessary, by getting these fields upstream into OSV as
`ecosystem_specific` for npm, where Go and Rust already publish theirs.

## Licence

Code is MIT. The contents of `advisories/` are CC-BY-4.0, matching OSV, so the
data can be redistributed and contributed upstream without conflict.
