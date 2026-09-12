# Contributing

## Current state

`advisories/` was seeded by picking records whose advisory text named the
export unambiguously. That selection was made by reading excerpts, not by
verifying exports against the packages, so those 11 records still need the same
review as anything in `proposals/`.

## The two directories

- **`advisories/`** is the dataset. Human-reviewed records only.
- **`proposals/`** is machine output awaiting review. Never consume it as data.

The extraction workflow opens pull requests against `proposals/`. Promoting a
record into `advisories/` is a human decision.

## Why review is mandatory

Extraction reads vulnerable function names out of advisory prose. On a
held-out sample of 20 records it ran at roughly **75 percent precision** and
**7.9 percent recall** against the 7,368 GHSA advisories in the npm feed.

Recall is deliberately the weaker number. The two failure directions are not
symmetric:

- A **missing** record leaves a finding in someone's queue. Annoying, safe.
- A **wrong** record marks a real vulnerability as unreachable. Silent, unsafe.

So the extractor drops anything ambiguous, and a human confirms everything that
survives.

## Where to start

Do not read `proposals/` top to bottom. [docs/review-queue.md](docs/review-queue.md)
sorts every record into bands by what two independent signals say about it, and
the bands are ordered by how much a reviewer's attention repays:

| Band | What to do |
|---|---|
| Likely wrong | Reject, and add a regression test. Highest yield. |
| Conflicting signals | Read properly. This is where judgement is needed. |
| Likely right | Skim and promote. |
| Weak support | Light check. |
| Unsupported | Leave until last. |

Regenerate it with `npx tsx scripts/build-review-queue.ts` after any change to
the dataset or to `study/export-check.json`.

## Reviewing a proposal

For each file in `proposals/`:

1. Open the advisory and confirm the named symbols are the vulnerable exports,
   not config keys, class names used in passing, or prose words.
2. Confirm the symbols are actually exported by each affected package. A symbol
   valid for `lodash` may not exist in `lodash.template`. `scripts/check-exports.ts`
   does this mechanically where it can, writing `study/export-check.json`:

   - `confirmed` means the symbol really is an export. Nothing to decide.
   - `not_found` means it was not found in a surface the parser can see. That is
     a **suspicion, not proof**, and it is the queue worth reading first.
   - `unknown` means the export surface could not be read at all, which proves
     nothing either way. Roughly two thirds of packages land here.
3. Check the `excerpt` supports the claim rather than contradicting it.
   Advisories often describe what is *not* affected.
4. If it holds, move the file to `advisories/` and set `reviewedBy`,
   `reviewedAt` and `reviewMethod`. Raise `evidence.confidence` if a fix commit
   corroborates it.
5. If it does not hold, delete it and add a regression test to
   `tests/extract-symbols.test.ts` so the extractor stops producing that shape.

Step 5 is the one that compounds. Every rejected proposal that becomes a test
raises precision permanently.

## Saying how you reviewed

`reviewedBy` alone spans everything from a person reading the advisory to an
agent reading it with a glance from a human, and a consumer cannot tell which.
So a review claim has to state its method, and validation enforces the pair.

| `reviewMethod` | Means |
|---|---|
| `human` | you read the advisory and decided |
| `assisted` | an agent read it and you accepted the result |
| `machine` | no human in the loop |

**Agent-assisted review is welcome.** Most review will be assisted, and saying
so is worth more than a claim that overstates itself. What is not welcome is a
record that reads as human-reviewed when it was not, because that is the same
failure this project documents in reachability tooling: an unmarked absence of
evidence, read as evidence of safety.

## Confidence levels

| Level | Means |
|---|---|
| `high` | Advisory prose and the fix-commit diff independently agree |
| `medium` | One source names the symbols and nothing contradicts it |
| `low` | Inferred or disputed. Consumers must not suppress findings on this |

## Running things

```
npm ci
npm test                  # unit tests
npx tsx scripts/validate.ts   # validate advisories/
npx tsx scripts/extract.ts --osv-dir <unzipped-osv-feed> --out proposals
```

The OSV feed is at
`https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip` (roughly
205 MB, about 229,000 records, of which 7,368 are GHSA advisories and the rest
are malicious-package reports that this dataset deliberately ignores).
