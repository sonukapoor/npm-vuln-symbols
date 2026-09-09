# Proposals: unreviewed machine output

**Do not consume anything in this directory as data.**

These records were produced by `scripts/extract.ts` reading vulnerable function
names out of advisory prose. On a held-out sample of 20 the extractor ran at
roughly **75 percent precision**, so expect around one in four of these to be
wrong.

This is a review queue, not a dataset. Records move to `advisories/` only after
a human confirms the named symbols really are the vulnerable exports. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for what that review involves.

The daily `extract` workflow adds to this directory by pull request. It never
writes to `advisories/`.
