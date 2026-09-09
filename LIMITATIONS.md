# Known limitations

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

## Extraction precision

Records in `proposals/` are machine-extracted at roughly 75 percent precision
on a held-out sample. Nothing is reviewed. See CONTRIBUTING.md.
