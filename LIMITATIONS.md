# Known limitations

## Transitive reachability has no scalable sound answer yet

This is the open question that decides whether the approach is practical.

The analyzer can be run two ways, and neither is currently both correct and
affordable on a real project:

| Mode | Cost on a 365-package project | Sound for transitive paths |
|---|---|---|
| Full analysis | Exhausted a 16 GB V8 heap, never completed | Yes |
| `--include-packages <vulnerable ones>` | 791 ms, 202 MB | **No** |

Bounding the analysis to the vulnerable packages is what makes it affordable,
but it removes the intermediate packages a call path would travel through. It
therefore answers "does application code call this directly" rather than "can
this be reached at all".

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
