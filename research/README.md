# Research

A reproducible measurement of what AI app builders actually ship.

| File | What it does |
|---|---|
| `collect_corpus.py` | Samples public repos by the build markers Lovable, Bolt, and v0 leave behind |
| `corpus_scan.py` | Clones each, scans it, aggregates. Publishes aggregates only |
| `verify_sample.py` | Pulls a random sample of findings so precision can be measured by hand |
| `corpus.txt` | The 283 repositories sampled |
| `results/REPORT.md` | The numbers |
| `METHOD.md` | How they were produced, and what they cannot support |

## Reproduce

```bash
python3 research/collect_corpus.py --per-marker 100 > research/corpus.txt
python3 research/corpus_scan.py research/corpus.txt --workers 10
```

Roughly four minutes for 283 repos on a laptop.

## Ethics

Only public repositories. Static analysis only: nothing is executed, no host is
contacted, no vulnerability is tested against a running system.

**Per-repository results are never published.** A public map of "this repo has
an exposed key" would be a disclosure of live vulnerabilities in other people's
projects. The run log keeps hashed identifiers locally and is gitignored. The
corpus list is published because it is the input, not the result: anyone can
rerun it, and reproducibility requires it.
