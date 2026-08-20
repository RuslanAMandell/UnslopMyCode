#!/usr/bin/env python3
"""Scan a corpus of public repositories and aggregate the findings.

Publishes aggregates only. Per-repository findings are deliberately never
written to the results directory: a public map of "this repo has an exposed
key" would be a disclosure of live vulnerabilities in other people's projects.
Repos are identified in the run log by a short hash, and the log is gitignored.

Usage:
  python3 research/corpus_scan.py research/corpus.txt --limit 200 --workers 8
"""
import argparse
import hashlib
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from scan import scan                                    # noqa: E402
from unslop.catalog import CHECKS                        # noqa: E402
from unslop.report import DOMAIN_NAMES                   # noqa: E402

# Shallow clones carry one synthetic commit and no real history, so the two
# history-dependent checks cannot be measured this way. Excluded from every
# statistic rather than reported as if they were real.
HISTORY_CHECKS = {"H1", "S4"}


def clone(full_name, dest, depth=1, timeout=120):
    url = "https://github.com/%s.git" % full_name
    r = subprocess.run(
        ["git", "clone", "--quiet", "--depth", str(depth), "--single-branch", url, dest],
        capture_output=True, timeout=timeout)
    return r.returncode == 0


def scan_one(full_name):
    tmp = tempfile.mkdtemp(prefix="unslop-corpus-")
    dest = str(Path(tmp) / "repo")
    started = time.time()
    try:
        if not clone(full_name, dest):
            return {"ok": False, "reason": "clone-failed"}
        findings, coverage = scan(Path(dest))
        checks = sorted({f.check_id for f in findings} - HISTORY_CHECKS)
        counts = Counter(CHECKS[f.check_id].severity
                         for f in findings if f.check_id not in HISTORY_CHECKS)
        return {
            "ok": True,
            "id": hashlib.sha256(full_name.encode()).hexdigest()[:12],
            "checks": checks,
            "severity": {s: counts.get(s, 0) for s in ("P0", "P1", "P2", "P3")},
            "total": sum(counts.values()),
            "files": coverage.scanned_files,
            "stack": coverage.stack,
            "seconds": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {"ok": False, "reason": exc.__class__.__name__}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def aggregate(results):
    ok = [r for r in results if r.get("ok")]
    n = len(ok)
    if not n:
        return {}

    prevalence = Counter()
    for r in ok:
        prevalence.update(r["checks"])

    domain_hit = defaultdict(int)
    for r in ok:
        for dom in {c[0] for c in r["checks"]}:
            domain_hit[dom] += 1

    totals = [r["total"] for r in ok]
    p0 = [r["severity"]["P0"] for r in ok]
    stacks = Counter(t for r in ok for t in r["stack"])

    # Segment by stack: "how many Supabase apps ship without RLS" is a far more
    # meaningful number than the same figure across every repo, most of which
    # have no database at all.
    segments = {}
    for tag in ("supabase", "firebase", "nextjs", "express"):
        sub = [r for r in ok if tag in r["stack"]]
        if len(sub) < 10:
            continue
        seg_prev = Counter()
        for r in sub:
            seg_prev.update(r["checks"])
        segments[tag] = {
            "repos": len(sub),
            "with_p0_pct": round(100.0 * sum(1 for r in sub if r["severity"]["P0"]) / len(sub), 1),
            "top_critical_pct": {
                cid: round(100.0 * cnt / len(sub), 1)
                for cid, cnt in sorted(
                    ((c, n) for c, n in seg_prev.items()
                     if CHECKS[c].severity in ("P0", "P1")),
                    key=lambda kv: -kv[1])[:10]
            },
        }

    return {
        "repos_attempted": len(results),
        "repos_scanned": n,
        "repos_failed": len(results) - n,
        "excluded_checks": sorted(HISTORY_CHECKS),
        "files_scanned_total": sum(r["files"] for r in ok),
        "median_findings_per_repo": statistics.median(totals),
        "mean_findings_per_repo": round(statistics.mean(totals), 1),
        "repos_with_any_p0_pct": round(100.0 * sum(1 for x in p0 if x) / n, 1),
        "median_p0_per_repo": statistics.median(p0),
        "severity_totals": {
            s: sum(r["severity"][s] for r in ok) for s in ("P0", "P1", "P2", "P3")
        },
        "critical_prevalence_pct": {
            cid: round(100.0 * cnt / n, 1)
            for cid, cnt in sorted(
                ((c, k) for c, k in prevalence.items() if CHECKS[c].severity == "P0"),
                key=lambda kv: -kv[1])
        },
        "check_prevalence_pct": {
            cid: round(100.0 * cnt / n, 1)
            for cid, cnt in sorted(prevalence.items(), key=lambda kv: -kv[1])
        },
        "domain_prevalence_pct": {
            dom: round(100.0 * cnt / n, 1)
            for dom, cnt in sorted(domain_hit.items(), key=lambda kv: -kv[1])
        },
        "stack_counts": dict(stacks.most_common()),
        "scan_seconds_median": round(statistics.median(r["seconds"] for r in ok), 2),
        "segments": segments,
    }


def render(agg):
    L = ["# Corpus scan results", ""]
    L += ["Aggregate findings from scanning **%d public AI-generated repositories**."
          % agg["repos_scanned"], ""]
    L += ["| | |", "|---|---|"]
    L += ["| Repositories scanned | %d (%d failed to clone) |"
          % (agg["repos_scanned"], agg["repos_failed"])]
    L += ["| Files analyzed | %s |" % format(agg["files_scanned_total"], ",")]
    L += ["| Repos with at least one critical (P0) finding | **%.1f%%** |"
          % agg["repos_with_any_p0_pct"]]
    L += ["| Median findings per repo | %g |" % agg["median_findings_per_repo"]]
    L += ["| Median critical findings per repo | %g |" % agg["median_p0_per_repo"]]
    L += ["| Median scan time per repo | %.2fs |" % agg["scan_seconds_median"], ""]

    L += ["## Findings by severity", "", "| Severity | Total |", "|---|---|"]
    for s in ("P0", "P1", "P2", "P3"):
        L.append("| %s | %s |" % (s, format(agg["severity_totals"][s], ",")))
    L.append("")

    L += ["## Prevalence by domain", "",
          "Share of repositories with at least one finding in the domain.", "",
          "| Domain | Repos affected |", "|---|---|"]
    for dom, pct in agg["domain_prevalence_pct"].items():
        L.append("| %s | %.1f%% |" % (DOMAIN_NAMES[dom], pct))
    L.append("")

    L += ["## Critical findings (P0)", "",
          "Share of repositories with at least one of each. These are the ones "
          "that are exploitable as they stand.", "",
          "| Check | | Repos affected |", "|---|---|---|"]
    for cid, pct in agg["critical_prevalence_pct"].items():
        L.append("| `%s` | %s | **%.1f%%** |" % (cid, CHECKS[cid].title, pct))
    L.append("")

    L += ["## Most common checks", "", "| Check | | Severity | Repos affected |",
          "|---|---|---|---|"]
    for cid, pct in list(agg["check_prevalence_pct"].items())[:25]:
        c = CHECKS[cid]
        L.append("| `%s` | %s | %s | %.1f%% |" % (cid, c.title, c.severity, pct))
    L.append("")

    if agg.get("segments"):
        L += ["## By stack", "",
              "Checks that only apply to a given stack, measured only against "
              "repositories using it.", ""]
        for tag, seg in agg["segments"].items():
            L += ["**%s** (%d repos, **%.1f%%** with a critical finding)"
                  % (tag, seg["repos"], seg["with_p0_pct"]), "",
                  "| Check | | Severity | Repos affected |", "|---|---|---|---|"]
            for cid, pct in seg["top_critical_pct"].items():
                c = CHECKS[cid]
                L.append("| `%s` | %s | %s | %.1f%% |" % (cid, c.title, c.severity, pct))
            L.append("")

    L += ["## Stacks detected", "", "| Tag | Repos |", "|---|---|"]
    for tag, cnt in list(agg["stack_counts"].items())[:12]:
        L.append("| %s | %d |" % (tag, cnt))
    L += ["", "## Method notes", "",
          "- Shallow clones (`--depth 1`), so the two history-dependent checks "
          "(%s) cannot be measured and are excluded from every number above."
          % ", ".join("`%s`" % c for c in agg["excluded_checks"]),
          "- Counts are raw scanner output. The scanner marks most findings "
          "`SUSPECTED` until an agent verifies them by reading the code, so "
          "these are upper bounds on a per-check basis.",
          "- Only public repositories. Static analysis only: nothing was "
          "executed, no host was contacted, no vulnerability was tested.",
          "- Per-repository results are deliberately not published.",
          ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", nargs="?", default="research/corpus.txt")
    ap.add_argument("--from-log", default="", help="re-aggregate a previous run log")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default="research/results")
    args = ap.parse_args()

    if args.from_log:
        results = [json.loads(l) for l in Path(args.from_log).read_text().splitlines() if l.strip()]
        agg = aggregate(results)
        out = Path(args.out)
        (out / "aggregate.json").write_text(json.dumps(agg, indent=2) + "\n")
        (out / "REPORT.md").write_text(render(agg))
        sys.stderr.write("re-aggregated %d results\n" % len(results))
        return

    names = [l.strip() for l in Path(args.corpus).read_text().splitlines() if l.strip()]
    if args.limit:
        names = names[:args.limit]
    sys.stderr.write("scanning %d repos with %d workers\n" % (len(names), args.workers))

    results, done = [], 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for res in pool.map(scan_one, names):
            results.append(res)
            done += 1
            if done % 25 == 0:
                sys.stderr.write("  %d/%d\n" % (done, len(names)))

    agg = aggregate(results)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "aggregate.json").write_text(json.dumps(agg, indent=2) + "\n")
    (out / "REPORT.md").write_text(render(agg))
    # Run log keeps hashed ids for reproducibility checks. Gitignored.
    (out / "run-log.jsonl.local").write_text(
        "\n".join(json.dumps(r) for r in results) + "\n")
    sys.stderr.write("wrote %s\n" % (out / "REPORT.md"))


if __name__ == "__main__":
    main()
