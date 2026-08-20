#!/usr/bin/env python3
"""Collect a random sample of findings per check for hand verification.

Precision cannot be asserted, only measured. This pulls a sample so each
finding can be judged by reading it, and the verdicts recorded alongside the
aggregate numbers.
"""
import argparse
import json
import random
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from scan import scan                            # noqa: E402
from unslop.catalog import CHECKS                # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", type=int, default=40)
    ap.add_argument("--per-check", type=int, default=10)
    ap.add_argument("--seed", type=int, default=99)
    ap.add_argument("--severity", default="P0")
    args = ap.parse_args()

    names = [l.strip() for l in (ROOT / "research/corpus.txt").read_text().splitlines() if l.strip()]
    random.seed(args.seed)
    sample = random.sample(names, min(args.repos, len(names)))

    want = {cid for cid, c in CHECKS.items() if c.severity == args.severity}
    hits = {}
    scanned = 0
    # A repo that drops out shrinks the pool the sample was actually drawn from,
    # which changes what the hand-verified precision figure describes. Counting
    # the reason class keeps that shrinkage visible instead of letting it be
    # absorbed silently into the result.
    failures = Counter()

    for full in sample:
        tmp = tempfile.mkdtemp()
        try:
            r = subprocess.run(
                ["git", "clone", "-q", "--depth", "1", "--single-branch",
                 "https://github.com/%s.git" % full, tmp + "/r"],
                capture_output=True, timeout=120)
            if r.returncode:
                # Renamed, deleted, or gone private since the corpus was
                # collected. Ordinary, but still a repo missing from the sample.
                failures["clone-failed"] += 1
                continue
            findings, _ = scan(Path(tmp + "/r"))
            for x in findings:
                if x.check_id in want and len(hits.setdefault(x.check_id, [])) < args.per_check:
                    hits[x.check_id].append({"file": x.file, "line": x.line,
                                             "snippet": x.snippet[:160]})
            scanned += 1
        except Exception as exc:
            # One unscannable repo must not end the run, but it must not vanish
            # either. Exception rather than BaseException so an interrupt still
            # stops the run instead of being recorded as a bad repo.
            failures[exc.__class__.__name__] += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # The accounting is part of the measurement, so it goes in the payload and
    # travels with the sample whenever the output is saved for the record. This
    # mirrors repos_attempted/scanned/failed in corpus_scan.py's aggregate, and
    # costs no consumer: nothing parses this stdout today, only humans read it.
    out = {
        "sample": {
            # requested and attempted diverge when --repos exceeds the corpus,
            # which is the same silent shrink seen from the other end.
            "repos_requested": args.repos,
            "repos_attempted": len(sample),
            "repos_scanned": scanned,
            "repos_failed": len(sample) - scanned,
            "failures_by_reason": dict(failures.most_common()),
        },
        "findings": hits,
    }
    print(json.dumps(out, indent=2))

    # Repeated on stderr because the JSON above scrolls off the top of a long
    # run, and because a reader who redirects stdout to a file would otherwise
    # watch a shrinking sample produce no signal at all.
    sys.stdout.flush()
    detail = ", ".join("%s: %d" % kv for kv in failures.most_common())
    sys.stderr.write("scanned %d/%d repos, %d failed%s\n" % (
        scanned, len(sample), len(sample) - scanned,
        " (%s)" % detail if detail else ""))


if __name__ == "__main__":
    main()
