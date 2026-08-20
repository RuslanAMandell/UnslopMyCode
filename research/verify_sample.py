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
    for full in sample:
        tmp = tempfile.mkdtemp()
        try:
            r = subprocess.run(
                ["git", "clone", "-q", "--depth", "1", "--single-branch",
                 "https://github.com/%s.git" % full, tmp + "/r"],
                capture_output=True, timeout=120)
            if r.returncode:
                continue
            findings, _ = scan(Path(tmp + "/r"))
            for x in findings:
                if x.check_id in want and len(hits.setdefault(x.check_id, [])) < args.per_check:
                    hits[x.check_id].append({"file": x.file, "line": x.line,
                                             "snippet": x.snippet[:160]})
        except Exception:
            pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print(json.dumps(hits, indent=2))


if __name__ == "__main__":
    main()
