#!/usr/bin/env python3
"""Exit 1 when findings at or above a severity threshold exist.

This is the only unslop entry point that returns a non-zero exit code. The
scanner itself always exits 0, so that a scan failure never masquerades as a
clean result.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unslop.catalog import CHECKS                # noqa: E402

ORDER = ["P0", "P1", "P2", "P3"]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gate.py")
    ap.add_argument("findings", nargs="?", default=".unslop/findings.json")
    ap.add_argument("--fail-on", default="P0", choices=ORDER)
    ap.add_argument("--only", default="", help="comma-separated check ids to consider")
    args = ap.parse_args(argv)

    path = Path(args.findings)
    if not path.is_file():
        print("unslop gate: no findings file at %s (nothing to gate)" % path)
        return 0

    try:
        data = json.loads(path.read_text())
    except ValueError:
        print("unslop gate: %s is not valid JSON (not blocking)" % path)
        return 0

    limit = ORDER.index(args.fail_on)
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    blocking = []
    for row in data.get("findings", []):
        cid = row.get("check_id")
        if only and cid not in only:
            continue
        if cid in CHECKS and ORDER.index(CHECKS[cid].severity) <= limit:
            blocking.append(row)

    if not blocking:
        print("unslop gate: clear at %s and above" % args.fail_on)
        return 0

    print("unslop gate: %d blocking finding(s) at %s and above" % (len(blocking), args.fail_on))
    for row in blocking[:20]:
        print("  %s %s  %s:%s" % (CHECKS[row["check_id"]].severity, row["check_id"],
                                  row.get("file"), row.get("line")))
    if len(blocking) > 20:
        print("  ... and %d more" % (len(blocking) - 20))
    return 1


if __name__ == "__main__":
    sys.exit(main())
