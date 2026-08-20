#!/usr/bin/env python3
"""unslop scanner: emit deterministic findings for a codebase. Never exits non-zero."""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unslop import detectors, rules, walker                      # noqa: E402
from unslop.catalog import CHECKS                                # noqa: E402
from unslop.findings import Coverage, Finding, write             # noqa: E402
from unslop.ruleset import RULES                                 # noqa: E402

ENV_EXAMPLE_FILES = (".env.example", ".env.sample", ".env.template")


def _postprocess_s5(root, found, coverage):
    root = Path(root)
    documented = set()
    seen_example = False
    for name in ENV_EXAMPLE_FILES:
        p = root / name
        if p.is_file():
            seen_example = True
            for line in p.read_text(errors="replace").splitlines():
                m = re.match(r"\s*([A-Z][A-Z0-9_]*)\s*=", line)
                if m:
                    documented.add(m.group(1))
    if not seen_example:
        coverage.note("no .env.example: every referenced env var is reported as undocumented")

    kept, referenced = [], {}
    for f in found:
        if f.check_id != "S5":
            kept.append(f)
            continue
        m = re.search(r"([A-Z][A-Z0-9_]{2,})", f.snippet)
        if not m or m.group(1) in documented:
            continue
        referenced.setdefault(m.group(1), f)
    for name, f in sorted(referenced.items()):
        kept.append(Finding("S5", f.file, f.line,
                            "%s is read in code but absent from .env.example" % name,
                            confidence="CONFIRMED"))
    return kept


def _postprocess_o3(found):
    per_file = defaultdict(list)
    kept = []
    for f in found:
        if f.check_id == "O3":
            per_file[f.file].append(f)
        else:
            kept.append(f)
    for rel, group in sorted(per_file.items()):
        first = sorted(group, key=lambda x: x.line)[0]
        kept.append(Finding("O3", rel, first.line,
                            "%d console.log/debug calls in this file" % len(group)))
    return kept


def scan(root, max_files=20000):
    root = Path(root)
    coverage = Coverage()
    coverage.stack = walker.detect_stack(root)
    files = walker.walk(root, coverage, max_files=max_files)
    found = rules.run(RULES, files)
    for mod in detectors.ALL:
        try:
            found.extend(mod.detect(root, files, coverage))
        except Exception as exc:  # a detector must never take the scan down
            coverage.note("detector %s failed (%s): its checks did not run"
                          % (mod.__name__.rsplit(".", 1)[-1], exc.__class__.__name__))
    found = _postprocess_s5(root, found, coverage)
    found = _postprocess_o3(found)
    found.sort(key=lambda f: (CHECKS[f.check_id].severity, f.check_id, f.file, f.line))
    return found, coverage


def main(argv=None):
    ap = argparse.ArgumentParser(prog="scan.py")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--out", default=".unslop/findings.json")
    ap.add_argument("--max-files", type=int, default=20000)
    ap.add_argument("--json", action="store_true", help="print a summary to stdout")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    found, coverage = scan(root, args.max_files)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = root / out_path
    write(out_path, found, coverage)

    counts = Counter(CHECKS[f.check_id].severity for f in found)
    summary = {
        "out": str(out_path),
        "counts": {sev: counts.get(sev, 0) for sev in ("P0", "P1", "P2", "P3")},
        "total": len(found),
        "scannedFiles": coverage.scanned_files,
        "stack": coverage.stack,
        "notes": coverage.notes,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("unslop: %d findings (P0=%d P1=%d P2=%d P3=%d) across %d files -> %s"
              % (summary["total"], summary["counts"]["P0"], summary["counts"]["P1"],
                 summary["counts"]["P2"], summary["counts"]["P3"],
                 coverage.scanned_files, out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
